// Package netconf holds what nebctl knows about this host and about the
// network a CA signs for, and renders nebula's config.yml from it.
package netconf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Lighthouse struct {
	Name      string   `json:"name,omitempty"`
	NebulaIP  string   `json:"nebula_ip"` // bare address, e.g. 10.221.221.1
	Endpoints []string `json:"endpoints"` // host:port reachable from the internet
	Relay     bool     `json:"relay,omitempty"`
	DNS       bool     `json:"dns,omitempty"` // answers DNS for Nebula hosts on NebulaIP:53
}

func (l Lighthouse) String() string {
	s := l.NebulaIP + " at " + strings.Join(l.Endpoints, ", ")
	var roles []string
	if l.Relay {
		roles = append(roles, "relay")
	}
	if l.DNS {
		roles = append(roles, "DNS")
	}
	if len(roles) > 0 {
		s += " (" + strings.Join(roles, ", ") + ")"
	}
	return s
}

// Rule is one inbound firewall rule. Port is "any", a number or a range
// ("8000-8100"); Proto is any, tcp, udp or icmp; Host or Group says who.
type Rule struct {
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Host  string `json:"host,omitempty"`
	Group string `json:"group,omitempty"`
}

func (r Rule) String() string {
	who := "any host"
	switch {
	case r.Group != "":
		who = "group " + r.Group
	case r.Host != "" && r.Host != "any":
		who = r.Host
	}
	if r.Proto == "icmp" {
		return "ping from " + who
	}
	return fmt.Sprintf("%s/%s from %s", r.Proto, r.Port, who)
}

// OpensSSH reports whether any rule lets tcp/22 in: a protocol of tcp or any
// whose port is 22, any, or a range holding 22, from any host or group.
func OpensSSH(rules []Rule) bool {
	for _, r := range rules {
		if r.Proto != "tcp" && r.Proto != "any" {
			continue
		}
		port := strings.TrimSpace(r.Port)
		if port == "any" {
			return true
		}
		lo, hi, isRange := strings.Cut(port, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if a <= 22 && 22 <= b {
			return true
		}
	}
	return false
}

// Host is this machine's setup, saved as nebctl.json beside config.yml.
type Host struct {
	Role        string       `json:"role"` // "lighthouse" or "node"
	Name        string       `json:"name"`
	NebulaIP    string       `json:"nebula_ip"` // CIDR, e.g. 10.221.221.1/22
	ListenPort  int          `json:"listen_port"`
	Relay       bool         `json:"relay,omitempty"` // lighthouse only: relay for nodes
	DNS         bool         `json:"dns,omitempty"`   // lighthouse only: answer DNS on NebulaIP:53
	Lighthouses []Lighthouse `json:"lighthouses"`
	Inbound     []Rule       `json:"inbound"`
	// Domain is the network's Nebula-only domain; with Resolve set, this
	// machine looks up names under it through the lighthouses' DNS.
	Domain  string `json:"domain,omitempty"`
	Resolve bool   `json:"resolve,omitempty"`

	// Admin turns on nebula's SSH admin server (list-hostmap and the
	// rest), on 127.0.0.1 only, for nebctl's own key.
	Admin *Admin `json:"admin,omitempty"`
	// Logging is nebula's log level and format; nil is info and text.
	Logging *Logging `json:"logging,omitempty"`
	// Metrics turns on nebula's Prometheus endpoint on 127.0.0.1.
	Metrics *Metrics `json:"metrics,omitempty"`
	// Blocklist holds the fingerprints of revoked certs.
	Blocklist []string `json:"blocklist,omitempty"`
	// SIEM forwards nebula's log lines to a syslog collector (Linux).
	SIEM *SIEM `json:"siem,omitempty"`

	rev string // digest of the file this was loaded from, for SaveIfUnchanged
}

type Admin struct {
	Listen string `json:"listen"` // 127.0.0.1:port
}

type Logging struct {
	Level  string `json:"level"`  // trace, debug, info, warn, error
	Format string `json:"format"` // text or json
}

type Metrics struct {
	Listen string `json:"listen"` // 127.0.0.1:port; served at /metrics
}

type SIEM struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // udp, tcp or tls
	CAFile   string `json:"ca_file,omitempty"`
}

// Defaults for the admin server and metrics: loopback only.
const (
	DefaultAdminListen   = "127.0.0.1:2242"
	DefaultMetricsListen = "127.0.0.1:9417"
)

// LogLevels are nebula's, quietest last.
var LogLevels = []string{"trace", "debug", "info", "warn", "error"}

func (h Host) LogLevel() string {
	if h.Logging == nil || h.Logging.Level == "" {
		return "info"
	}
	return h.Logging.Level
}

func (h Host) LogFormat() string {
	if h.Logging == nil || h.Logging.Format == "" {
		return "text"
	}
	return h.Logging.Format
}

const (
	RoleLighthouse = "lighthouse"
	RoleNode       = "node"
)

// Issued is one certificate the CA has signed.
type Issued struct {
	Name        string    `json:"name"`
	NebulaIP    string    `json:"nebula_ip"` // CIDR
	Groups      []string  `json:"groups,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	IssuedAt    time.Time `json:"issued_at"`
	// History holds the certs this entry's host had before, newest last.
	// A renewal or rename leaves the old cert working until it expires, so
	// its fingerprint is kept here to stay revocable. Absent in older files.
	History []Superseded `json:"history,omitempty"`
}

// Superseded is a cert a newer one replaced. NotAfter and IssuedAt are zero
// when not known.
type Superseded struct {
	Name         string    `json:"name"` // the name it was issued for
	NebulaIP     string    `json:"nebula_ip"`
	Fingerprint  string    `json:"fingerprint"`
	IssuedAt     time.Time `json:"issued_at,omitzero"`
	NotAfter     time.Time `json:"not_after,omitzero"`
	SupersededAt time.Time `json:"superseded_at"`
}

// Expired reports whether the cert's expiry is known and past.
func (s Superseded) Expired(now time.Time) bool {
	return !s.NotAfter.IsZero() && now.After(s.NotAfter)
}

// Network is the CA's record: the address range, the lighthouses every
// bundle carries, and the certs signed so far (so addresses are not reused).
type Network struct {
	CIDR        string       `json:"cidr"`
	Domain      string       `json:"domain,omitempty"` // host names end in it; only Nebula uses it
	Lighthouses []Lighthouse `json:"lighthouses"`
	Issued      []Issued     `json:"issued"`
}

// Record stores i, replacing the entry with the same name. The replaced
// cert, if its fingerprint differs, moves into i's History.
func (n *Network) Record(i Issued) {
	n.RecordReplacing("", i)
}

// RecordReplacing is Record for a cert that also takes over from the entry
// named replaces (a rename), which is dropped; its cert goes into History
// the same way.
func (n *Network) RecordReplacing(replaces string, i Issued) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, name := range []string{i.Name, replaces} {
		if name == "" {
			continue
		}
		if old, ok := n.Find(name); ok {
			i.History = mergeHistory(i.History, old, i.Fingerprint, now)
			if name != i.Name {
				n.Remove(name)
			}
		}
	}
	i.History = pruneHistory(i.History, now)
	for k := range n.Issued {
		if n.Issued[k].Name == i.Name {
			n.Issued[k] = i
			return
		}
	}
	n.Issued = append(n.Issued, i)
}

// mergeHistory adds old's own history and old itself (unless it is the cert
// now being recorded) to h, skipping fingerprints already there.
func mergeHistory(h []Superseded, old Issued, current string, now time.Time) []Superseded {
	add := func(s Superseded) {
		if s.Fingerprint == "" || s.Fingerprint == current {
			return
		}
		for _, e := range h {
			if e.Fingerprint == s.Fingerprint {
				return
			}
		}
		h = append(h, s)
	}
	for _, s := range old.History {
		add(s)
	}
	add(Superseded{Name: old.Name, NebulaIP: old.NebulaIP, Fingerprint: old.Fingerprint,
		IssuedAt: old.IssuedAt, NotAfter: old.NotAfter, SupersededAt: now})
	return h
}

func pruneHistory(h []Superseded, now time.Time) []Superseded {
	var out []Superseded
	for _, s := range h {
		if !s.Expired(now) {
			out = append(out, s)
		}
	}
	return out
}

// Prune drops history entries whose cert has expired.
func (n *Network) Prune(now time.Time) {
	for k := range n.Issued {
		n.Issued[k].History = pruneHistory(n.Issued[k].History, now)
	}
}

// ValidFingerprint checks s is a nebula cert fingerprint (SHA-256, 64 hex
// digits) and returns it lowercased.
func ValidFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !fingerprintRe.MatchString(s) {
		return "", errors.New("a fingerprint is 64 hexadecimal characters (the SHA-256 shown for the cert)")
	}
	return s, nil
}

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (n *Network) Find(name string) (Issued, bool) {
	for _, i := range n.Issued {
		if i.Name == name {
			return i, true
		}
	}
	return Issued{}, false
}

// Owner returns the name holding addr, if any.
func (n *Network) Owner(addr netip.Addr) (string, bool) {
	for _, i := range n.Issued {
		if p, err := netip.ParsePrefix(i.NebulaIP); err == nil && p.Addr() == addr {
			return i.Name, true
		}
	}
	return "", false
}

// AddLighthouse adds l, replacing one with the same Nebula IP.
func AddLighthouse(list []Lighthouse, l Lighthouse) []Lighthouse {
	for k := range list {
		if list[k].NebulaIP == l.NebulaIP {
			list[k] = l
			return list
		}
	}
	return append(list, l)
}

// NextFree returns the first address in cidr not issued yet, as a CIDR
// with the network's prefix length. The network and broadcast addresses
// are skipped.
func (n *Network) NextFree() (string, error) {
	p, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return "", fmt.Errorf("network %q: %w", n.CIDR, err)
	}
	p = p.Masked()
	last := lastAddr(p)
	for a := p.Addr().Next(); a.IsValid() && p.Contains(a) && a != last; a = a.Next() {
		if _, used := n.Owner(a); !used {
			return netip.PrefixFrom(a, p.Bits()).String(), nil
		}
	}
	return "", fmt.Errorf("network %s is full", n.CIDR)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		a = a.Unmap()
	}
	return a
}

// ParseHostIP accepts "10.221.221.5/22" or a bare "10.221.221.5", which
// takes cidr's prefix length, and checks the address is inside cidr.
func ParseHostIP(s, cidr string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var netw netip.Prefix
	if cidr != "" {
		var err error
		if netw, err = netip.ParsePrefix(cidr); err != nil {
			return netip.Prefix{}, err
		}
	}
	if !strings.Contains(s, "/") {
		if !netw.IsValid() {
			return netip.Prefix{}, errors.New("give the address with its prefix, e.g. 10.42.0.5/22")
		}
		s += "/" + strconv.Itoa(netw.Bits())
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address like 10.42.0.5/22", s)
	}
	if netw.IsValid() && !netw.Masked().Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("%s is outside the network %s", p.Addr(), netw)
	}
	return p, nil
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName accepts a cert name usable as a file name: letters, digits,
// dot, dash and underscore.
func ValidName(s string) error {
	if !nameRe.MatchString(s) {
		return errors.New("use letters, digits, '.', '-' and '_' (e.g. web01.example.com)")
	}
	return nil
}

// ParseEndpoint accepts host or host:port; a bare host takes defPort.
func ParseEndpoint(s string, defPort int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("required")
	}
	host, port := s, strconv.Itoa(defPort)
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.HasSuffix(s, "]") && strings.Count(s, ":") == 1 {
		host, port = s[:i], s[i+1:]
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("bad port in %q", s)
	}
	if strings.ContainsAny(host, " /") {
		return "", fmt.Errorf("bad host in %q", s)
	}
	return host + ":" + port, nil
}

// ParseRules reads "tcp/443, udp/53, tcp/8000-8100" into rules open to any host.
func ParseRules(s string) ([]Rule, error) {
	var rules []Rule
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		proto, port, ok := strings.Cut(strings.ToLower(f), "/")
		if !ok || (proto != "tcp" && proto != "udp" && proto != "any") || !validPort(port) {
			return nil, fmt.Errorf("%q: write ports as tcp/443, udp/53 or tcp/8000-8100", f)
		}
		rules = append(rules, Rule{Port: port, Proto: proto, Host: "any"})
	}
	return rules, nil
}

func validPort(s string) bool {
	if s == "any" {
		return true
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil || a < 0 || a > 65535 {
		return false
	}
	if !isRange {
		return true
	}
	b, err := strconv.Atoi(hi)
	return err == nil && b >= a && b <= 65535
}

// Firewall presets offered by the setup wizards.
var (
	PingRule = Rule{Port: "any", Proto: "icmp", Host: "any"}
	SSHRule  = Rule{Port: "22", Proto: "tcp", Host: "any"}
	AllRule  = Rule{Port: "any", Proto: "any", Host: "any"}
)

// ErrChanged means the state file was rewritten by someone else after this
// copy was loaded, so saving it would silently drop their change.
var ErrChanged = errors.New("changed by another nebctl while you were working; nothing was written, so run it again")

// load reads path into v and returns the file's digest.
func load(path string, v any) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return digest(data), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func save(path string, v any, mode os.FileMode) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	return digest(data), WriteFileAtomic(path, data, mode)
}

// unchanged reports whether path still holds what was loaded (rev). A copy
// that was not loaded from the file (rev empty) is not checked.
func unchanged(path, rev string) error {
	if rev == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || digest(data) != rev {
		return fmt.Errorf("%s: %w", path, ErrChanged)
	}
	return nil
}

func LoadHost(path string) (*Host, error) {
	var h Host
	rev, err := load(path, &h)
	h.rev = rev
	return &h, err
}

func (h *Host) Save(path string) (err error) {
	h.rev, err = save(path, h, 0o644)
	return err
}

// CheckUnchanged is for a copy loaded earlier: with the state lock held, it
// returns ErrChanged when the file was rewritten since the load, so the caller
// can stop before it writes anything.
func (h *Host) CheckUnchanged(path string) error { return unchanged(path, h.rev) }

func LoadNetwork(path string) (*Network, error) {
	var n Network
	_, err := load(path, &n)
	return &n, err
}

func (n *Network) Save(path string) error {
	_, err := save(path, n, 0o600)
	return err
}

// WriteFileAtomic writes beside path, syncs it to disk and renames over it,
// so a crash leaves the old file or the whole new one.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil { // make the rename durable
		d.Sync()
		d.Close()
	}
	return nil
}
