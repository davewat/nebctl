package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/admin"
	"github.com/davewat/nebctl/internal/bundle"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
	"github.com/davewat/nebctl/internal/prompt"
	"github.com/davewat/nebctl/internal/release"
	"github.com/davewat/nebctl/internal/service"
)

// The web console's commands: `nebctl app <command>`, JSON out, inputs as
// flags (never stdin), so the console runs them the same way here and on a
// lighthouse over SSH. Messages nebctl would print go into a "log" field.

func (a *app) adminKeys() admin.Keys { return admin.Keys{Dir: filepath.Join(a.cfgDir(), "admin")} }

// adminClient is nebula's admin server on this machine.
func (a *app) adminClient() (admin.Client, *netconf.Host, error) {
	h, ok, err := a.loadHost()
	if err != nil {
		return admin.Client{}, nil, err
	}
	if !ok {
		return admin.Client{}, nil, errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	if h.Admin == nil {
		return admin.Client{}, nil, errors.New("nebula's admin access is off here: turn it on with `sudo nebctl app admin-enable`")
	}
	return admin.Client{Addr: h.Admin.Listen, User: netconf.AdminUser, Keys: a.adminKeys()}, h, nil
}

var consoleCommands = []string{
	"connections", "tunnel", "close-tunnel", "create-tunnel", "change-remote", "lookup", "log-level",
	"reload", "admin-enable", "certs", "next-ip", "sign", "sign-request", "revoke", "blocklist",
	"settings", "configure", "logs", "siem", "siem-test", "health", "audit", "update", "service",
}

// consoleCmd runs one console command. ok is false for a name it doesn't know.
func (a *app) consoleCmd(name string, args []string) (ok bool, err error) {
	if !slices.Contains(consoleCommands, name) {
		return false, nil
	}
	var log bytes.Buffer
	a.p = prompt.New(strings.NewReader(""), &log)
	withLog := func(v map[string]any, err error) error {
		if err != nil {
			if s := strings.TrimSpace(log.String()); s != "" {
				return fmt.Errorf("%w\n%s", err, s)
			}
			return err
		}
		if v == nil {
			v = map[string]any{}
		}
		v["log"] = strings.TrimSpace(log.String())
		return printJSON(v)
	}

	fs := flag.NewFlagSet("app "+name, flag.ContinueOnError)
	localOnly := fs.Bool("local-only", false, "close-tunnel: don't tell the other host")
	address := fs.String("address", "", "create-tunnel, change-remote: ip:port")
	certName := fs.String("name", "", "sign: the host's name")
	ip := fs.String("ip", "", "sign: its Nebula address")
	groups := fs.String("groups", "", "sign: comma separated groups")
	request := fs.String("request", "", "sign-request: the request text")
	fingerprint := fs.String("fingerprint", "", "revoke: the cert's fingerprint")
	set := fs.String("set", "", "blocklist: the whole list, comma separated")
	jsonIn := fs.String("json", "", "configure, siem: the change as JSON")
	lines := fs.Int("lines", 200, "logs: how many lines")
	if err := fs.Parse(args); err != nil {
		return true, err
	}
	arg := fs.Arg(0)
	groupsGiven := false
	fs.Visit(func(f *flag.Flag) { groupsGiven = groupsGiven || f.Name == "groups" })

	switch name {
	case "connections":
		return true, a.consoleConnections()
	case "tunnel":
		c, _, err := a.adminClient()
		if err != nil {
			return true, err
		}
		p, err := c.Tunnel(arg)
		if err != nil {
			return true, err
		}
		return true, printJSON(p)
	case "close-tunnel", "create-tunnel", "change-remote":
		c, _, err := a.adminClient()
		if err != nil {
			return true, err
		}
		if _, err := netip.ParseAddr(arg); err != nil {
			return true, fmt.Errorf("%q is not a Nebula address", arg)
		}
		cmd := name
		switch {
		case name == "close-tunnel" && *localOnly:
			cmd += " -local-only"
		case name == "change-remote" && *address == "":
			return true, errors.New("give the new address with -address ip:port")
		case *address != "":
			if _, err := netip.ParseAddrPort(*address); err != nil {
				return true, fmt.Errorf("%q is not an address like 198.51.100.7:4242", *address)
			}
			cmd += " -address " + *address
		}
		msg, err := c.Message(cmd + " " + arg)
		if err != nil {
			return true, err
		}
		return true, printJSON(map[string]string{"message": msg})
	case "lookup":
		c, _, err := a.adminClient()
		if err != nil {
			return true, err
		}
		e, err := c.Lookup(arg)
		if err != nil {
			return true, err
		}
		return true, printJSON(e)
	case "log-level":
		c, _, err := a.adminClient()
		if err != nil {
			return true, err
		}
		if arg != "" && !slices.Contains(netconf.LogLevels, arg) {
			return true, fmt.Errorf("log level %q: use one of %s", arg, strings.Join(netconf.LogLevels, ", "))
		}
		level, err := c.LogLevel(arg)
		if err != nil {
			return true, err
		}
		return true, printJSON(map[string]string{"level": level})
	case "reload":
		if err := a.requireRoot(); err != nil {
			return true, err
		}
		return true, withLog(map[string]any{"message": "Reloaded"}, a.reloadNebula())
	case "admin-enable":
		return true, withLog(nil, a.consoleAdminEnable())
	case "certs":
		return true, a.consoleCerts()
	case "next-ip":
		network, err := a.loadNetwork()
		if err != nil {
			return true, err
		}
		next, err := network.NextFree()
		if err != nil {
			return true, err
		}
		return true, printJSON(map[string]string{"ip": next})
	case "sign", "sign-request":
		v, err := a.consoleSign(*certName, *ip, splitList(*groups), groupsGiven, *request, name == "sign-request")
		return true, withLog(v, err)
	case "revoke":
		v, err := a.consoleRevoke(*fingerprint)
		return true, withLog(v, err)
	case "blocklist":
		return true, withLog(nil, a.consoleBlocklist(splitList(*set)))
	case "settings":
		return true, a.consoleSettings()
	case "configure":
		v, err := a.consoleConfigure(*jsonIn)
		return true, withLog(v, err)
	case "logs":
		out, err := a.nebulaLog(*lines)
		if err != nil {
			return true, err
		}
		return true, printJSON(map[string][]string{"lines": out})
	case "siem":
		if *jsonIn == "" {
			return true, a.consoleSIEM()
		}
		return true, withLog(nil, a.consoleSetSIEM(*jsonIn))
	case "siem-test":
		return true, withLog(nil, a.siemTest())
	case "health":
		return true, a.consoleHealth()
	case "audit":
		err := a.audit(true, false)
		if errors.Is(err, errAuditFailed) {
			err = nil // the findings say so
		}
		return true, err
	case "update":
		if err := a.requireRoot(); err != nil {
			return true, err
		}
		return true, withLog(nil, a.update("", false))
	case "service":
		return true, withLog(nil, a.serviceCmd([]string{arg}))
	}
	return true, fmt.Errorf("unknown console command %q", name)
}

func (a *app) consoleConnections() error {
	c, h, err := a.adminClient()
	if err != nil {
		return err
	}
	peers, err := c.Peers()
	if err != nil {
		return err
	}
	self, _, _ := strings.Cut(h.NebulaIP, "/")
	out := struct {
		Self struct {
			VpnAddr string `json:"vpn_addr"`
			Name    string `json:"name"`
			Role    string `json:"role"`
		} `json:"self"`
		Peers   []admin.Peer      `json:"peers"`
		AddrMap []admin.AddrEntry `json:"addr_map,omitempty"`
		At      time.Time         `json:"at"`
	}{Peers: peers, At: time.Now().UTC().Truncate(time.Second)}
	out.Self.VpnAddr, out.Self.Name, out.Self.Role = self, h.Name, h.Role
	if h.Role == netconf.RoleLighthouse {
		if out.AddrMap, err = c.AddrMap(); err != nil {
			return err
		}
	}
	return printJSON(out)
}

func (a *app) consoleAdminEnable() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	defaultAdmin(h)
	return a.apply(h)
}

// reloadNebula makes nebula re-read config.yml without dropping tunnels.
func (a *app) reloadNebula() error {
	if a.root != "" || a.noService {
		a.p.Println("Reload nebula with: sudo kill -HUP $(pgrep -x nebula)")
		return nil
	}
	if err := service.Reload(a.goos); err != nil {
		return err
	}
	a.p.Println("nebula re-read its config.")
	return nil
}

// writeLive writes the config for h, then restarts nebula or (when what
// changed allows) only reloads it.
func (a *app) writeLive(h *netconf.Host, restart bool) error {
	if restart {
		return a.apply(h)
	}
	dns, err := a.writeConfig(h)
	if err != nil {
		return err
	}
	_ = dns
	return a.reloadNebula()
}

// Certificates

type issuedOut struct {
	Name        string    `json:"name"`
	NebulaIP    string    `json:"nebula_ip"`
	Groups      []string  `json:"groups"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	IssuedAt    time.Time `json:"issued_at"`
	DaysLeft    int       `json:"days_left"`
	Revoked     bool      `json:"revoked"`
	Online      *bool     `json:"online,omitempty"`
}

func (a *app) issuedOut(i netconf.Issued, blocked []string, online map[string]bool) issuedOut {
	o := issuedOut{Name: i.Name, NebulaIP: i.NebulaIP, Groups: i.Groups, Fingerprint: i.Fingerprint,
		NotAfter: i.NotAfter, IssuedAt: i.IssuedAt, DaysLeft: daysLeft(i.NotAfter),
		Revoked: slices.Contains(blocked, i.Fingerprint)}
	if o.Groups == nil {
		o.Groups = []string{}
	}
	if online != nil {
		on := online[i.Name]
		o.Online = &on
	}
	return o
}

func (a *app) consoleCerts() error {
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	h, _, err := a.loadHost()
	if err != nil {
		return err
	}
	var online map[string]bool
	if c, _, err := a.adminClient(); err == nil {
		if peers, err := c.Peers(); err == nil {
			online = map[string]bool{h.Name: true} // this machine
			for _, p := range peers {
				online[p.Name] = online[p.Name] || !p.Pending
			}
		}
	}
	cas, err := a.tool().Inspect(a.caDirCrt())
	if err != nil {
		return err
	}
	ca := cas[0]
	out := map[string]any{
		"ca": map[string]any{"name": ca.Name, "not_after": ca.NotAfter, "days_left": daysLeft(ca.NotAfter),
			"fingerprint": ca.Fingerprint},
		"cidr": network.CIDR, "domain": network.Domain,
		"lighthouses": nonNilList(network.Lighthouses), "blocklist": nonNilList(h.Blocklist),
	}
	issued := make([]issuedOut, len(network.Issued))
	for i, is := range network.Issued {
		issued[i] = a.issuedOut(is, h.Blocklist, online)
	}
	out["issued"] = issued
	return printJSON(out)
}

func nonNilList[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// planCert is askHostCert without the questions: a short name gets the
// domain, a name signed before keeps its address (a renewal), and a name that
// moves an older cert into the domain takes over its address.
func (a *app) planCert(network *netconf.Network, name, ip string, groups []string, groupsGiven bool) (certReq, error) {
	if err := netconf.ValidName(name); err != nil {
		return certReq{}, fmt.Errorf("name: %w", err)
	}
	name = netconf.Qualify(name, network.Domain)
	prev, renewing := network.Find(name)
	replaces := ""
	if !renewing {
		if old, ok := network.Renames(name); ok {
			prev, replaces, renewing = old, old.Name, true
		}
	}
	var p netip.Prefix
	var err error
	switch {
	case ip != "":
		if p, err = netconf.ParseHostIP(ip, network.CIDR); err != nil {
			return certReq{}, err
		}
	case renewing:
		if p, err = netip.ParsePrefix(prev.NebulaIP); err != nil {
			return certReq{}, err
		}
	default:
		next, err := network.NextFree()
		if err != nil {
			return certReq{}, err
		}
		p = netip.MustParsePrefix(next)
	}
	if owner, used := network.Owner(p.Addr()); used && owner != name && owner != replaces {
		return certReq{}, fmt.Errorf("%s belongs to %s", p.Addr(), owner)
	}
	if !groupsGiven && renewing {
		groups = prev.Groups
	}
	return certReq{name: name, ip: p, groups: groups, replaces: replaces}, nil
}

func (a *app) consoleSign(name, ip string, groups []string, groupsGiven bool, request string, fromRequest bool) (map[string]any, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	network, err := a.loadNetwork()
	if err != nil {
		return nil, err
	}
	if len(network.Lighthouses) == 0 {
		return nil, errors.New("no lighthouse is recorded for bundles yet: run `sudo nebctl ca lighthouse` on this machine")
	}
	tmp, err := os.MkdirTemp("", "nebctl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	pubPath, keyPath := "", filepath.Join(tmp, "host.key")
	if fromRequest {
		req, err := bundle.DecodeRequest(request)
		if err != nil {
			return nil, err
		}
		if _, err := pki.PublicKeyHex([]byte(req.PublicKey)); err != nil {
			return nil, fmt.Errorf("the request's public key: %w", err)
		}
		if name == "" {
			name = req.Name
		}
		if ip == "" && req.NebulaIP != "" {
			if p, err := netconf.ParseHostIP(req.NebulaIP, network.CIDR); err == nil {
				if _, used := network.Owner(p.Addr()); !used {
					ip = req.NebulaIP
				}
			}
		}
		pubPath, keyPath = filepath.Join(tmp, "host.pub"), ""
		if err := os.WriteFile(pubPath, []byte(req.PublicKey), 0o600); err != nil {
			return nil, err
		}
	}
	r, err := a.planCert(network, name, ip, groups, groupsGiven)
	if err != nil {
		return nil, err
	}
	_, crt, err := a.issue(network, r, pubPath, keyPath)
	if err != nil {
		return nil, err
	}
	b, err := a.bundleFor(network, r.name, crt, keyPath)
	if err != nil {
		return nil, err
	}
	text, err := bundle.EncodeBundle(b)
	if err != nil {
		return nil, err
	}
	h, _, _ := a.loadHost()
	is, _ := network.Find(r.name)
	next, _ := network.NextFree()
	out := map[string]any{"bundle": text, "cert": a.issuedOut(is, h.Blocklist, nil), "next_ip": next}
	if r.replaces != "" {
		out["replaces"] = r.replaces
	}
	return out, nil
}

func (a *app) consoleRevoke(fp string) (map[string]any, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return nil, errors.New("give the cert's fingerprint with -fingerprint")
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	if c := a.currentCert(); c != nil && c.Fingerprint == fp {
		return nil, errors.New("that is this machine's own cert: revoking it here would cut this machine off")
	}
	if !slices.Contains(h.Blocklist, fp) {
		h.Blocklist = append(h.Blocklist, fp)
	}
	if err := a.writeLive(h, false); err != nil {
		return nil, err
	}
	if network, err := a.loadNetwork(); err == nil {
		for _, i := range network.Issued {
			if i.Fingerprint == fp {
				a.p.Printf("Revoked %s (%s). Hosts that don't have it on their blocklist still accept it.\n", i.Name, i.NebulaIP)
			}
		}
	}
	return map[string]any{"blocklist": h.Blocklist}, nil
}

func (a *app) consoleBlocklist(fps []string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	if c := a.currentCert(); c != nil && slices.Contains(fps, c.Fingerprint) {
		return errors.New("the list holds this machine's own cert: it would cut this machine off")
	}
	h.Blocklist = fps
	if err := a.writeLive(h, false); err != nil {
		return err
	}
	a.p.Printf("The blocklist here holds %s.\n", plural(len(fps), "cert", "certs"))
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// Settings

func (a *app) consoleSettings() error {
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	metrics := map[string]any{"enabled": h.Metrics != nil, "listen": netconf.DefaultMetricsListen}
	if h.Metrics != nil {
		metrics["listen"] = h.Metrics.Listen
	}
	return printJSON(map[string]any{
		"host":      h,
		"logging":   map[string]string{"level": h.LogLevel(), "format": h.LogFormat()},
		"metrics":   metrics,
		"blocklist": nonNilList(h.Blocklist),
	})
}

type settingsChange struct {
	Inbound     *[]netconf.Rule       `json:"inbound"`
	DNS         *bool                 `json:"dns"`
	Relay       *bool                 `json:"relay"`
	ListenPort  *int                  `json:"listen_port"`
	Lighthouses *[]netconf.Lighthouse `json:"lighthouses"`
	Resolve     *bool                 `json:"resolve"`
	Logging     *struct {
		Level  string `json:"level"`
		Format string `json:"format"`
	} `json:"logging"`
	Metrics *struct {
		Enabled bool `json:"enabled"`
	} `json:"metrics"`
}

func (a *app) consoleConfigure(raw string) (map[string]any, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	var ch settingsChange
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ch); err != nil {
		return nil, fmt.Errorf("reading the change: %w", err)
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	lighthouse := h.Role == netconf.RoleLighthouse
	restart := false
	if ch.Inbound != nil {
		for _, r := range *ch.Inbound {
			if err := checkRule(r); err != nil {
				return nil, err
			}
		}
		h.Inbound = *ch.Inbound
	}
	if (ch.DNS != nil || ch.Relay != nil || ch.ListenPort != nil) && !lighthouse {
		return nil, errors.New("DNS, relay and the listen port are lighthouse settings")
	}
	if ch.DNS != nil && *ch.DNS != h.DNS {
		h.DNS, restart = *ch.DNS, true
	}
	if ch.Relay != nil && *ch.Relay != h.Relay {
		h.Relay, restart = *ch.Relay, true
	}
	if ch.DNS != nil || ch.Relay != nil {
		self, _, _ := strings.Cut(h.NebulaIP, "/")
		for i := range h.Lighthouses {
			if h.Lighthouses[i].NebulaIP == self {
				h.Lighthouses[i].DNS, h.Lighthouses[i].Relay = h.DNS, h.Relay
			}
		}
	}
	if ch.ListenPort != nil && *ch.ListenPort != h.ListenPort {
		if err := validPort(strconv.Itoa(*ch.ListenPort)); err != nil {
			return nil, fmt.Errorf("listen port: %w", err)
		}
		h.ListenPort, restart = *ch.ListenPort, true
	}
	if ch.Lighthouses != nil {
		if lighthouse {
			return nil, errors.New("a lighthouse's lighthouse list is set with `sudo nebctl lighthouse`")
		}
		if len(*ch.Lighthouses) == 0 {
			return nil, errors.New("a node needs at least one lighthouse")
		}
		var ls []netconf.Lighthouse
		for _, l := range *ch.Lighthouses {
			if err := validAddr(l.NebulaIP); err != nil {
				return nil, err
			}
			for i, e := range l.Endpoints {
				if l.Endpoints[i], err = netconf.ParseEndpoint(e, 4242); err != nil {
					return nil, err
				}
			}
			ls = append(ls, l)
		}
		h.Lighthouses, restart = ls, true
	}
	if ch.Resolve != nil && *ch.Resolve != h.Resolve {
		h.Resolve, restart = *ch.Resolve, true
	}
	if ch.Logging != nil {
		lg := netconf.Logging{Level: h.LogLevel(), Format: h.LogFormat()}
		if ch.Logging.Level != "" {
			if !slices.Contains(netconf.LogLevels, ch.Logging.Level) {
				return nil, fmt.Errorf("log level %q: use one of %s", ch.Logging.Level, strings.Join(netconf.LogLevels, ", "))
			}
			lg.Level = ch.Logging.Level
		}
		if ch.Logging.Format != "" {
			if ch.Logging.Format != "text" && ch.Logging.Format != "json" {
				return nil, errors.New("log format: text or json")
			}
			lg.Format = ch.Logging.Format
		}
		h.Logging = &lg
	}
	if ch.Metrics != nil {
		switch {
		case ch.Metrics.Enabled && h.Metrics == nil:
			h.Metrics = &netconf.Metrics{Listen: netconf.DefaultMetricsListen}
		case !ch.Metrics.Enabled:
			h.Metrics = nil
		}
	}
	if err := a.writeLive(h, restart); err != nil {
		return nil, err
	}
	return map[string]any{"restarted": restart}, nil
}

func checkRule(r netconf.Rule) error {
	switch r.Proto {
	case "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("protocol %q: use any, tcp, udp or icmp", r.Proto)
	}
	if _, err := netconf.ParseRules(map[bool]string{true: "any/" + r.Port, false: "tcp/" + r.Port}[r.Port == "any"]); err != nil {
		return fmt.Errorf("port %q: a number, a range like 8000-8100, or any", r.Port)
	}
	if r.Group != "" && r.Host != "" && r.Host != "any" {
		return errors.New("a rule matches a group or a host, not both")
	}
	return nil
}

// Logs

// nebulaLog returns nebula's last n log lines.
func (a *app) nebulaLog(n int) ([]string, error) {
	if n < 1 || n > 5000 {
		n = 200
	}
	if a.goos == "linux" && a.root == "" {
		out, err := exec.Command("journalctl", "-u", "nebula", "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso").Output()
		if err != nil {
			return nil, fmt.Errorf("reading nebula's journal: %w", err)
		}
		return splitLines(string(out)), nil
	}
	f, err := os.Open(a.path(service.MacLog))
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read the tail only: the log can grow large.
	if st, err := f.Stat(); err == nil && st.Size() > 1<<20 {
		f.Seek(-(1 << 20), io.SeekEnd)
	}
	var all []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		all = append(all, sc.Text())
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return nonNilList(all), nil
}

func splitLines(s string) []string {
	out := []string{}
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, "-- ") {
			out = append(out, l)
		}
	}
	return out
}

// Health

func (a *app) consoleHealth() error {
	out := map[string]any{"nebctl": version, "service": "not managed (test root)", "tunnels": 0, "pending": 0}
	if v := release.InstalledVersion(a.nebulaBin()); v != "" {
		out["nebula"] = v
	}
	if a.root == "" {
		out["service"] = service.Status(a.goos)
	}
	if c := a.currentCert(); c != nil {
		out["cert"] = infoOf(*c)
	}
	if exists(a.caCrt()) && exists(a.certBin()) {
		if cas, err := a.tool().Inspect(a.caCrt()); err == nil {
			out["ca"] = map[string]any{"name": cas[0].Name, "days_left": daysLeft(cas[0].NotAfter)}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rel, err := release.Get(ctx, a.http, a.repo, ""); err == nil {
		out["latest"] = rel.Version()
	}
	if c, h, err := a.adminClient(); err == nil {
		if peers, err := c.Peers(); err == nil {
			t, p := 0, 0
			for _, pe := range peers {
				if pe.Pending {
					p++
				} else {
					t++
				}
			}
			out["tunnels"], out["pending"] = t, p
		}
		if h.Metrics != nil {
			if m, err := scrapeMetrics(ctx, a.http, h.Metrics.Listen); err == nil {
				out["metrics"] = m
			}
		}
	}
	return printJSON(out)
}

// scrapeMetrics reads nebula's Prometheus endpoint: single-value series
// only (histogram buckets left out), keyed by name and labels.
func scrapeMetrics(ctx context.Context, c *http.Client, listen string) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listen+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		l := sc.Text()
		if l == "" || l[0] == '#' || strings.Contains(l, "_bucket{") || !strings.HasPrefix(l, "nebula_") {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		if v, err := strconv.ParseFloat(l[i+1:], 64); err == nil {
			out[l[:i]] = v
		}
	}
	return out, sc.Err()
}
