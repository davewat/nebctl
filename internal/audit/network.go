package audit

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/davewat/nebctl/internal/hostfw"
)

func isDNS(r hostfw.Rule) bool { return r.Port == "53" && r.Proto == "udp" }

// tunDev is the tun device nebctl's Linux config names.
const tunDev = "nebula1"

type firewall struct {
	kind   string // "ufw", "nftables", "iptables", or "" for none
	denyIn bool   // unknown inbound traffic is dropped
	rules  []ufwRule
}

// ufwRule is one ALLOW (or LIMIT) line of `ufw status verbose`.
type ufwRule struct {
	to, from, iface string
}

// public reports whether the rule lets in traffic from the internet.
func (r ufwRule) public() bool {
	return strings.HasPrefix(r.from, "Anywhere") && r.iface != tunDev
}

type listener struct {
	proto string // tcp or udp
	addr  string // without brackets or %iface
	port  int
	proc  string
	pid   int
}

func (a *auditor) gather() {
	a.fw = a.readFirewall()
	a.ssh = a.readSSHD()
	if out, err := a.sys.Run("ss", "-H", "-tulpn"); err == nil {
		a.listeners = parseSS(out)
	}
}

func (a *auditor) readFirewall() firewall {
	if a.sys.Has("ufw") {
		out, _ := a.sys.Run("ufw", "status", "verbose")
		if fw, active := parseUFW(out); active {
			return fw
		}
	}
	if a.sys.Has("nft") {
		out, _ := a.sys.Run("nft", "list", "ruleset")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "hook input") && strings.Contains(l, "policy drop") {
				return firewall{kind: "nftables", denyIn: true}
			}
		}
	}
	if a.sys.Has("iptables") {
		out, _ := a.sys.Run("iptables", "-S", "INPUT")
		if strings.HasPrefix(out, "-P INPUT DROP") {
			return firewall{kind: "iptables", denyIn: true}
		}
	}
	return firewall{}
}

var spaces2 = regexp.MustCompile(`\s{2,}`)

func parseUFW(out string) (fw firewall, active bool) {
	fw.kind = "ufw"
	inRules := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "Status:"):
			active = strings.TrimSpace(strings.TrimPrefix(l, "Status:")) == "active"
		case strings.HasPrefix(l, "Default:"):
			fw.denyIn = strings.Contains(l, "deny (incoming)") || strings.Contains(l, "reject (incoming)")
		case strings.HasPrefix(l, "--"):
			inRules = true
		case inRules && strings.TrimSpace(l) != "":
			cols := spaces2.Split(strings.TrimSpace(l), -1)
			if len(cols) < 3 || !(strings.HasPrefix(cols[1], "ALLOW") || strings.HasPrefix(cols[1], "LIMIT")) {
				continue
			}
			r := ufwRule{to: strings.TrimSuffix(cols[0], " (v6)"), from: cols[2]}
			if to, iface, ok := strings.Cut(r.to, " on "); ok {
				r.to, r.iface = to, iface
			}
			fw.rules = append(fw.rules, r)
		}
	}
	return fw, active
}

// matches reports whether the rule's To column covers port/proto: "22/tcp",
// "4242", "80,443/tcp", "6000:6007/udp", "OpenSSH" or "Anywhere".
func (r ufwRule) matches(port int, proto string) bool {
	for _, tok := range strings.Fields(r.to) {
		switch tok {
		case "Anywhere":
			return true
		case "OpenSSH":
			if port == 22 && proto == "tcp" {
				return true
			}
			continue
		}
		spec, p, _ := strings.Cut(tok, "/")
		if p != "" && p != proto {
			continue
		}
		for _, part := range strings.Split(spec, ",") {
			lo, hi, isRange := strings.Cut(part, ":")
			l, err := strconv.Atoi(lo)
			if err != nil {
				continue
			}
			h := l
			if isRange {
				if h, err = strconv.Atoi(hi); err != nil {
					continue
				}
			}
			if port >= l && port <= h {
				return true
			}
		}
	}
	return false
}

// allowing returns the ufw rules that let port/proto in.
func (fw firewall) allowing(port int, proto string) []ufwRule {
	var rs []ufwRule
	for _, r := range fw.rules {
		if r.matches(port, proto) {
			rs = append(rs, r)
		}
	}
	return rs
}

func publicRules(rs []ufwRule) []ufwRule {
	var out []ufwRule
	for _, r := range rs {
		if r.public() {
			out = append(out, r)
		}
	}
	return out
}

var ssProc = regexp.MustCompile(`\(\("([^"]+)",pid=(\d+)`)

// parseSS reads `ss -H -tulpn`: netid state recv-q send-q local peer process.
func parseSS(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		i := strings.LastIndex(f[4], ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(f[4][i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(f[4][:i], "[]")
		if j := strings.Index(addr, "%"); j >= 0 {
			addr = addr[:j]
		}
		l := listener{proto: f[0], addr: addr, port: port}
		if m := ssProc.FindStringSubmatch(line); m != nil {
			l.proc = m[1]
			l.pid, _ = strconv.Atoi(m[2])
		}
		ls = append(ls, l)
	}
	return ls
}

// exposed reports whether a listener's address can be reached from the
// internet: every address, or a public one.
func (a *auditor) exposed(l listener) bool {
	if l.addr == "*" || l.addr == "0.0.0.0" || l.addr == "::" {
		return true
	}
	ip, err := netip.ParseAddr(l.addr)
	if err != nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

func (a *auditor) nebulaPort() int {
	if h := a.in.Host; h != nil && h.ListenPort > 0 {
		return h.ListenPort
	}
	return 4242
}

// nebulaCIDR is the Nebula network, e.g. 10.221.220.0/22, or "".
func (a *auditor) nebulaCIDR() (network, addr string) {
	if a.in.Host == nil {
		return "", ""
	}
	p, err := netip.ParsePrefix(a.in.Host.NebulaIP)
	if err != nil {
		return "", ""
	}
	return p.Masked().String(), p.Addr().String()
}

// syncFix brings ufw in step with nebula's config.
const syncFix = "sudo nebctl firewall"

// blockedOver returns the rules nebula's firewall needs over Nebula that ufw
// doesn't let in on the nebula device.
func (a *auditor) blockedOver(fw firewall) []hostfw.Rule {
	if a.in.Host == nil {
		return nil
	}
	network, _ := a.nebulaCIDR()
	var out []hostfw.Rule
	for _, w := range hostfw.Wanted(*a.in.Host) {
		if w.Part == hostfw.PartOver && !fw.letsInOver(w, network) {
			out = append(out, w)
		}
	}
	return out
}

// letsInOver reports whether a ufw rule lets w in on the nebula device: one
// on that device, or one on every device from anywhere or the Nebula
// network.
func (fw firewall) letsInOver(w hostfw.Rule, network string) bool {
	protos := []string{w.Proto}
	if w.Proto == "" {
		protos = []string{"tcp", "udp"}
	}
	lo, hi, _ := strings.Cut(w.Port, ":")
	for _, proto := range protos {
		ok := false
		for _, r := range fw.rules {
			from := strings.TrimSuffix(r.from, " (v6)")
			if !(r.iface == tunDev || r.iface == "" && (from == "Anywhere" || from == network)) {
				continue
			}
			if w.Port == "" {
				ok = strings.HasPrefix(r.to, "Anywhere") && (!strings.Contains(r.to, "/") || strings.HasSuffix(r.to, "/"+proto))
			} else {
				l, _ := strconv.Atoi(lo)
				h := l
				if hi != "" {
					h, _ = strconv.Atoi(hi)
				}
				ok = r.matches(l, proto) && r.matches(h, proto)
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (a *auditor) firewallChecks() {
	a.section = "Firewall"
	fw := a.fw
	port := a.nebulaPort()
	switch {
	case fw.kind == "":
		fix := []string{}
		if !a.sys.Has("ufw") {
			fix = append(fix, "sudo apt install ufw")
		}
		fix = append(fix, "sudo ufw allow OpenSSH")
		if a.in.Host != nil {
			fix = append(fix, syncFix+"   # what nebula needs")
		}
		fix = append(fix, "sudo ufw enable")
		a.add(Fail, "No host firewall is on",
			"Every port this machine listens on is open to the internet, unless your cloud provider's firewall blocks it. Allow SSH before enabling ufw, or you lock yourself out.",
			fix...)
	case !fw.denyIn:
		a.add(Fail, "ufw is on but lets in everything by default", "", "sudo ufw default deny incoming")
	case fw.kind == "ufw":
		a.add(Pass, "ufw is on and refuses inbound traffic by default", "")
	default:
		a.add(Pass, "The firewall ("+fw.kind+") drops inbound traffic by default",
			"nebctl reads ufw's rules only, so it can't tell which ports this firewall allows.")
	}
	if a.isLighthouse() && fw.kind == "ufw" && fw.denyIn {
		if rs := publicRules(fw.allowing(port, "udp")); len(rs) > 0 {
			a.add(Pass, fmt.Sprintf("ufw lets nodes reach nebula on UDP %d", port), "")
		} else {
			a.add(Fail, fmt.Sprintf("ufw blocks UDP %d: nodes can't reach this lighthouse", port), "",
				syncFix, fmt.Sprintf("# or: sudo ufw allow %d/udp", port))
		}
	}
	if fw.kind == "ufw" && fw.denyIn && a.in.Host != nil {
		if blocked := a.blockedOver(fw); len(blocked) > 0 {
			var names []string
			for _, r := range blocked {
				names = append(names, strings.TrimSuffix(r.String(), " on "+tunDev))
			}
			a.add(Fail, "ufw blocks what nebula lets in over Nebula: "+strings.Join(names, ", "),
				"Nebula's firewall allows these, but ufw drops them on "+tunDev+", so Nebula hosts can't reach them"+
					map[bool]string{true: " (DNS among them: names under the network's domain don't resolve)", false: ""}[a.isLighthouse() && a.in.Host.DNS && slices.ContainsFunc(blocked, isDNS)]+".",
				syncFix)
		} else if len(hostfw.Wanted(*a.in.Host)) > 0 {
			a.add(Pass, "ufw lets in what nebula allows over Nebula", "")
		}
	}
	allow := "SSH"
	if a.isLighthouse() {
		allow = fmt.Sprintf("UDP %d and SSH", port)
	}
	a.add(Info, "Check your cloud provider's firewall too",
		"This audit can't see it. Let in only "+allow+"; with SSH over Nebula, a lighthouse needs nothing but its UDP port.")
}

func (a *auditor) portChecks() {
	a.section = "Listening ports"
	if a.listeners == nil {
		a.add(Info, "Couldn't list listening ports", "`ss -tulpn` failed; run the audit with sudo.")
		return
	}
	ssh := a.sshPorts()
	type key struct {
		proto string
		port  int
		proc  string
	}
	seen := map[key]bool{}
	var keys []key
	for _, l := range a.listeners {
		if !a.exposed(l) {
			continue
		}
		k := key{l.proto, l.port, l.proc}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	others := 0
	for _, k := range keys {
		name := k.proc
		if name == "" {
			name = "a process"
		}
		what := fmt.Sprintf("%s on %s %d", name, strings.ToUpper(k.proto), k.port)
		switch {
		case k.proc == "nebula":
			a.add(Pass, "nebula listens on "+strings.ToUpper(k.proto)+" "+strconv.Itoa(k.port), "")
			continue
		case k.proto == "tcp" && ssh[k.port]:
			continue // the SSH section covers it
		case k.proto == "udp" && (k.port == 68 || k.port == 546):
			continue // DHCP client
		}
		others++
		fw := a.fw
		switch {
		case fw.kind == "":
			a.add(Fail, what+" is open to the internet",
				"Nothing stands between it and the internet. Bind it to 127.0.0.1 or the Nebula address if only this machine or the Nebula network needs it.")
		case fw.kind == "ufw" && fw.denyIn:
			if rs := publicRules(fw.allowing(k.port, k.proto)); len(rs) > 0 {
				a.add(Warn, what+" is open to the internet",
					"ufw allows it from anywhere. If only Nebula hosts need it, allow it from the Nebula network instead.",
					ufwRestrict(rs, k.port, k.proto, a)...)
			} else {
				a.add(Info, what+" listens on every address; ufw blocks it",
					"Bind it to 127.0.0.1 or the Nebula address so it stays private if the firewall changes.")
			}
		default:
			a.add(Info, what+" listens on every address",
				"Check that the firewall blocks it, or bind it to 127.0.0.1 or the Nebula address.")
		}
	}
	if others == 0 {
		a.add(Pass, "Nothing else listens on a public address", "")
	}
}

// ufwRestrict moves a ufw allow from anywhere to the Nebula network.
func ufwRestrict(rs []ufwRule, port int, proto string, a *auditor) []string {
	var fix []string
	if network, _ := a.nebulaCIDR(); network != "" {
		fix = append(fix, fmt.Sprintf("sudo ufw allow from %s to any port %d proto %s", network, port, proto))
	}
	done := map[string]bool{}
	for _, r := range rs {
		if done[r.to] {
			continue
		}
		done[r.to] = true
		fix = append(fix, "sudo ufw delete allow "+r.to)
	}
	return fix
}

// sshPorts are the ports sshd listens on (from `sshd -T`), 22 when unknown.
func (a *auditor) sshPorts() map[int]bool {
	ports := map[int]bool{}
	for _, p := range a.sshd()["port"] {
		if n, err := strconv.Atoi(p); err == nil {
			ports[n] = true
		}
	}
	if len(ports) == 0 {
		ports[22] = true
	}
	return ports
}

func (a *auditor) sshd() map[string][]string { return a.ssh }

// readSSHD is sshd's effective config: `sshd -T` prints "key value" lines.
// nil when there is no sshd or it can't be read.
func (a *auditor) readSSHD() map[string][]string {
	if !a.sys.Has("sshd") {
		return nil
	}
	out, err := a.sys.Run("sshd", "-T")
	if err != nil {
		return nil
	}
	cfg := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if ok {
			cfg[k] = append(cfg[k], v)
		}
	}
	return cfg
}

func first(cfg map[string][]string, key string) string {
	if v := cfg[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (a *auditor) sshChecks() {
	a.section = "SSH"
	if !a.sys.Has("sshd") {
		a.add(Pass, "No SSH server is installed", "")
		return
	}
	cfg := a.sshd()
	if cfg == nil {
		a.add(Info, "Couldn't read sshd's settings", "`sshd -T` failed; run the audit with sudo.")
		return
	}
	const dropIn = "/etc/ssh/sshd_config.d/00-nebctl.conf"

	passwords := first(cfg, "passwordauthentication") == "yes" ||
		(first(cfg, "kbdinteractiveauthentication") == "yes" && first(cfg, "usepam") == "yes")
	if passwords {
		a.add(Fail, "SSH accepts passwords",
			"Bots try passwords against every SSH server on the internet. Allow keys only. sshd keeps the first value it reads, so a 00- file wins over cloud-init's 50- file.",
			"# check you can log in with a key first, then:",
			"printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a "+dropIn,
			"sudo sshd -t && sudo systemctl reload ssh")
	} else {
		a.add(Pass, "SSH accepts keys only", "")
	}

	switch first(cfg, "permitrootlogin") {
	case "no", "forced-commands-only":
		a.add(Pass, "root can't log in over SSH", "")
	default:
		a.add(Warn, "root can log in over SSH",
			"Log in as your own user and use sudo, so a stolen key isn't root on its own and sudo logs who did what.",
			"# make a user with sudo and your key first, and check you can log in as it:",
			"#   sudo adduser <you> && sudo usermod -aG sudo <you>",
			"#   sudo rsync -a --chown=<you>:<you> /root/.ssh/ /home/<you>/.ssh/",
			"echo 'PermitRootLogin no' | sudo tee -a "+dropIn,
			"sudo sshd -t && sudo systemctl reload ssh")
	}

	public := false
	ports := a.sshPorts()
	listening := false
	for _, l := range a.listeners {
		if l.proto == "tcp" && ports[l.port] && a.exposed(l) {
			listening = true
		}
	}
	fw := a.fw
	var open []ufwRule
	for p := range ports {
		open = append(open, publicRules(fw.allowing(p, "tcp"))...)
	}
	network, addr := a.nebulaCIDR()
	switch {
	case !listening && a.listeners != nil:
		a.add(Pass, "SSH listens only on private addresses", "")
	case fw.kind == "":
		public = true
		a.add(Warn, "SSH is open to the whole internet", "Turn on the firewall (see Firewall above).")
	case fw.kind == "ufw" && len(open) > 0:
		public = true
		detail := "Once this machine's Nebula address works, allow SSH only from the Nebula network. Keep your provider's web console as a way back in."
		fix := []string{"# from a session over Nebula (ssh <you>@" + addr + "), so a mistake can't cut you off:"}
		if network == "" {
			fix = []string{"# set up nebula here first: sudo nebctl"}
		} else {
			if a.in.Host != nil && !allowsSSH(a.in.Host) {
				fix = append(fix, "# nebula's own firewall must let tcp/22 in first: sudo nebctl "+a.in.Host.Role+" and choose \"Ping and SSH\"")
			}
			fix = append(fix, ufwRestrict(open, 22, "tcp", a)...)
		}
		a.add(Warn, "SSH is open to the whole internet", detail, fix...)
	case fw.kind == "ufw":
		var from []string
		for p := range ports {
			for _, r := range fw.allowing(p, "tcp") {
				from = append(from, r.from)
			}
		}
		if len(from) == 0 {
			a.add(Pass, "ufw blocks SSH from the internet", "")
		} else {
			a.add(Pass, "SSH is allowed only from "+strings.Join(dedupe(from), ", "), "")
		}
	default:
		public = true
		a.add(Info, "SSH listens on a public address",
			"Check that the "+fw.kind+" firewall lets SSH in only from the Nebula network or addresses you trust.")
	}

	if !public {
		return
	}
	for _, svc := range []string{"fail2ban", "sshguard"} {
		if out, _ := a.sys.Run("systemctl", "is-active", svc); strings.TrimSpace(out) == "active" {
			a.add(Pass, svc+" is blocking repeated failed logins", "")
			return
		}
	}
	if passwords {
		a.add(Warn, "Nothing blocks repeated failed SSH logins", "", "sudo apt install fail2ban")
	} else {
		a.add(Info, "Nothing blocks repeated failed SSH logins",
			"With keys only, guessing can't succeed; fail2ban just cuts the noise in the logs.", "sudo apt install fail2ban")
	}
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		v = strings.TrimSuffix(v, " (v6)")
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
