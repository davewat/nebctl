package audit

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
)

const launchdLabel = "system/net.nebctl.nebula"

func (a *auditor) nebula() {
	a.section = "Nebula"
	h := a.in.Host
	if h == nil {
		a.add(Info, "nebctl hasn't set up nebula on this machine",
			"Checks on nebula's own config were skipped.", "sudo nebctl")
	}
	a.service()
	a.strays()
	a.version()
	a.cert("This host's cert", a.in.HostCert, false)
	a.cert("The CA cert", a.in.CACert, true)
	a.files()
	a.caKey()
	if h != nil {
		a.nebulaFirewall()
	}
}

// mainPID is the service's nebula process, 0 when it isn't running.
func (a *auditor) mainPID() (pid int, running bool) {
	if a.in.GOOS == "darwin" {
		out, err := a.sys.Run("launchctl", "print", launchdLabel)
		if err != nil {
			return 0, false
		}
		for _, l := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "pid = "); ok {
				pid, _ = strconv.Atoi(v)
			}
		}
		return pid, pid > 0
	}
	out, _ := a.sys.Run("systemctl", "is-active", "nebula")
	if strings.TrimSpace(out) != "active" {
		return 0, false
	}
	out, _ = a.sys.Run("systemctl", "show", "-p", "MainPID", "--value", "nebula")
	pid, _ = strconv.Atoi(strings.TrimSpace(out))
	return pid, true
}

func (a *auditor) service() {
	_, running := a.mainPID()
	switch {
	case running:
		a.add(Pass, "The nebula service is running", "")
	case a.in.Host == nil:
	case a.in.GOOS == "darwin":
		a.add(Fail, "The nebula service isn't running", "",
			"tail -n 30 /var/log/nebula.log", "sudo nebctl service start")
	default:
		a.add(Fail, "The nebula service isn't running", "",
			"sudo journalctl -u nebula -n 30 --no-pager -o cat", "sudo nebctl service start")
	}
}

// strays finds nebula processes the service didn't start: one run by hand
// keeps an old config, and holds the port and device the service needs.
func (a *auditor) strays() {
	out, _ := a.sys.Run("pgrep", "-x", "nebula")
	main, _ := a.mainPID()
	for _, f := range strings.Fields(out) {
		pid, err := strconv.Atoi(f)
		if err != nil || pid == main {
			continue
		}
		what, _ := a.sys.Run("ps", "-o", "lstart=,args=", "-p", f)
		detail := "It wasn't started by the nebula service, so it may run an old config, and it holds the port and tun device the service needs."
		if what = strings.TrimSpace(what); what != "" {
			detail = "Started " + what + ". " + detail
		}
		a.add(Warn, fmt.Sprintf("Another nebula is running (PID %d)", pid), detail,
			fmt.Sprintf("sudo kill %d", pid), "sudo nebctl service restart")
	}
}

func (a *auditor) version() {
	in := a.in
	switch {
	case in.Nebula == "":
		if in.Host != nil {
			a.add(Fail, "nebula isn't installed in "+in.BinDir, "", "sudo nebctl install")
		}
	case in.Latest == "":
		a.add(Info, "nebula "+in.Nebula+" is installed; couldn't check for a newer release", in.LatestErr)
	case compareVersions(in.Nebula, in.Latest) < 0:
		a.add(Warn, fmt.Sprintf("nebula %s is out of date (latest is %s)", in.Nebula, in.Latest),
			"Releases carry security fixes. Updating restarts nebula, which drops tunnels for a few seconds.",
			"sudo nebctl update")
	default:
		a.add(Pass, "nebula "+in.Nebula+" is the latest release", "")
	}
}

// compareVersions compares dotted versions numerically: -1, 0 or 1.
func compareVersions(x, y string) int {
	xs, ys := strings.Split(x, "."), strings.Split(y, ".")
	for i := 0; i < len(xs) || i < len(ys); i++ {
		var xi, yi int
		if i < len(xs) {
			xi, _ = strconv.Atoi(strings.SplitN(xs[i], "-", 2)[0])
		}
		if i < len(ys) {
			yi, _ = strconv.Atoi(strings.SplitN(ys[i], "-", 2)[0])
		}
		if xi != yi {
			if xi < yi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (a *auditor) cert(label string, c *pki.Cert, isCA bool) {
	if c == nil {
		return
	}
	now := a.in.Now
	days := int(c.NotAfter.Sub(now).Hours() / 24)
	date := c.NotAfter.Format("2006-01-02")
	role := "node"
	if a.in.Host != nil {
		role = a.in.Host.Role
	}
	renew := []string{"# on the CA host: sudo nebctl ca sign (the same name renews it); then here: sudo nebctl " + role + ", answer n to \"Keep it?\", and paste the bundle"}
	if _, err := a.sys.Stat(filepath.Join(a.in.ConfigDir, "ca", "ca.key")); err == nil {
		renew = []string{"sudo nebctl " + role + "   # answer n to \"Keep it?\" and sign a new cert with the CA here"}
	}
	if isCA {
		renew = []string{"# every host cert ends with the CA: make a new CA (sudo nebctl ca init) and sign each host again before then"}
	}
	switch {
	case now.Before(c.NotBefore):
		a.add(Fail, label+" isn't valid until "+c.NotBefore.Format("2006-01-02 15:04"),
			"Check this machine's clock: nebula refuses certs outside their dates.", "timedatectl")
	case days < 0:
		a.add(Fail, label+" expired on "+date, "Nebula refuses expired certs.", renew...)
	case days < 30:
		a.add(Warn, fmt.Sprintf("%s expires in %s (%s)", label, plural(days, "day", "days"), date), "", renew...)
	default:
		a.add(Pass, fmt.Sprintf("%s is valid until %s", label, date), "")
	}
}

// files checks that only root can change nebula's keys, config and binaries:
// nebula runs as root, so whoever can write them can become root.
func (a *auditor) files() {
	in := a.in
	type want struct {
		path string
		mask uint32 // permission bits that must be clear
		fix  string // chmod mode
	}
	cfg := in.ConfigDir
	checks := []want{
		{cfg, 0o022, "go-w"},
		{filepath.Join(cfg, "config.yml"), 0o022, "go-w"},
		{filepath.Join(cfg, "host.key"), 0o077, "600"},
		{filepath.Join(cfg, "pending.key"), 0o077, "600"},
		{filepath.Join(cfg, "ca"), 0o077, "700"},
		{filepath.Join(cfg, "ca", "ca.key"), 0o077, "600"},
		{filepath.Join(in.BinDir, "nebula"), 0o022, "go-w"},
		{filepath.Join(in.BinDir, "nebula-cert"), 0o022, "go-w"},
	}
	if in.Self != "" {
		checks = append(checks, want{in.Self, 0o022, "go-w"})
	}
	bad := 0
	for _, c := range checks {
		f, err := a.sys.Stat(c.path)
		if err != nil {
			continue
		}
		if f.UID > 0 {
			bad++
			a.add(Fail, c.path+" isn't owned by root",
				"It runs as root or holds nebula's secrets, so whoever owns it can take over this machine or join your network.",
				"sudo chown root "+c.path)
		}
		if uint32(f.Mode.Perm())&c.mask != 0 {
			bad++
			a.add(Fail, fmt.Sprintf("%s is %s: others can %s it", c.path, f.Mode.Perm(), readOrWrite(c.mask)),
				"", "sudo chmod "+c.fix+" "+c.path)
		}
	}
	if bad == 0 {
		a.add(Pass, "Only root can read nebula's keys or change its config and binaries", "")
	}
}

func readOrWrite(mask uint32) string {
	if mask == 0o022 {
		return "change"
	}
	return "read"
}

// caKey flags a CA key on an internet-facing host: whoever takes it can sign
// certs that join the network as any host.
func (a *auditor) caKey() {
	p := filepath.Join(a.in.ConfigDir, "ca", "ca.key")
	data, err := a.sys.ReadFile(p)
	if err != nil {
		return
	}
	encrypted := strings.Contains(strings.SplitN(string(data), "\n", 2)[0], "ENCRYPTED")
	switch {
	case encrypted:
		a.add(Info, "The CA key is here, protected by a passphrase",
			"Keep a copy offline: losing it means signing every host again under a new CA.")
	case a.isLighthouse():
		a.add(Warn, "The CA key is on this internet-facing host, without a passphrase",
			"Anyone who gets root here can sign certs that join your network as any host. Keep ca.key offline and copy it back here only to sign.",
			"# copy "+p+" somewhere offline first (a password manager, an encrypted drive), then:",
			"sudo shred -u "+p,
			"# to sign later, copy it back to "+p+" (chmod 600), sign, and remove it again")
	default:
		a.add(Info, "The CA key is here, without a passphrase",
			"Keep a copy offline, and keep this machine's access tight.")
	}
}

func (a *auditor) nebulaFirewall() {
	h := a.in.Host
	rules := make([]string, 0, len(h.Inbound))
	for _, r := range h.Inbound {
		if r.Port == "any" && (r.Proto == "any" || r.Proto == "") && (r.Host == "any" || r.Host == "") && r.Group == "" {
			a.add(Warn, "Nebula's firewall lets every Nebula host reach every port here",
				"One compromised node then reaches every service on this machine. Allow only what other hosts need.",
				"sudo nebctl "+h.Role+"   # keep the cert, choose \"Ping and SSH\" and add the ports you serve")
			return
		}
		rules = append(rules, r.String())
	}
	if len(rules) == 0 {
		a.add(Pass, "Nebula's firewall lets nothing in", "")
		return
	}
	a.add(Pass, "Nebula's firewall allows only "+strings.Join(rules, ", "), "")
}

// allowsSSH reports whether nebula's own firewall lets tcp/22 in.
func allowsSSH(h *netconf.Host) bool {
	for _, r := range h.Inbound {
		if (r.Proto == "tcp" || r.Proto == "any") && (r.Port == "22" || r.Port == "any") {
			return true
		}
	}
	return false
}
