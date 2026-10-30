package audit

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
)

// fake is a machine made of files and canned command output.
type fake struct {
	files map[string]string
	stats map[string]File
	cmds  map[string]string // "name args..." -> stdout; missing means it fails
	has   map[string]bool
}

func (f *fake) ReadFile(p string) ([]byte, error) {
	if s, ok := f.files[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (f *fake) Stat(p string) (File, error) {
	if s, ok := f.stats[p]; ok {
		return s, nil
	}
	if _, ok := f.files[p]; ok {
		return File{Mode: 0o644}, nil
	}
	return File{}, fs.ErrNotExist
}

func (f *fake) Run(name string, args ...string) (string, error) {
	out, ok := f.cmds[strings.Join(append([]string{name}, args...), " ")]
	if !ok {
		return "", errors.New("exit status 1")
	}
	return out, nil
}

func (f *fake) Has(name string) bool { return f.has[name] }

var now = time.Date(2026, 10, 29, 4, 0, 0, 0, time.UTC)

// hs01 is a fresh Ubuntu lighthouse as a cloud image leaves it: no
// firewall, SSH with passwords for root, and a nebula started by hand
// still running beside the service.
func hs01() (*fake, Input) {
	f := &fake{
		files: map[string]string{
			"/etc/os-release":                                 `PRETTY_NAME="Ubuntu 24.04.1 LTS"` + "\n",
			"/etc/nebula/ca/ca.key":                           "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\nAAAA\n",
			"/etc/passwd":                                     "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n",
			"/etc/shadow":                                     "root:$6$abc:19000::::::\ndaemon:*:19000::::::\n",
			"/proc/sys/net/ipv4/tcp_syncookies":               "1\n",
			"/proc/sys/net/ipv4/conf/all/rp_filter":           "2\n",
			"/proc/sys/net/ipv4/conf/all/accept_redirects":    "1\n",
			"/proc/sys/net/ipv6/conf/all/accept_redirects":    "1\n",
			"/proc/sys/net/ipv4/conf/all/send_redirects":      "1\n",
			"/proc/sys/net/ipv4/conf/all/accept_source_route": "0\n",
			"/etc/apt/apt.conf.d/20auto-upgrades":             "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		},
		stats: map[string]File{
			"/etc/nebula":                 {Mode: fs.ModeDir | 0o755},
			"/etc/nebula/config.yml":      {Mode: 0o600},
			"/etc/nebula/host.key":        {Mode: 0o600},
			"/etc/nebula/ca":              {Mode: fs.ModeDir | 0o700},
			"/etc/nebula/ca/ca.key":       {Mode: 0o600},
			"/usr/local/bin/nebula":       {Mode: 0o755},
			"/usr/local/bin/nebula-cert":  {Mode: 0o755, UID: 1000},
			"/var/cache/apt/pkgcache.bin": {ModTime: now.Add(-24 * time.Hour)},
		},
		cmds: map[string]string{
			"systemctl is-active nebula":                     "active\n",
			"systemctl show -p MainPID --value nebula":       "9100\n",
			"pgrep -x nebula":                                "7546\n9100\n",
			"ps -o lstart=,args= -p 7546":                    "Wed Oct 15 02:11:09 2026 ./nebula -config /etc/nebula/config.yml\n",
			"ufw status verbose":                             "Status: inactive\n",
			"iptables -S INPUT":                              "-P INPUT ACCEPT\n",
			"systemctl is-active fail2ban":                   "inactive\n",
			"systemctl is-active sshguard":                   "inactive\n",
			"dpkg-query -W -f=${Status} unattended-upgrades": "install ok installed",
			"apt-get -s -o Debug::NoLocking=1 upgrade": "Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n" +
				"Inst vim [2:9.1.0016-1ubuntu7.3] (2:9.1.0016-1ubuntu7.4 Ubuntu:24.04/noble-updates [amd64])\n",
			"ss -H -tulpn": `udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=13))
udp   UNCONN 0      0             0.0.0.0:4242       0.0.0.0:*    users:(("nebula",pid=9100,fd=7))
udp   UNCONN 0      0   66.228.62.148%eth0:68        0.0.0.0:*    users:(("systemd-network",pid=500,fd=20))
tcp   LISTEN 0      4096          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      4096             [::]:22            [::]:*    users:(("sshd",pid=800,fd=4))
tcp   LISTEN 0      511           0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=900,fd=6))
tcp   LISTEN 0      511              [::]:80            [::]:*    users:(("nginx",pid=900,fd=7))
tcp   LISTEN 0      4096        127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=950,fd=5))
tcp   LISTEN 0      4096     10.221.221.1:9100       0.0.0.0:*    users:(("node_exporter",pid=960,fd=3))
`,
			"sshd -T": "port 22\npermitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication no\nusepam yes\n",
		},
		has: map[string]bool{"sshd": true, "iptables": true, "apt-get": true},
	}
	in := Input{
		Sys:  f,
		GOOS: "linux",
		Host: &netconf.Host{
			Role: netconf.RoleLighthouse, Name: "hs01.solidpath.com", NebulaIP: "10.221.221.1/22",
			ListenPort: 4242, Relay: true,
			Inbound: []netconf.Rule{netconf.PingRule, netconf.SSHRule},
		},
		ConfigDir: "/etc/nebula",
		BinDir:    "/usr/local/bin",
		HostCert:  &pki.Cert{Name: "hs01.solidpath.com", NotBefore: now.AddDate(0, -2, 0), NotAfter: now.AddDate(0, 0, 12)},
		CACert:    &pki.Cert{Name: "solidpath", NotBefore: now.AddDate(0, -2, 0), NotAfter: now.AddDate(4, 0, 0)},
		Nebula:    "1.10.0",
		Latest:    "1.11.2",
		Now:       now,
	}
	return f, in
}

// find returns the finding whose title contains s.
func find(t *testing.T, fs []Finding, s string) Finding {
	t.Helper()
	for _, f := range fs {
		if strings.Contains(f.Title, s) {
			return f
		}
	}
	var titles []string
	for _, f := range fs {
		titles = append(titles, f.Level.String()+" "+f.Title)
	}
	t.Fatalf("no finding %q in:\n%s", s, strings.Join(titles, "\n"))
	return Finding{}
}

func none(t *testing.T, fs []Finding, s string) {
	t.Helper()
	for _, f := range fs {
		if strings.Contains(f.Title, s) {
			t.Fatalf("unexpected finding: %s %s", f.Level, f.Title)
		}
	}
}

func level(t *testing.T, fs []Finding, s string, want Level) Finding {
	t.Helper()
	f := find(t, fs, s)
	if f.Level != want {
		t.Errorf("%q is %s, want %s", f.Title, f.Level, want)
	}
	return f
}

func fixHas(t *testing.T, f Finding, s string) {
	t.Helper()
	if !strings.Contains(strings.Join(f.Fix, "\n"), s) {
		t.Errorf("%q fix lacks %q:\n%s", f.Title, s, strings.Join(f.Fix, "\n"))
	}
}

func TestFreshLighthouse(t *testing.T) {
	_, in := hs01()
	fs := Run(in)

	level(t, fs, "The nebula service is running", Pass)
	fixHas(t, level(t, fs, "Another nebula is running (PID 7546)", Warn), "sudo kill 7546")
	none(t, fs, "PID 9100")
	fixHas(t, level(t, fs, "nebula 1.10.0 is out of date (latest is 1.11.2)", Warn), "sudo nebctl update")
	fixHas(t, level(t, fs, "This host's cert expires in 12 days", Warn), "sudo nebctl lighthouse   # answer n")
	level(t, fs, "The CA cert is valid until", Pass)
	fixHas(t, level(t, fs, "/usr/local/bin/nebula-cert isn't owned by root", Fail), "sudo chown root /usr/local/bin/nebula-cert")
	fixHas(t, level(t, fs, "The CA key is on this internet-facing host", Warn), "shred -u /etc/nebula/ca/ca.key")
	level(t, fs, "Nebula's firewall allows only ping from any host, tcp/22 from any host", Pass)

	fw := level(t, fs, "No host firewall is on", Fail)
	fixHas(t, fw, "sudo apt install ufw")
	fixHas(t, fw, "sudo nebctl firewall")
	if i, j := strings.Index(strings.Join(fw.Fix, "\n"), "allow OpenSSH"), strings.Index(strings.Join(fw.Fix, "\n"), "ufw enable"); i > j {
		t.Error("the fix enables ufw before allowing SSH")
	}

	level(t, fs, "nebula listens on UDP 4242", Pass)
	level(t, fs, "nginx on TCP 80 is open to the internet", Fail)
	none(t, fs, "postgres")      // loopback
	none(t, fs, "node_exporter") // Nebula address
	none(t, fs, "systemd-network")
	none(t, fs, "sshd on")

	fixHas(t, level(t, fs, "SSH accepts passwords", Fail), "PasswordAuthentication no")
	level(t, fs, "root can log in over SSH", Warn)
	level(t, fs, "SSH is open to the whole internet", Warn)
	level(t, fs, "Nothing blocks repeated failed SSH logins", Warn)

	level(t, fs, "Security updates install automatically", Pass)
	f := level(t, fs, "1 security update is waiting", Warn)
	if f.Detail != "openssl" {
		t.Errorf("security updates detail = %q, want openssl only", f.Detail)
	}
	level(t, fs, "No reboot is pending", Pass)
	f = level(t, fs, "3 network hardening settings are off", Warn)
	fixHas(t, f, "sudo tee /etc/sysctl.d/60-nebctl.conf")
	level(t, fs, "Only root has UID 0", Pass)
	level(t, fs, "Every account has a password or is locked", Pass)
	level(t, fs, "Accounts that can log in: root", Info)
}

// After the fixes: ufw on with only nebula's port and SSH from the Nebula
// network, keys only, root locked out.
func TestHardenedLighthouse(t *testing.T) {
	f, in := hs01()
	f.has["ufw"] = true
	f.cmds["ufw status verbose"] = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
4242/udp                   ALLOW IN    Anywhere
22/tcp                     ALLOW IN    10.221.220.0/22
80/tcp                     ALLOW IN    Anywhere
4242/udp (v6)              ALLOW IN    Anywhere (v6)
80/tcp (v6)                ALLOW IN    Anywhere (v6)
`
	f.cmds["sshd -T"] = "port 22\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam yes\n"
	f.cmds["pgrep -x nebula"] = "9100\n"
	f.stats["/usr/local/bin/nebula-cert"] = File{Mode: 0o755}
	delete(f.files, "/etc/nebula/ca/ca.key")
	in.Nebula = "1.11.2"
	fs := Run(in)

	none(t, fs, "Another nebula")
	level(t, fs, "nebula 1.11.2 is the latest release", Pass)
	level(t, fs, "Only root can read nebula's keys", Pass)
	none(t, fs, "CA key")
	level(t, fs, "ufw is on and refuses inbound traffic by default", Pass)
	level(t, fs, "ufw lets nodes reach nebula on UDP 4242", Pass)
	nginx := level(t, fs, "nginx on TCP 80 is open to the internet", Warn)
	fixHas(t, nginx, "sudo ufw allow from 10.221.220.0/22 to any port 80 proto tcp")
	fixHas(t, nginx, "sudo ufw delete allow 80/tcp")
	level(t, fs, "SSH accepts keys only", Pass)
	level(t, fs, "root can't log in over SSH", Pass)
	level(t, fs, "SSH is allowed only from 10.221.220.0/22", Pass)
	none(t, fs, "failed SSH logins")
	if n := Count(fs)[Fail]; n != 0 {
		t.Errorf("%d FAIL findings, want 0", n)
	}
}

func TestSSHOpenThroughUFW(t *testing.T) {
	f, in := hs01()
	f.has["ufw"] = true
	f.cmds["ufw status verbose"] = `Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW IN    Anywhere
4242                       ALLOW IN    Anywhere
Anywhere on nebula1        ALLOW IN    Anywhere
OpenSSH (v6)               ALLOW IN    Anywhere (v6)
`
	fs := Run(in)
	ssh := level(t, fs, "SSH is open to the whole internet", Warn)
	fixHas(t, ssh, "sudo ufw allow from 10.221.220.0/22 to any port 22 proto tcp")
	fixHas(t, ssh, "sudo ufw delete allow OpenSSH")
	fixHas(t, ssh, "ssh <you>@10.221.221.1")
	level(t, fs, "ufw lets nodes reach nebula on UDP 4242", Pass)
	// ufw blocks nginx: the only allow-all rule is for the nebula device.
	level(t, fs, "nginx on TCP 80 listens on every address; ufw blocks it", Info)
}

// ufw on with nebula's port and SSH over Nebula allowed, but not DNS: hosts
// time out looking up names under the network's domain.
func TestLighthouseDNSBlocked(t *testing.T) {
	f, in := hs01()
	in.Host.DNS = true
	f.has["ufw"] = true
	rules := "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo  Action  From\n--  ------  ----\n" +
		"4242/udp                   ALLOW IN    Anywhere\n" +
		"22/tcp on nebula1          ALLOW IN    Anywhere\n"
	f.cmds["ufw status verbose"] = rules
	blocked := level(t, Run(in), "ufw blocks what nebula lets in over Nebula: 53/udp", Fail)
	fixHas(t, blocked, "sudo nebctl firewall")
	if !strings.Contains(blocked.Detail, "DNS") {
		t.Errorf("detail doesn't mention DNS: %q", blocked.Detail)
	}

	for _, rule := range []string{
		"53/udp on nebula1          ALLOW IN    Anywhere\n",
		"53/udp                     ALLOW IN    10.221.220.0/22\n",
		"Anywhere on nebula1        ALLOW IN    Anywhere\n",
	} {
		f.cmds["ufw status verbose"] = rules + rule
		fs := Run(in)
		level(t, fs, "ufw lets in what nebula allows over Nebula", Pass)
		none(t, fs, "ufw blocks what")
	}

	// From an unrelated network, the rule doesn't cover Nebula hosts.
	f.cmds["ufw status verbose"] = rules + "53/udp                     ALLOW IN    192.0.2.0/24\n"
	level(t, Run(in), "ufw blocks what nebula lets in over Nebula: 53/udp", Fail)

	// Without a firewall, the steps to turn ufw on include nebctl's sync.
	f.cmds["ufw status verbose"] = "Status: inactive\n"
	fixHas(t, level(t, Run(in), "No host firewall is on", Fail), "sudo nebctl firewall")
}

func TestLighthousePortBlocked(t *testing.T) {
	f, in := hs01()
	f.has["ufw"] = true
	f.cmds["ufw status verbose"] = "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo  Action  From\n--  ------  ----\n22/tcp                     ALLOW IN    Anywhere\n"
	fs := Run(in)
	fixHas(t, level(t, fs, "ufw blocks UDP 4242", Fail), "sudo nebctl firewall")
}

func TestServiceDownAndBadFiles(t *testing.T) {
	f, in := hs01()
	f.cmds["systemctl is-active nebula"] = "failed\n"
	f.stats["/etc/nebula/host.key"] = File{Mode: 0o644}
	f.files["/etc/passwd"] += "toor:x:0:0::/root:/bin/sh\n"
	f.files["/etc/shadow"] += "guest::19000::::::\n"
	f.files["/var/run/reboot-required.pkgs"] = "linux-image-6.8.0-48\nlinux-base\n"
	f.stats["/var/run/reboot-required"] = File{}
	in.HostCert.NotAfter = now.AddDate(0, 0, -1)
	fs := Run(in)

	level(t, fs, "The nebula service isn't running", Fail)
	// with the service down, the hand-started nebula is still a stray
	level(t, fs, "Another nebula is running (PID 9100)", Warn)
	level(t, fs, "This host's cert expired on", Fail)
	fixHas(t, level(t, fs, "/etc/nebula/host.key is -rw-r--r--: others can read it", Fail), "sudo chmod 600 /etc/nebula/host.key")
	level(t, fs, "Other accounts have root's powers (UID 0): toor", Fail)
	fixHas(t, level(t, fs, "Accounts with no password: guest", Fail), "sudo passwd -l guest")
	f2 := level(t, fs, "A reboot is needed", Warn)
	if !strings.Contains(f2.Detail, "linux-image-6.8.0-48") {
		t.Errorf("reboot detail = %q", f2.Detail)
	}
}

func TestMacChecksNebulaOnly(t *testing.T) {
	f, in := hs01()
	in.GOOS = "darwin"
	in.Host.Role = netconf.RoleNode
	f.cmds["launchctl print system/net.nebctl.nebula"] = "system/net.nebctl.nebula = {\n\tstate = running\n\tpid = 9100\n}\n"
	fs := Run(in)
	level(t, fs, "The nebula service is running", Pass)
	level(t, fs, "Host checks cover Linux", Info)
	level(t, fs, "The CA key is here, without a passphrase", Info)
	none(t, fs, "ufw")
}

func TestAppBundleOwnership(t *testing.T) {
	f, in := hs01()
	in.GOOS = "darwin"
	in.Self = "/Applications/Nebula Node.app/Contents/Resources/nebctl"
	f.stats["/Applications/Nebula Node.app"] = File{Mode: 0o755, UID: 501}
	fs := Run(in)
	got := level(t, fs, "/Applications/Nebula Node.app isn't owned by root", Fail)
	fixHas(t, got, `sudo chown -R root:wheel '/Applications/Nebula Node.app'`)
	none(t, fs, "Resources/nebctl isn't owned")
}

func TestUFWRuleMatching(t *testing.T) {
	cases := []struct {
		to    string
		port  int
		proto string
		want  bool
	}{
		{"22/tcp", 22, "tcp", true},
		{"22/tcp", 22, "udp", false},
		{"4242", 4242, "udp", true},
		{"80,443/tcp", 443, "tcp", true},
		{"6000:6007/udp", 6003, "udp", true},
		{"6000:6007/udp", 6008, "udp", false},
		{"OpenSSH", 22, "tcp", true},
		{"OpenSSH", 2222, "tcp", false},
		{"Anywhere", 9999, "tcp", true},
	}
	for _, c := range cases {
		if got := (ufwRule{to: c.to}).matches(c.port, c.proto); got != c.want {
			t.Errorf("%q matches %d/%s = %t, want %t", c.to, c.port, c.proto, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		x, y string
		want int
	}{{"1.10.0", "1.9.7", 1}, {"1.9.7", "1.10.0", -1}, {"1.11.2", "1.11.2", 0}, {"1.11", "1.11.0", 0}} {
		if got := compareVersions(c.x, c.y); got != c.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

func TestReport(t *testing.T) {
	_, in := hs01()
	fs := Run(in)
	var b bytes.Buffer
	Write(&b, Header(in), fs)
	out := b.String()
	for _, want := range []string{
		"nebctl audit: hs01.solidpath.com (lighthouse, 10.221.221.1/22), Ubuntu 24.04.1 LTS, 2026-10-29 04:00 UTC",
		"\nFirewall\n  FAIL  No host firewall is on\n",
		"        $ sudo ufw enable\n",
		"        # check you can log in with a key first, then:\n",
		"Fix the FAIL lines first",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}
