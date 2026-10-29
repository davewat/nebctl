package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var autoUpgrades = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"1"`)

func (a *auditor) updateChecks() {
	a.section = "Updates"
	if !a.sys.Has("apt-get") {
		a.add(Info, "Update checks cover apt (Ubuntu, Debian) only", "")
		return
	}

	status, _ := a.sys.Run("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
	conf, _ := a.sys.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
	if strings.Contains(status, "install ok installed") && autoUpgrades.Match(conf) {
		a.add(Pass, "Security updates install automatically (unattended-upgrades)", "")
	} else {
		a.add(Warn, "Security updates don't install automatically",
			"An internet-facing machine should take security fixes the day they ship.",
			"sudo apt install unattended-upgrades",
			"sudo dpkg-reconfigure -plow unattended-upgrades")
	}

	age := -1
	for _, p := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin"} {
		if f, err := a.sys.Stat(p); err == nil {
			age = int(a.in.Now.Sub(f.ModTime).Hours() / 24)
			break
		}
	}
	out, err := a.sys.Run("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
	switch {
	case err != nil:
		a.add(Info, "Couldn't list pending updates", strings.TrimSpace(out))
	default:
		var security []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "Inst ") && strings.Contains(l, "-security") {
				security = append(security, strings.Fields(l)[1])
			}
		}
		switch {
		case len(security) > 0:
			names := security
			if len(names) > 5 {
				names = append(names[:5:5], fmt.Sprintf("and %d more", len(security)-5))
			}
			a.add(Warn, plural(len(security), "security update is", "security updates are")+" waiting",
				strings.Join(names, ", "), "sudo apt update && sudo apt upgrade")
		case age > 7:
			a.add(Warn, fmt.Sprintf("The package lists are %d days old", age),
				"So this check may miss updates. Updating them is safe.", "sudo apt update")
		default:
			a.add(Pass, "No security updates are waiting", "")
		}
	}

	if _, err := a.sys.Stat("/var/run/reboot-required"); err == nil {
		pkgs, _ := a.sys.ReadFile("/var/run/reboot-required.pkgs")
		detail := "Updates that need a restart (often the kernel) aren't in effect until then. Nebula starts again at boot."
		if p := strings.Fields(string(pkgs)); len(p) > 0 {
			detail = "For " + strings.Join(dedupe(p), ", ") + ". " + detail
		}
		a.add(Warn, "A reboot is needed to finish updates", detail, "sudo reboot")
	} else {
		a.add(Pass, "No reboot is pending", "")
	}
}

type sysctl struct {
	key  string
	want string
	ok   func(string) bool
}

var hardening = []sysctl{
	{"net.ipv4.tcp_syncookies", "1", is("1")},
	{"net.ipv4.conf.all.rp_filter", "2", func(v string) bool { return v == "1" || v == "2" }},
	{"net.ipv4.conf.all.accept_redirects", "0", is("0")},
	{"net.ipv6.conf.all.accept_redirects", "0", is("0")},
	{"net.ipv4.conf.all.send_redirects", "0", is("0")},
	{"net.ipv4.conf.all.accept_source_route", "0", is("0")},
	{"net.ipv6.conf.all.accept_source_route", "0", is("0")},
}

func is(want string) func(string) bool { return func(v string) bool { return v == want } }

func (a *auditor) kernelChecks() {
	a.section = "Kernel"
	var off []string
	for _, s := range hardening {
		data, err := a.sys.ReadFile("/proc/sys/" + strings.ReplaceAll(s.key, ".", "/"))
		if err != nil {
			continue // IPv6 off, say
		}
		if v := strings.TrimSpace(string(data)); !s.ok(v) {
			off = append(off, fmt.Sprintf("%s is %s (want %s)", s.key, v, s.want))
		}
	}
	if len(off) == 0 {
		a.add(Pass, "Network hardening settings are on", "SYN cookies, reverse-path filtering, no ICMP redirects or source routing.")
		return
	}
	lines := make([]string, len(hardening))
	for i, s := range hardening {
		lines[i] = fmt.Sprintf("'%s = %s'", s.key, s.want)
	}
	a.add(Warn, plural(len(off), "network hardening setting is", "network hardening settings are")+" off",
		strings.Join(off, "; ")+".",
		"printf '%s\\n' "+strings.Join(lines, " ")+" | sudo tee /etc/sysctl.d/60-nebctl.conf",
		"sudo sysctl --system")
}

func (a *auditor) accountChecks() {
	a.section = "Accounts"
	passwd, err := a.sys.ReadFile("/etc/passwd")
	if err != nil {
		a.add(Info, "Couldn't read /etc/passwd", err.Error())
		return
	}
	var uid0, login []string
	for _, l := range strings.Split(string(passwd), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		if uid == 0 && f[0] != "root" {
			uid0 = append(uid0, f[0])
		}
		shell := f[6]
		if (uid == 0 || (uid >= 1000 && uid != 65534)) &&
			!strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "false") {
			login = append(login, f[0])
		}
	}
	if len(uid0) > 0 {
		a.add(Fail, "Other accounts have root's powers (UID 0): "+strings.Join(uid0, ", "),
			"Only root should have UID 0. An extra one is a common sign of a break-in.",
			"# find out why each exists, then remove it: sudo userdel <name>")
	} else {
		a.add(Pass, "Only root has UID 0", "")
	}

	if shadow, err := a.sys.ReadFile("/etc/shadow"); err == nil {
		var empty []string
		for _, l := range strings.Split(string(shadow), "\n") {
			f := strings.Split(l, ":")
			if len(f) > 1 && f[0] != "" && f[1] == "" {
				empty = append(empty, f[0])
			}
		}
		if len(empty) > 0 {
			fix := make([]string, len(empty))
			for i, u := range empty {
				fix[i] = "sudo passwd -l " + u
			}
			a.add(Fail, "Accounts with no password: "+strings.Join(empty, ", "),
				"Anyone can log in as them wherever passwords are accepted.", fix...)
		} else {
			a.add(Pass, "Every account has a password or is locked", "")
		}
	}

	if len(login) > 0 {
		a.add(Info, "Accounts that can log in: "+strings.Join(login, ", "), "Remove any you don't recognise.")
	}
}
