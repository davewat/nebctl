// Package service runs nebula at boot: a systemd unit on Linux, a launchd
// daemon on macOS.
package service

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
)

const (
	systemdUnit  = "/etc/systemd/system/nebula.service"
	launchdLabel = "net.nebctl.nebula"
	launchdPlist = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	macLog       = "/var/log/nebula.log"
)

// DNS sends lookups for Domain to Servers over the tun device Dev. On Linux
// the unit sets it with resolvectl each time nebula starts, since the
// device (and its settings) goes away when nebula stops. Resolvectl is its
// path; empty leaves DNS alone.
type DNS struct {
	Resolvectl string
	Dev        string
	Servers    []string
	Domain     string
}

// Install writes the unit or plist, enables it at boot and (re)starts it.
func Install(goos, nebulaBin, configPath string, dns DNS) error {
	switch goos {
	case "linux":
		if _, err := exec.LookPath("systemctl"); err != nil {
			return fmt.Errorf("no systemd here; start nebula yourself with: %s -config %s", nebulaBin, configPath)
		}
		if err := os.WriteFile(systemdUnit, []byte(unit(nebulaBin, configPath, dns)), 0o644); err != nil {
			return err
		}
		if err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := run("systemctl", "enable", "nebula"); err != nil {
			return err
		}
		return run("systemctl", "restart", "nebula")
	case "darwin":
		if err := os.WriteFile(launchdPlist, []byte(plist(nebulaBin, configPath)), 0o644); err != nil {
			return err
		}
		exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run() // not loaded yet is fine
		return run("launchctl", "bootstrap", "system", launchdPlist)
	}
	return fmt.Errorf("no service support for %s", goos)
}

// Installed reports whether Install has run on this machine.
func Installed(goos string) bool {
	p := systemdUnit
	if goos == "darwin" {
		p = launchdPlist
	}
	_, err := os.Stat(p)
	return err == nil
}

func Restart(goos string) error {
	if goos == "darwin" {
		return run("launchctl", "kickstart", "-k", "system/"+launchdLabel)
	}
	return run("systemctl", "restart", "nebula")
}

func Start(goos string) error {
	if goos == "darwin" {
		if err := exec.Command("launchctl", "print", "system/"+launchdLabel).Run(); err == nil {
			return run("launchctl", "kickstart", "system/"+launchdLabel)
		}
		return run("launchctl", "bootstrap", "system", launchdPlist)
	}
	return run("systemctl", "start", "nebula")
}

func Stop(goos string) error {
	if goos == "darwin" {
		return run("launchctl", "bootout", "system/"+launchdLabel)
	}
	return run("systemctl", "stop", "nebula")
}

// Uninstall stops nebula and removes the unit or plist.
func Uninstall(goos string) error {
	if goos == "darwin" {
		exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
		return removeIfExists(launchdPlist)
	}
	exec.Command("systemctl", "disable", "--now", "nebula").Run()
	if err := removeIfExists(systemdUnit); err != nil {
		return err
	}
	return run("systemctl", "daemon-reload")
}

// Status is one line: running, stopped or not installed.
func Status(goos string) string {
	if !Installed(goos) {
		return "not installed"
	}
	if goos == "darwin" {
		out, err := exec.Command("launchctl", "print", "system/"+launchdLabel).Output()
		if err != nil {
			return "installed, not loaded"
		}
		for _, l := range strings.Split(string(out), "\n") {
			if s, ok := strings.CutPrefix(strings.TrimSpace(l), "state = "); ok {
				return s + " (logs: " + macLog + ")"
			}
		}
		return "loaded"
	}
	out, _ := exec.Command("systemctl", "is-active", "nebula").Output()
	return strings.TrimSpace(string(out)) + " (logs: journalctl -u nebula)"
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// unit follows nebula's examples/service_scripts/nebula.service. Type=notify
// runs ExecStartPost once nebula reports ready, after its tun device is up.
func unit(bin, cfg string, dns DNS) string {
	post := ""
	if dns.Resolvectl != "" && dns.Domain != "" && len(dns.Servers) > 0 {
		r := dns.Resolvectl
		post = "ExecStartPost=-" + r + " dns " + dns.Dev + " " + strings.Join(dns.Servers, " ") + "\n" +
			"ExecStartPost=-" + r + " domain " + dns.Dev + " ~" + dns.Domain + "\n" +
			"ExecStartPost=-" + r + " default-route " + dns.Dev + " false\n"
	}
	return `[Unit]
Description=Nebula overlay network
Wants=basic.target network-online.target nss-lookup.target time-sync.target
After=basic.target network.target network-online.target
Before=sshd.service

[Service]
Type=notify
NotifyAccess=main
SyslogIdentifier=nebula
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=` + bin + ` -config ` + cfg + `
` + post + `Restart=always

[Install]
WantedBy=multi-user.target
`
}

func plist(bin, cfg string) string {
	e := html.EscapeString
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + e(bin) + `</string>
		<string>-config</string>
		<string>` + e(cfg) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>` + macLog + `</string>
	<key>StandardErrorPath</key>
	<string>` + macLog + `</string>
</dict>
</plist>
`
}
