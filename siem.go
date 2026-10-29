package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davewat/nebctl/internal/netconf"
)

// SIEM forwarding. Nebula writes its log to the systemd journal (as
// "nebula"); journald hands it to rsyslog, and a rule nebctl writes sends
// those lines on to the SIEM's syslog input. macOS has no rsyslog, so it is
// Linux only.

const siemHeader = "# Written by nebctl: forwards nebula's log lines to a SIEM. `sudo nebctl web` changes it."

func (a *app) siemConf() string { return a.path("/etc/rsyslog.d/60-nebctl-siem.conf") }

// rsyslogRule is the rule for s, in rsyslog's RainerScript.
func rsyslogRule(s netconf.SIEM) string {
	q := strconv.Quote
	proto := s.Protocol
	tls := ""
	if proto == "tls" {
		proto = "tcp"
		tls = fmt.Sprintf(`
         StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
         StreamDriverPermittedPeers=%s StreamDriver.CAFile=%s`, q(s.Host), q(s.CAFile))
	}
	return fmt.Sprintf(`%s
if $programname == 'nebula' then {
  action(type="omfwd" target=%s port="%d" protocol=%s
         template="RSYSLOG_SyslogProtocol23Format"%s
         queue.type="LinkedList" queue.size="10000" action.resumeRetryCount="-1")
}
`, siemHeader, q(s.Host), s.Port, q(proto), tls)
}

func checkSIEM(s netconf.SIEM) error {
	if s.Host == "" || strings.ContainsAny(s.Host, " \"'\\/") {
		return errors.New("SIEM host: a name or IP address")
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("SIEM port: 1 to 65535 (syslog is usually 514, or 6514 for TLS)")
	}
	switch s.Protocol {
	case "udp", "tcp":
	case "tls":
		if s.CAFile == "" {
			return errors.New("TLS needs the CA file that signed the SIEM's certificate")
		}
		if _, err := os.Stat(s.CAFile); err != nil {
			return fmt.Errorf("the CA file: %w", err)
		}
	default:
		return errors.New("SIEM protocol: udp, tcp or tls")
	}
	return nil
}

// writeSIEM writes (or removes) the rsyslog rule for h and restarts rsyslog
// when it changed.
func (a *app) writeSIEM(h *netconf.Host) error {
	path := a.siemConf()
	old, _ := os.ReadFile(path)
	ours := strings.HasPrefix(string(old), siemHeader)
	if h.SIEM == nil {
		if ours {
			if err := os.Remove(path); err != nil {
				return err
			}
			a.p.Println("Stopped forwarding nebula's log to the SIEM.")
			return a.restartRsyslog()
		}
		return nil
	}
	if a.goos != "linux" {
		return errors.New("SIEM forwarding uses rsyslog, which only Linux has; on a Mac, point your SIEM's agent at " + "/var/log/nebula.log")
	}
	if len(old) > 0 && !ours {
		return fmt.Errorf("%s exists and wasn't written by nebctl; move it away first", path)
	}
	rule := rsyslogRule(*h.SIEM)
	if string(old) == rule {
		return nil
	}
	if err := writeFile(path, []byte(rule), 0o644); err != nil {
		return err
	}
	if a.root == "" {
		if out, err := exec.Command("rsyslogd", "-N1").CombinedOutput(); err != nil {
			if len(old) > 0 {
				os.WriteFile(path, old, 0o644)
			} else {
				os.Remove(path)
			}
			return fmt.Errorf("rsyslog rejected the forwarding rule, so it was not kept:\n%s", strings.TrimSpace(string(out)))
		}
	}
	a.p.Printf("Forwarding nebula's log to %s:%d over %s (%s).\n", h.SIEM.Host, h.SIEM.Port, strings.ToUpper(h.SIEM.Protocol), path)
	return a.restartRsyslog()
}

func (a *app) restartRsyslog() error {
	if a.root != "" || a.noService {
		a.p.Println("Restart rsyslog with: sudo systemctl restart rsyslog")
		return nil
	}
	if out, err := exec.Command("systemctl", "restart", "rsyslog").CombinedOutput(); err != nil {
		return fmt.Errorf("restarting rsyslog: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// siemSupport says whether forwarding can work here, and what's missing.
func (a *app) siemSupport() (bool, string) {
	if a.goos != "linux" {
		return false, "SIEM forwarding uses rsyslog, which macOS doesn't have. Point your SIEM's agent at /var/log/nebula.log instead."
	}
	if _, err := exec.LookPath("rsyslogd"); err != nil && a.root == "" {
		return false, "rsyslog isn't installed. Install it (sudo apt install rsyslog), then come back."
	}
	if a.root == "" {
		gtls, _ := filepath.Glob("/usr/lib/*/rsyslog/lmnsd_gtls.so")
		if len(gtls) == 0 {
			return true, "For TLS, install rsyslog's TLS module first: sudo apt install rsyslog-gnutls"
		}
	}
	return true, ""
}

func (a *app) consoleSIEM() error {
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	supported, note := a.siemSupport()
	out := map[string]any{"enabled": h.SIEM != nil, "host": "", "port": 514, "protocol": "tcp",
		"supported": supported, "note": note}
	if s := h.SIEM; s != nil {
		out["host"], out["port"], out["protocol"], out["ca_file"] = s.Host, s.Port, s.Protocol, s.CAFile
	}
	return printJSON(out)
}

func (a *app) consoleSetSIEM(raw string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	var in struct {
		Enabled bool `json:"enabled"`
		netconf.SIEM
	}
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return fmt.Errorf("reading the SIEM settings: %w", err)
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	if !in.Enabled {
		h.SIEM = nil
		return a.writeLive(h, false)
	}
	if supported, note := a.siemSupport(); !supported {
		return errors.New(note)
	}
	s := in.SIEM
	if s.Protocol != "tls" {
		s.CAFile = ""
	}
	if err := checkSIEM(s); err != nil {
		return err
	}
	h.SIEM = &s
	// SIEMs parse JSON lines far better than nebula's text format.
	if h.LogFormat() != "json" {
		h.Logging = &netconf.Logging{Level: h.LogLevel(), Format: "json"}
		a.p.Println("Switched nebula's log to JSON, which SIEMs parse field by field.")
	}
	return a.writeLive(h, false)
}

// siemTest sends one line tagged nebula, which the rule forwards.
func (a *app) siemTest() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok || h.SIEM == nil {
		return errors.New("SIEM forwarding is off here: save the SIEM settings first")
	}
	msg := fmt.Sprintf(`{"level":"info","msg":"nebctl SIEM test from %s"}`, h.Name)
	if a.root != "" {
		a.p.Printf("Would send: logger -t nebula '%s'\n", msg)
		return nil
	}
	if out, err := exec.Command("logger", "-t", "nebula", msg).CombinedOutput(); err != nil {
		return fmt.Errorf("logger: %v: %s", err, strings.TrimSpace(string(out)))
	}
	a.p.Printf("Sent a test line to %s:%d. Search the SIEM for \"nebctl SIEM test from %s\".\n", h.SIEM.Host, h.SIEM.Port, h.Name)
	return nil
}
