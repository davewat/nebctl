package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"strings"

	"github.com/davewat/nebctl/internal/hostfw"
	"github.com/davewat/nebctl/internal/netconf"
)

// The host firewall (ufw) must let in what nebula needs: its UDP port on a
// lighthouse, and on the nebula device what nebula's own firewall allows.
// nebctl adds those rules tagged "nebctl", removes its own when the setup
// stops needing them, and never touches other rules. See package hostfw.

type fwReport struct {
	Tool   string     `json:"tool"` // "ufw", "firewalld" or "" for none nebctl knows
	Active bool       `json:"active"`
	Rules  []fwRuleOK `json:"rules"`
	Stale  []fwRuleOK `json:"stale"` // nebctl's rules the setup no longer needs
	Note   string     `json:"note,omitempty"`
	add    []hostfw.Rule
	del    []hostfw.Rule
}

type fwRuleOK struct {
	hostfw.Rule
	Text    string `json:"text"`    // as ufw shows it
	Command string `json:"command"` // the ufw command that adds it
	OK      bool   `json:"ok"`      // nebctl's rule for it is in ufw
}

// ufw runs ufw. Tests and unprivileged runs (root set) don't touch the real
// one.
func (a *app) ufw() func(args ...string) (string, error) {
	if a.ufwCmd != nil {
		return a.ufwCmd
	}
	if a.root != "" || a.goos != "linux" || !lookPath("ufw") {
		return nil
	}
	return func(args ...string) (string, error) {
		out, err := exec.Command("ufw", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("ufw %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}
}

func (a *app) firewallState(h *netconf.Host) (fwReport, error) {
	r := fwReport{Rules: []fwRuleOK{}, Stale: []fwRuleOK{}}
	wanted := hostfw.Wanted(*h)
	out := func(rs []hostfw.Rule, ok bool) []fwRuleOK {
		o := []fwRuleOK{}
		for _, x := range rs {
			o = append(o, fwRuleOK{Rule: x, Text: x.String(), Command: x.Command(), OK: ok})
		}
		return o
	}
	ufw := a.ufw()
	if ufw == nil {
		r.Rules = out(wanted, false)
		switch {
		case a.goos == "darwin":
			r.Rules = []fwRuleOK{} // macOS's firewall allows apps, not ports
			r.Note = "macOS: nothing to keep in step. Allow nebula if macOS asks about incoming connections."
		case a.root == "" && lookPath("firewall-cmd"):
			r.Tool = "firewalld"
			r.Note = "nebctl keeps ufw in step, not firewalld: open these yourself with firewall-cmd."
		default:
			r.Note = "No ufw here, so nothing to keep in step. If another firewall runs, open these yourself."
		}
		return r, nil
	}
	r.Tool = "ufw"
	status, err := ufw("status")
	if err != nil {
		return r, err
	}
	r.Active = strings.Contains(status, "Status: active")
	added, err := ufw("show", "added")
	if err != nil {
		return r, err
	}
	r.add, r.del = hostfw.Plan(hostfw.Added(added), wanted)
	missing := map[string]bool{}
	for _, x := range r.add {
		missing[x.String()] = true
	}
	for _, x := range wanted {
		r.Rules = append(r.Rules, out([]hostfw.Rule{x}, !missing[x.String()])...)
	}
	r.Stale = out(r.del, true)
	if !r.Active {
		r.Note = "ufw is off: these rules take effect when you turn it on. Allow SSH first (sudo ufw allow OpenSSH), or you lock yourself out."
	}
	return r, nil
}

// syncFirewall brings ufw in step with h and says what it changed.
func (a *app) syncFirewall(h *netconf.Host) (fwReport, []string, error) {
	r, err := a.firewallState(h)
	ufw := a.ufw()
	if err != nil || ufw == nil {
		return r, nil, err
	}
	var did []string
	for _, x := range r.del {
		if _, err := ufw(x.DeleteArgs()...); err != nil {
			return r, did, err
		}
		did = append(did, "removed "+x.String())
	}
	for _, x := range r.add {
		if _, err := ufw(x.AddArgs()...); err != nil {
			return r, did, err
		}
		did = append(did, "allowed "+x.String()+": "+x.Why)
	}
	r, err = a.firewallState(h)
	return r, did, err
}

// syncFirewallQuietly runs after nebula's config changes. A failure is
// reported, not fatal: nebula's config is already written.
func (a *app) syncFirewallQuietly(h *netconf.Host) {
	if a.ufw() == nil {
		return
	}
	_, did, err := a.syncFirewall(h)
	for _, d := range did {
		a.p.Println("ufw: " + d)
	}
	if err != nil {
		a.p.Printf("Couldn't update ufw (%v). Run `sudo nebctl firewall` to try again.\n", err)
	}
}

// firewallCmd is `nebctl firewall`: show what the host firewall needs, and
// sync ufw.
func (a *app) firewallCmd(args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ContinueOnError)
	check := fs.Bool("check", false, "only show the rules; change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
	r, err := a.firewallState(h)
	if err != nil {
		return err
	}
	a.printFirewall(h, r)
	if r.Tool != "ufw" || len(r.add)+len(r.del) == 0 || *check {
		return nil
	}
	yes, err := a.p.Confirm("\nUpdate ufw now?", true)
	if err != nil || !yes {
		return err
	}
	_, did, err := a.syncFirewall(h)
	for _, d := range did {
		a.p.Println("  " + d)
	}
	return err
}

func (a *app) printFirewall(h *netconf.Host, r fwReport) {
	tool := "no ufw"
	if r.Tool != "" {
		tool = r.Tool
		if r.Tool == "ufw" {
			tool += map[bool]string{true: " (on)", false: " (off)"}[r.Active]
		}
	}
	a.p.Printf("Host firewall: %s\n", tool)
	mark := func(x fwRuleOK) string {
		switch {
		case r.Tool != "ufw":
			return " "
		case x.OK:
			return "✓"
		}
		return "✗"
	}
	group := func(title, part, none string) {
		a.p.Println("\n" + title)
		n := 0
		for _, x := range r.Rules {
			if x.Part == part {
				a.p.Printf("  %s %-24s %s\n", mark(x), x.Text, x.Why)
				n++
			}
		}
		if n == 0 {
			a.p.Println("  " + none)
		}
	}
	if h.Role == netconf.RoleLighthouse {
		group("For Nebula itself, from the internet:", hostfw.PartNebula, "nothing")
	} else {
		group("For Nebula itself:", hostfw.PartNebula, "nothing: a node reaches the lighthouses first, and replies come back on that")
	}
	group("Over Nebula, on "+hostfw.Dev+" (nebula's own firewall still decides who):", hostfw.PartOver, "nothing: nebula's firewall lets in ping at most")
	if len(r.Stale) > 0 {
		a.p.Println("\nNo longer needed (nebctl added these):")
		for _, x := range r.Stale {
			a.p.Println("  - " + x.Text)
		}
	}
	if r.Note != "" {
		a.p.Println("\n" + r.Note)
	}
	if r.Tool == "ufw" && len(r.add)+len(r.del) == 0 {
		a.p.Println("\nufw is in step with nebula's config.")
	}
}

// consoleFirewall is the console's view, and with apply its sync.
func (a *app) consoleFirewall(apply bool) (map[string]any, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	h, ok, err := a.loadHost()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("this machine is not set up yet: run `sudo nebctl`")
	}
	var r fwReport
	did := []string{}
	if apply {
		var d []string
		r, d, err = a.syncFirewall(h)
		did = append(did, d...)
	} else {
		r, err = a.firewallState(h)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"firewall": r, "role": h.Role, "changed": did}, nil
}
