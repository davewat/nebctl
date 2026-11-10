package main

import (
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/keep"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/prompt"
)

// 2026-11-09: a firewall edit could remove the last inbound rule that lets
// SSH in over Nebula, locking out an admin who reaches the host only over
// Nebula, with no warning. A save that removes it must ask first (writing
// nothing); a save that keeps tcp/22 open, by any rule that covers it, must
// not be blocked.
func TestSaveWithoutSSHNeedsConfirmation(t *testing.T) {
	a, _ := recoverApp(t, "0", "running")
	a.console = true
	h := netconf.Host{Role: netconf.RoleNode, Name: "web01.test.internal", NebulaIP: "10.9.0.7/24", ListenPort: 4242,
		Inbound: []netconf.Rule{netconf.PingRule, netconf.SSHRule}}
	if err := h.Save(a.stateFile()); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, a.stateFile())

	ping := `{"inbound":[{"proto":"icmp","port":"any","host":"any"}]}`
	v, err := a.consoleConfigure(ping)
	if err != nil {
		t.Fatal(err)
	}
	if v["confirm_required"] != "no_ssh" || v["node"] != "web01.test.internal" ||
		v["message"] != "This removes SSH over Nebula to web01.test.internal. If you reach it only over Nebula you will be locked out." {
		t.Fatalf("answer: %v", v)
	}
	if readFile(t, a.stateFile()) != before || exists(a.cfgFile()) {
		t.Fatal("a save awaiting confirmation wrote something")
	}
	if a.release != nil {
		t.Fatal("the state lock is still held")
	}

	// Rules that keep 22 open are not blocked: a range, any port, proto any.
	for _, keepOpen := range []string{
		`{"inbound":[{"proto":"tcp","port":"20-30","host":"any"}]}`,
		`{"inbound":[{"proto":"tcp","port":"any","group":"admins"}]}`,
		`{"inbound":[{"proto":"any","port":"22","host":"any"}]}`,
	} {
		if v, err := a.consoleConfigure(keepOpen); err != nil || v["confirm_required"] != nil {
			t.Fatalf("%s: %v %v", keepOpen, v, err)
		}
	}

	// Back to ping+ssh, then the operator confirms the removal.
	if _, err := a.consoleConfigure(`{"inbound":[{"proto":"icmp","port":"any"},{"proto":"tcp","port":"22"}]}`); err != nil {
		t.Fatal(err)
	}
	v, err = a.consoleConfigure(`{"confirm_no_ssh":true,"inbound":[{"proto":"icmp","port":"any","host":"any"}]}`)
	if err != nil || v["confirm_required"] != nil {
		t.Fatalf("confirmed save: %v %v", v, err)
	}
	got, _, _ := a.loadHost()
	if len(got.Inbound) != 1 || got.Inbound[0].Proto != "icmp" {
		t.Fatalf("inbound after confirm: %+v", got.Inbound)
	}
	if !exists(keep.Prev(a.cfgFile())) {
		t.Error("the config this replaced was not kept")
	}

	// A host that never had SSH is not warned about changes that keep it off.
	if v, err := a.consoleConfigure(`{"inbound":[{"proto":"icmp","port":"any"},{"proto":"udp","port":"53"}]}`); err != nil || v["confirm_required"] != nil {
		t.Fatalf("no ssh before or after: %v %v", v, err)
	}
}

// 2026-11-09: the console turns a "confirm first" answer from `nebctl app`
// into a 409 so the page can ask; ordinary answers must pass through.
func TestConfirmRequiredIs409Shaped(t *testing.T) {
	if _, ok := confirmRequired(map[string]any{"restarted": false}); ok {
		t.Fatal("an ordinary answer was taken for a confirmation")
	}
	body, ok := confirmRequired(map[string]any{"confirmRequired": "no_ssh", "message": "m", "log": ""})
	if !ok || body["error"] != "m" || body["confirmRequired"] != "no_ssh" {
		t.Fatalf("body %v", body)
	}
}

// 2026-11-09: the CLI wizard says the same as the console and asks,
// defaulting to no.
func TestAskFirewallWarnsBeforeDroppingSSH(t *testing.T) {
	ask := func(input string) (*netconf.Host, string) {
		var out strings.Builder
		a := &app{p: prompt.New(strings.NewReader(input), &out)}
		h := &netconf.Host{Name: "web01", Inbound: []netconf.Rule{netconf.PingRule, netconf.SSHRule}}
		if err := a.askFirewall(h); err != nil {
			t.Fatal(err)
		}
		return h, out.String()
	}
	// no to keeping, "Ping only", no extra ports, then no to "Save anyway?", then keep.
	h, out := ask("n\n2\n\nn\ny\n")
	if !strings.Contains(out, "This removes SSH over Nebula to web01.") || !netconf.OpensSSH(h.Inbound) {
		t.Fatalf("declined: ssh=%v\n%s", netconf.OpensSSH(h.Inbound), out)
	}
	// ... or yes: the removal goes through.
	h, _ = ask("n\n2\n\ny\n")
	if netconf.OpensSSH(h.Inbound) || len(h.Inbound) != 1 {
		t.Fatalf("confirmed: %+v", h.Inbound)
	}
	// Keeping the rules asks nothing.
	if h, out = ask("y\n"); strings.Contains(out, "Save anyway") || !netconf.OpensSSH(h.Inbound) {
		t.Fatalf("kept: %s", out)
	}
}
