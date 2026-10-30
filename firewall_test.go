package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/prompt"
)

// fakeUFW keeps rules the way `ufw show added` prints them: ufw puts
// "proto" after the port.
type fakeUFW struct {
	active bool
	lines  []string
	calls  []string
}

func (f *fakeUFW) run(args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch {
	case args[0] == "status":
		return map[bool]string{true: "Status: active\n", false: "Status: inactive\n"}[f.active], nil
	case args[0] == "show":
		return "Added user rules (see 'ufw status' for running firewall):\n" + strings.Join(f.lines, "\n") + "\n", nil
	case args[0] == "allow":
		f.lines = append(f.lines, canonical(args))
	case args[0] == "delete":
		want := "ufw " + strings.Join(args[1:], " ")
		f.lines = slices.DeleteFunc(f.lines, func(l string) bool {
			return strings.TrimSuffix(l, " comment 'nebctl'") == want
		})
	}
	return "", nil
}

func canonical(args []string) string {
	var words, proto, comment []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "proto":
			proto = args[i : i+2]
			i++
		case "comment":
			comment = []string{"comment", "'" + args[i+1] + "'"}
			i++
		default:
			words = append(words, args[i])
		}
	}
	return "ufw " + strings.Join(slices.Concat(words, proto, comment), " ")
}

func fwApp(t *testing.T, h netconf.Host) (*app, *fakeUFW, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	f := &fakeUFW{active: true, lines: []string{"ufw allow OpenSSH"}}
	a := &app{root: t.TempDir(), goos: "linux", ufwCmd: f.run, p: prompt.New(strings.NewReader("\n"), &out)}
	os.MkdirAll(a.cfgDir(), 0o755)
	if err := h.Save(a.stateFile()); err != nil {
		t.Fatal(err)
	}
	return a, f, &out
}

func TestFirewallSync(t *testing.T) {
	h := netconf.Host{Role: netconf.RoleLighthouse, Name: "lh", NebulaIP: "10.9.0.1/24", ListenPort: 4242, DNS: true,
		Inbound: []netconf.Rule{netconf.PingRule, netconf.SSHRule}}
	a, f, out := fwApp(t, h)
	if err := a.firewallCmd(nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"For Nebula itself, from the internet:", "✗ 4242/udp", "Over Nebula, on nebula1", "✗ 22/tcp on nebula1", "✗ 53/udp on nebula1", "allowed 53/udp on nebula1"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	want := []string{"ufw allow OpenSSH", "ufw allow 4242/udp comment 'nebctl'",
		"ufw allow in on nebula1 to any port 22 proto tcp comment 'nebctl'",
		"ufw allow in on nebula1 to any port 53 proto udp comment 'nebctl'"}
	if !slices.Equal(f.lines, want) {
		t.Fatalf("rules after sync:\n%s", strings.Join(f.lines, "\n"))
	}

	// In step: nothing changes.
	f.calls = nil
	r, did, err := a.syncFirewall(&h)
	if err != nil || len(did) != 0 || slices.ContainsFunc(f.calls, func(c string) bool { return !strings.HasPrefix(c, "s") }) {
		t.Errorf("second sync: did %v, calls %v, err %v", did, f.calls, err)
	}
	for _, x := range r.Rules {
		if !x.OK {
			t.Errorf("%s not OK after sync", x.Text)
		}
	}

	// DNS off and SSH closed: nebctl removes its own rules only.
	h.DNS, h.Inbound = false, []netconf.Rule{netconf.PingRule}
	if _, _, err := a.syncFirewall(&h); err != nil {
		t.Fatal(err)
	}
	if want := []string{"ufw allow OpenSSH", "ufw allow 4242/udp comment 'nebctl'"}; !slices.Equal(f.lines, want) {
		t.Errorf("rules after closing:\n%s", strings.Join(f.lines, "\n"))
	}
}

// Writing nebula's config brings ufw along; a node opens nothing for Nebula
// itself.
func TestFirewallFollowsConfig(t *testing.T) {
	h := netconf.Host{Role: netconf.RoleNode, Name: "web01", NebulaIP: "10.9.0.5/24", ListenPort: 4242,
		Inbound: []netconf.Rule{{Port: "443", Proto: "tcp", Group: "web"}}}
	a, f, out := fwApp(t, h)
	a.syncFirewallQuietly(&h)
	if want := []string{"ufw allow OpenSSH", "ufw allow in on nebula1 to any port 443 proto tcp comment 'nebctl'"}; !slices.Equal(f.lines, want) {
		t.Errorf("rules:\n%s", strings.Join(f.lines, "\n"))
	}
	if !strings.Contains(out.String(), "ufw: allowed 443/tcp on nebula1: nebula lets tcp/443 from group web in; nebula limits who") {
		t.Errorf("output:\n%s", out)
	}
	v, err := a.consoleFirewall(false)
	if err != nil {
		t.Fatal(err)
	}
	if r := v["firewall"].(fwReport); r.Tool != "ufw" || !r.Active || len(r.Rules) != 1 || !r.Rules[0].OK {
		t.Errorf("console view: %+v", r)
	}
}
