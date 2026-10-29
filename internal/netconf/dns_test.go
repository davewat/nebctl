package netconf

import (
	"strings"
	"testing"
)

func TestQualify(t *testing.T) {
	for _, tc := range []struct{ name, domain, want string }{
		{"fe01", "example.internal", "fe01.example.internal"},
		{"fe01.example.internal", "example.internal", "fe01.example.internal"},
		{"fe01.example.com", "example.internal", "fe01.example.com"}, // a dotted name is taken as typed
		{"fe01", "", "fe01"},
	} {
		if got := Qualify(tc.name, tc.domain); got != tc.want {
			t.Errorf("Qualify(%q, %q) = %q, want %q", tc.name, tc.domain, got, tc.want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	for _, ok := range []string{"example.internal", "nebula.internal", "Nebula.Example.com.", "neb"} {
		if err := ValidDomain(ok); err != nil {
			t.Errorf("ValidDomain(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x.com", "a..b", "under_score.com", "a b.com"} {
		if ValidDomain(bad) == nil {
			t.Errorf("ValidDomain(%q) accepted", bad)
		}
	}
}

// The user's network: certs named under the public domain move into the
// Nebula-only one, keeping their addresses.
func TestRenames(t *testing.T) {
	n := &Network{CIDR: "10.221.220.0/22", Domain: "nebula.solidpath.com"}
	n.Record(Issued{Name: "fe01.solidpath.com", NebulaIP: "10.221.221.2/22"})
	n.Record(Issued{Name: "hs01.nebula.solidpath.com", NebulaIP: "10.221.221.1/22"})

	old, ok := n.Renames("fe01.nebula.solidpath.com")
	if !ok || old.Name != "fe01.solidpath.com" {
		t.Fatalf("Renames(fe01) = %+v, %t", old, ok)
	}
	if _, ok := n.Renames("hs01.nebula.solidpath.com"); ok {
		t.Error("a name already issued renames nothing")
	}
	if _, ok := n.Renames("be01.nebula.solidpath.com"); ok {
		t.Error("no cert has be01's short name")
	}
	if _, ok := n.Renames("fe01.other.com"); ok {
		t.Error("a name outside the domain renames nothing")
	}
	n.Remove("fe01.solidpath.com")
	if _, ok := n.Find("fe01.solidpath.com"); ok || len(n.Issued) != 1 {
		t.Errorf("Remove left %+v", n.Issued)
	}
}

func TestDNSServers(t *testing.T) {
	h := Host{Role: RoleLighthouse, NebulaIP: "10.221.221.1/22", DNS: true, Lighthouses: []Lighthouse{
		{NebulaIP: "10.221.221.1", DNS: true},
		{NebulaIP: "10.221.221.9", DNS: true},
		{NebulaIP: "10.221.221.10"},
	}}
	if got := strings.Join(DNSServers(h), ","); got != "10.221.221.1,10.221.221.9" {
		t.Errorf("lighthouse DNSServers = %s", got)
	}
	h.Role, h.DNS, h.NebulaIP = RoleNode, false, "10.221.221.2/22"
	if got := strings.Join(DNSServers(h), ","); got != "10.221.221.1,10.221.221.9" {
		t.Errorf("node DNSServers = %s", got)
	}
}

func TestRenderLighthouseServesDNS(t *testing.T) {
	h := Host{Role: RoleLighthouse, Name: "hs01.nebula.solidpath.com", NebulaIP: "10.221.221.1/22",
		ListenPort: 4242, DNS: true, Inbound: []Rule{PingRule, SSHRule}}
	cfg := Render(h, Files{}, "linux")
	for _, want := range []string{
		"  am_lighthouse: true\n  serve_dns: true\n  dns:\n    host: \"10.221.221.1\"\n    port: 53\n",
		"    - port: \"53\"\n      proto: udp\n      host: \"any\"\n",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %q:\n%s", want, cfg)
		}
	}
	if len(h.Inbound) != 2 {
		t.Error("Render changed the host's own rules")
	}

	// Everything already allowed: no extra rule.
	h.Inbound = []Rule{AllRule}
	if cfg := Render(h, Files{}, "linux"); strings.Contains(cfg, `port: "53"`) {
		t.Errorf("udp/53 added though every port is open:\n%s", cfg)
	}
	h.DNS = false
	if cfg := Render(h, Files{}, "linux"); strings.Contains(cfg, "serve_dns") {
		t.Error("serve_dns without DNS on")
	}
}
