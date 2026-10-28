package netconf

import (
	"strings"
	"testing"
)

func TestNextFreeSkipsIssuedAndNetworkAddress(t *testing.T) {
	n := &Network{CIDR: "10.221.220.0/22"}
	got, err := n.NextFree()
	if err != nil || got != "10.221.220.1/22" {
		t.Fatalf("NextFree = %q, %v", got, err)
	}
	n.Record(Issued{Name: "a", NebulaIP: "10.221.220.1/22"})
	n.Record(Issued{Name: "b", NebulaIP: "10.221.220.2/22"})
	if got, _ := n.NextFree(); got != "10.221.220.3/22" {
		t.Fatalf("NextFree = %q", got)
	}
}

func TestNextFreeSkipsBroadcastWhenFull(t *testing.T) {
	n := &Network{CIDR: "10.0.0.0/30"} // .1 and .2 usable
	n.Record(Issued{Name: "a", NebulaIP: "10.0.0.1/30"})
	n.Record(Issued{Name: "b", NebulaIP: "10.0.0.2/30"})
	if got, err := n.NextFree(); err == nil {
		t.Fatalf("NextFree = %q, want full", got)
	}
}

func TestRecordReplacesSameName(t *testing.T) {
	n := &Network{}
	n.Record(Issued{Name: "a", NebulaIP: "10.0.0.1/24"})
	n.Record(Issued{Name: "a", NebulaIP: "10.0.0.9/24"})
	if len(n.Issued) != 1 || n.Issued[0].NebulaIP != "10.0.0.9/24" {
		t.Fatalf("Issued = %+v", n.Issued)
	}
}

func TestParseHostIP(t *testing.T) {
	for _, tc := range []struct{ in, cidr, want string }{
		{"10.221.221.5", "10.221.220.0/22", "10.221.221.5/22"},
		{"10.221.221.5/22", "10.221.220.0/22", "10.221.221.5/22"},
		{"10.221.221.5/22", "", "10.221.221.5/22"},
	} {
		p, err := ParseHostIP(tc.in, tc.cidr)
		if err != nil || p.String() != tc.want {
			t.Errorf("ParseHostIP(%q, %q) = %v, %v; want %s", tc.in, tc.cidr, p, err, tc.want)
		}
	}
	for _, tc := range []struct{ in, cidr string }{
		{"10.221.224.1", "10.221.220.0/22"}, // outside
		{"10.1.1.1", ""},                    // no prefix to borrow
		{"nonsense", "10.0.0.0/8"},
	} {
		if p, err := ParseHostIP(tc.in, tc.cidr); err == nil {
			t.Errorf("ParseHostIP(%q, %q) = %v, want error", tc.in, tc.cidr, p)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"66.228.62.148":           "66.228.62.148:4242",
		"66.228.62.148:5000":      "66.228.62.148:5000",
		"hs01.solidpath.com":      "hs01.solidpath.com:4242",
		" hs01.solidpath.com:99 ": "hs01.solidpath.com:99",
	} {
		if got, err := ParseEndpoint(in, 4242); err != nil || got != want {
			t.Errorf("ParseEndpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "host:0", "host:x", "a b"} {
		if got, err := ParseEndpoint(in, 4242); err == nil {
			t.Errorf("ParseEndpoint(%q) = %q, want error", in, got)
		}
	}
}

func TestParseRules(t *testing.T) {
	rules, err := ParseRules("tcp/443, udp/53 tcp/8000-8100")
	if err != nil || len(rules) != 3 || rules[2].Port != "8000-8100" || rules[1].Proto != "udp" {
		t.Fatalf("ParseRules = %+v, %v", rules, err)
	}
	if rules, _ := ParseRules(""); len(rules) != 0 {
		t.Fatalf("blank gave %+v", rules)
	}
	for _, in := range []string{"443", "icmp/1", "tcp/70000", "tcp/9-1"} {
		if _, err := ParseRules(in); err == nil {
			t.Errorf("ParseRules(%q) accepted", in)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"hs01.solidpath.com", "dave_dev_01", "a"} {
		if ValidName(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a b", "-x", "a/b"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRenderNode(t *testing.T) {
	h := Host{
		Role: RoleNode, Name: "fe01", NebulaIP: "10.221.221.2/22",
		Lighthouses: []Lighthouse{{NebulaIP: "10.221.221.1", Endpoints: []string{"66.228.62.148:4242"}, Relay: true}},
		Inbound:     []Rule{PingRule, {Port: "443", Proto: "tcp", Group: "web"}},
	}
	got := Render(h, Files{CACrt: "/etc/nebula/ca.crt", HostCrt: "/etc/nebula/host.crt", HostKey: "/etc/nebula/host.key"}, "linux")
	for _, want := range []string{
		`"10.221.221.1": ["66.228.62.148:4242"]`,
		"am_lighthouse: false",
		"  hosts:\n    - \"10.221.221.1\"",
		"use_relays: true\n  relays:\n    - \"10.221.221.1\"",
		"dev: nebula1",
		"port: 0",
		"      group: \"web\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
	if mac := Render(h, Files{}, "darwin"); strings.Contains(mac, "dev:") {
		t.Errorf("macOS config names a tun device:\n%s", mac)
	}
}

func TestRenderLighthouseLeavesItselfOutOfStaticHosts(t *testing.T) {
	h := Host{
		Role: RoleLighthouse, Name: "hs01", NebulaIP: "10.221.221.1/22", ListenPort: 4242, Relay: true,
		Lighthouses: []Lighthouse{{NebulaIP: "10.221.221.1", Endpoints: []string{"66.228.62.148:4242"}}},
	}
	got := Render(h, Files{}, "linux")
	for _, want := range []string{"static_host_map: {}", "am_lighthouse: true", "am_relay: true", "port: 4242", "inbound: []"} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "hosts:") {
		t.Errorf("a lighthouse lists lighthouse hosts:\n%s", got)
	}
}
