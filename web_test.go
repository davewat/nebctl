package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
)

func TestVersionState(t *testing.T) {
	for _, c := range []struct{ remote, local, want string }{
		{"", "v0.5.0", "missing"},
		{"v0.5.0", "v0.5.0", ""},
		{"v0.4.0", "v0.5.0", "old"},
		{"v0.6.0", "v0.5.0", ""},                 // newer there is fine
		{"v0.5.0", "v0.5.0-3-gabc-dirty", "old"}, // a dev build wants itself there
		{"dev", "v0.5.0", "old"},
	} {
		if got := versionState(c.remote, c.local); got != c.want {
			t.Errorf("versionState(%q, %q) = %q, want %q", c.remote, c.local, got, c.want)
		}
	}
}

func TestRekey(t *testing.T) {
	var v any
	json.Unmarshal([]byte(`{"vpn_addr":"10.42.0.2","addr_map":[{"vpn_addr":"x","learned":[]}],
		"metrics":{"nebula_hostmap_main_hosts":3},"have_ca":true}`), &v)
	got, _ := json.Marshal(rekey(v, camel, false))
	want := `{"addrMap":[{"learned":[],"vpnAddr":"x"}],"haveCa":true,"metrics":{"nebula_hostmap_main_hosts":3},"vpnAddr":"10.42.0.2"}`
	if string(got) != want {
		t.Errorf("camel:\n got %s\nwant %s", got, want)
	}
	json.Unmarshal([]byte(`{"listenPort":4242,"lighthouses":[{"nebulaIp":"10.42.0.1"}],"caFile":"/x"}`), &v)
	got, _ = json.Marshal(rekey(v, snake, false))
	if string(got) != `{"ca_file":"/x","lighthouses":[{"nebula_ip":"10.42.0.1"}],"listen_port":4242}` {
		t.Errorf("snake: %s", got)
	}
}

func TestRsyslogRule(t *testing.T) {
	r := rsyslogRule(netconf.SIEM{Host: "siem.example.com", Port: 6514, Protocol: "tls", CAFile: "/etc/ssl/siem-ca.pem"})
	for _, want := range []string{
		"if $programname == 'nebula' then",
		`target="siem.example.com" port="6514" protocol="tcp"`,
		`StreamDriver="gtls"`, `StreamDriver.CAFile="/etc/ssl/siem-ca.pem"`,
		`StreamDriverPermittedPeers="siem.example.com"`,
	} {
		if !strings.Contains(r, want) {
			t.Errorf("rule lacks %s:\n%s", want, r)
		}
	}
	if u := rsyslogRule(netconf.SIEM{Host: "10.0.0.5", Port: 514, Protocol: "udp"}); strings.Contains(u, "gtls") || !strings.Contains(u, `protocol="udp"`) {
		t.Errorf("udp rule:\n%s", u)
	}
	if err := checkSIEM(netconf.SIEM{Host: "a b", Port: 514, Protocol: "tcp"}); err == nil {
		t.Error("a host with a space was accepted")
	}
	if err := checkSIEM(netconf.SIEM{Host: "siem", Port: 6514, Protocol: "tls"}); err == nil {
		t.Error("TLS without a CA file was accepted")
	}
}

func TestPlanCert(t *testing.T) {
	a := &app{}
	n := &netconf.Network{CIDR: "10.42.0.0/24", Domain: "nebula.example.com", Issued: []netconf.Issued{
		{Name: "lh.nebula.example.com", NebulaIP: "10.42.0.1/24"},
		{Name: "fe01.example.com", NebulaIP: "10.42.0.2/24", Groups: []string{"web"}},
		{Name: "be01.nebula.example.com", NebulaIP: "10.42.0.3/24", Groups: []string{"db"}},
	}}
	r, err := a.planCert(n, "new01", "", nil, false)
	if err != nil || r.name != "new01.nebula.example.com" || r.ip.String() != "10.42.0.4/24" {
		t.Errorf("new: %+v %v", r, err)
	}
	r, _ = a.planCert(n, "be01", "", nil, false) // renewal keeps address and groups
	if r.ip.String() != "10.42.0.3/24" || !reflect.DeepEqual(r.groups, []string{"db"}) || r.replaces != "" {
		t.Errorf("renew: %+v", r)
	}
	r, _ = a.planCert(n, "fe01", "", nil, false) // moves the old name into the domain
	if r.replaces != "fe01.example.com" || r.ip.String() != "10.42.0.2/24" {
		t.Errorf("rename: %+v", r)
	}
	if _, err := a.planCert(n, "x", "10.42.0.3", nil, false); err == nil || !strings.Contains(err.Error(), "belongs to be01") {
		t.Errorf("taken address: %v", err)
	}
	if _, err := a.planCert(n, "bad name", "", nil, false); err == nil {
		t.Error("a name with a space was accepted")
	}
}
