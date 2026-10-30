package hostfw

import (
	"reflect"
	"strings"
	"testing"

	"github.com/davewat/nebctl/internal/netconf"
)

func texts(rs []Rule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

func TestWanted(t *testing.T) {
	lh := netconf.Host{Role: netconf.RoleLighthouse, ListenPort: 4242, DNS: true, Inbound: []netconf.Rule{
		netconf.PingRule, netconf.SSHRule,
		{Port: "8000-8100", Proto: "any", Group: "web"},
		{Port: "443", Proto: "tcp", Host: "any"},
		{Port: "22", Proto: "tcp", Group: "admin"}, // already open from the rule above
	}}
	want := []string{"4242/udp", "22/tcp on nebula1", "8000:8100/tcp on nebula1", "8000:8100/udp on nebula1", "443/tcp on nebula1", "53/udp on nebula1"}
	if got := texts(Wanted(lh)); !reflect.DeepEqual(got, want) {
		t.Errorf("lighthouse: got %v, want %v", got, want)
	}
	for _, r := range Wanted(lh) {
		if (r.Dev == "") != (r.Part == PartNebula) {
			t.Errorf("%s is in part %s", r, r.Part)
		}
	}

	// A node needs nothing for Nebula itself, even with a fixed port.
	node := netconf.Host{Role: netconf.RoleNode, ListenPort: 4242, Inbound: []netconf.Rule{netconf.PingRule}}
	if got := Wanted(node); len(got) != 0 {
		t.Errorf("ping-only node: %v", texts(got))
	}
	node.Inbound = []netconf.Rule{netconf.AllRule}
	if got := texts(Wanted(node)); !reflect.DeepEqual(got, []string{"Anywhere on nebula1"}) {
		t.Errorf("open node: %v", got)
	}
}

func TestCommands(t *testing.T) {
	for _, tc := range []struct {
		r    Rule
		want string
	}{
		{Rule{Port: "4242", Proto: "udp"}, "sudo ufw allow 4242/udp comment 'nebctl'"},
		{Rule{Port: "53", Proto: "udp", Dev: Dev}, "sudo ufw allow in on nebula1 proto udp to any port 53 comment 'nebctl'"},
		{Rule{Dev: Dev}, "sudo ufw allow in on nebula1 to any comment 'nebctl'"},
	} {
		if got := tc.r.Command(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

// Rules as `ufw show added` prints them, in its own word order, match what
// nebctl adds; untagged rules are never nebctl's.
func TestAddedAndPlan(t *testing.T) {
	out := `Added user rules (see 'ufw status' for running firewall):
ufw allow OpenSSH
ufw allow 4242/udp comment 'nebctl'
ufw allow in on nebula1 to any port 22 proto tcp comment 'nebctl'
ufw allow in on nebula1 to any port 80 proto tcp comment 'nebctl'
ufw allow from 192.0.2.0/24 to any port 9000 comment 'nebctl'
ufw allow in on nebula1 to any port 53 proto udp
`
	added := Added(out)
	if len(added) != 4 {
		t.Fatalf("Added: %v", texts(added))
	}
	h := netconf.Host{Role: netconf.RoleLighthouse, ListenPort: 4242, DNS: true, Inbound: []netconf.Rule{netconf.SSHRule}}
	add, del := Plan(added, Wanted(h))
	if got := texts(add); !reflect.DeepEqual(got, []string{"53/udp on nebula1"}) {
		t.Errorf("add %v", got)
	}
	if got := texts(del); !reflect.DeepEqual(got, []string{"80/tcp on nebula1", "from 192.0.2.0/24 to any port 9000"}) {
		t.Errorf("delete %v", got)
	}
	// Deleting uses ufw's own words.
	if got := strings.Join(del[1].DeleteArgs(), " "); got != "delete allow from 192.0.2.0/24 to any port 9000" {
		t.Errorf("delete args %q", got)
	}
	if got := strings.Join(add[0].AddArgs(), " "); got != "allow in on nebula1 proto udp to any port 53 comment nebctl" {
		t.Errorf("add args %q", got)
	}
}
