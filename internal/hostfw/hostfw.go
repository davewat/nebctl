// Package hostfw works out the host firewall (ufw) rules a machine's nebula
// setup needs, and keeps the ones nebctl added in step with it.
//
// Two firewalls see Nebula traffic. Nebula's own firewall (config.yml)
// decides what other Nebula hosts may reach. The host firewall sees every
// packet, both nebula's UDP from the internet and what arrives on the nebula
// device, so it must let in:
//
//   - for Nebula itself, on a lighthouse, its UDP port from anywhere. A node
//     needs nothing: it reaches the lighthouses first, and the replies and
//     hole punching ride on that outbound traffic.
//   - over Nebula, on the nebula device only, every port nebula's firewall
//     lets in. Nebula still decides which hosts and groups may use them; ufw
//     can't see cert groups, so here a port is open to every Nebula host.
//
// Ping needs no rule: ufw lets ICMP echo in by default.
package hostfw

import (
	"strconv"
	"strings"

	"github.com/davewat/nebctl/internal/netconf"
)

// Tag is the comment on every ufw rule nebctl adds. nebctl changes or
// removes only rules that carry it.
const Tag = "nebctl"

// Dev is the tun device nebctl's Linux config names.
const Dev = "nebula1"

// Parts of the plan.
const (
	PartNebula = "nebula" // for Nebula itself
	PartOver   = "over"   // over Nebula, mirroring nebula's firewall
)

// Rule is one ufw allow rule. Empty Port, Proto or Dev means any.
type Rule struct {
	Part  string `json:"part"`
	Port  string `json:"port,omitempty"` // "4242" or "8000:8100"
	Proto string `json:"proto,omitempty"`
	Dev   string `json:"dev,omitempty"`
	Why   string `json:"why"`
	// raw is the rule as `ufw show added` printed it, for deleting.
	raw []string
}

func (r Rule) key() string { return r.Dev + "|" + r.Port + "|" + r.Proto }

// Args are ufw's arguments after "allow".
func (r Rule) Args() []string {
	if r.Dev == "" { // only nebula's own port: Port is always set
		if r.Proto == "" {
			return []string{r.Port}
		}
		return []string{r.Port + "/" + r.Proto}
	}
	args := []string{"in", "on", r.Dev}
	if r.Proto != "" {
		args = append(args, "proto", r.Proto)
	}
	args = append(args, "to", "any")
	if r.Port != "" {
		args = append(args, "port", r.Port)
	}
	return args
}

// Command is the ufw command that adds r.
func (r Rule) Command() string {
	return "sudo ufw allow " + strings.Join(r.Args(), " ") + " comment '" + Tag + "'"
}

// Wanted is what the host firewall must let in for h.
func Wanted(h netconf.Host) []Rule {
	var rs []Rule
	if h.Role == netconf.RoleLighthouse && h.ListenPort > 0 {
		rs = append(rs, Rule{Part: PartNebula, Port: strconv.Itoa(h.ListenPort), Proto: "udp",
			Why: "nebula's port: every host reaches this lighthouse here"})
	}
	seen := map[string]bool{}
	for _, nr := range netconf.Inbound(h) {
		for _, r := range overRules(nr) {
			if !seen[r.key()] {
				seen[r.key()] = true
				rs = append(rs, r)
			}
		}
	}
	return rs
}

// overRules turns one of nebula's inbound rules into ufw rules on the nebula
// device.
func overRules(nr netconf.Rule) []Rule {
	if nr.Proto == "icmp" {
		return nil
	}
	why := "nebula lets " + nr.String() + " in"
	if nr.Group != "" || nr.Host != "" && nr.Host != "any" {
		why += "; nebula limits who"
	}
	if nr == netconf.DNSRule {
		why = "this lighthouse answers DNS for Nebula hosts"
	}
	r := Rule{Part: PartOver, Dev: Dev, Why: why}
	if nr.Proto != "any" {
		r.Proto = nr.Proto
	}
	if nr.Port != "any" {
		r.Port = strings.Replace(nr.Port, "-", ":", 1)
	}
	// ufw takes a port range only with a protocol.
	if strings.Contains(r.Port, ":") && r.Proto == "" {
		tcp, udp := r, r
		tcp.Proto, udp.Proto = "tcp", "udp"
		return []Rule{tcp, udp}
	}
	return []Rule{r}
}

// Added reads `ufw show added` and returns the rules nebctl added.
func Added(out string) []Rule {
	var rs []Rule
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(l))
		n := len(f)
		if n < 5 || f[0] != "ufw" || f[1] != "allow" || f[n-2] != "comment" || strings.Trim(f[n-1], `'"`) != Tag {
			continue
		}
		rs = append(rs, parse(f[2:n-2]))
	}
	return rs
}

// parse reads ufw's rule syntax, after "allow". Anything it can't place
// makes the rule match no wanted rule, so a sync replaces it.
func parse(args []string) Rule {
	r := Rule{raw: args}
	odd := false
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			odd = true
			return ""
		}
		switch a := args[i]; a {
		case "in":
		case "on":
			r.Dev = next()
		case "proto":
			r.Proto = next()
		case "to", "from":
			if next() != "any" {
				odd = true
			}
		case "port":
			r.Port = next()
		default:
			port, proto, _ := strings.Cut(a, "/")
			if i != 0 || port == "" {
				odd = true
			}
			r.Port, r.Proto = port, proto
		}
	}
	if odd {
		r.Dev = "?" + strings.Join(args, " ")
	}
	return r
}

// Plan says which wanted rules to add, and which of nebctl's rules to
// delete because the setup no longer needs them.
func Plan(added, wanted []Rule) (add, del []Rule) {
	have := map[string]bool{}
	for _, r := range added {
		have[r.key()] = true
	}
	want := map[string]bool{}
	for _, r := range wanted {
		want[r.key()] = true
		if !have[r.key()] {
			add = append(add, r)
		}
	}
	for _, r := range added {
		if !want[r.key()] {
			del = append(del, r)
		}
	}
	return add, del
}

// DeleteArgs are ufw's arguments to delete r, one of Added's.
func (r Rule) DeleteArgs() []string {
	args := r.raw
	if args == nil {
		args = r.Args()
	}
	return append([]string{"delete", "allow"}, args...)
}

// AddArgs are ufw's arguments to add r with nebctl's tag.
func (r Rule) AddArgs() []string {
	return append(append([]string{"allow"}, r.Args()...), "comment", Tag)
}

// String is r as ufw's status shows it, e.g. "53/udp on nebula1".
func (r Rule) String() string {
	s := r.Port
	if s == "" {
		s = "Anywhere"
	}
	if r.Proto != "" {
		s += "/" + r.Proto
	}
	if strings.HasPrefix(r.Dev, "?") {
		return strings.TrimPrefix(r.Dev, "?")
	}
	if r.Dev != "" {
		s += " on " + r.Dev
	}
	return s
}
