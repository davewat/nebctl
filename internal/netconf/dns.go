package netconf

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

// A lighthouse with DNS on answers A queries for every host it knows, by
// cert name, on its Nebula address. It answers nothing else (no forwarding),
// so only a domain that Nebula alone uses can be sent to it.

// DNSRule lets Nebula hosts query a lighthouse's DNS.
var DNSRule = Rule{Port: "53", Proto: "udp", Host: "any"}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidDomain accepts a DNS domain such as nebula.example.com.
func ValidDomain(s string) error {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" {
		return errors.New("required")
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRe.MatchString(l) {
			return errors.New("use letters, digits and '-' between dots, e.g. nebula.example.com")
		}
	}
	return nil
}

// CleanDomain lower-cases d and drops a trailing dot.
func CleanDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// Qualify appends domain to a short name: "fe01" becomes
// "fe01.nebula.example.com". A name with a dot is left alone.
func Qualify(name, domain string) string {
	name = strings.TrimSpace(name)
	if domain == "" || name == "" || strings.Contains(name, ".") {
		return name
	}
	return name + "." + domain
}

// Under reports whether name is inside domain.
func Under(name, domain string) bool {
	return domain != "" && strings.HasSuffix(strings.ToLower(name), "."+domain)
}

// ShortName is a name's first label.
func ShortName(name string) string {
	short, _, _ := strings.Cut(name, ".")
	return short
}

// DNSServers are the Nebula addresses of the lighthouses h can query:
// those that answer DNS, itself included.
func DNSServers(h Host) []string {
	var out []string
	self := ""
	if p, err := netip.ParsePrefix(h.NebulaIP); err == nil {
		self = p.Addr().String()
	}
	if h.Role == RoleLighthouse && h.DNS && self != "" {
		out = append(out, self)
	}
	for _, l := range h.Lighthouses {
		if l.DNS && l.NebulaIP != self {
			out = append(out, l.NebulaIP)
		}
	}
	return out
}

// Remove forgets a signed cert.
func (n *Network) Remove(name string) {
	for k := range n.Issued {
		if n.Issued[k].Name == name {
			n.Issued = append(n.Issued[:k], n.Issued[k+1:]...)
			return
		}
	}
}

// Renames finds the cert a new name under the network's domain replaces:
// one with the same first label outside the domain, as when fe01.example.com
// becomes fe01.nebula.example.com.
func (n *Network) Renames(name string) (Issued, bool) {
	if !Under(name, n.Domain) {
		return Issued{}, false
	}
	if _, ok := n.Find(name); ok {
		return Issued{}, false
	}
	for _, i := range n.Issued {
		if strings.EqualFold(ShortName(i.Name), ShortName(name)) && !Under(i.Name, n.Domain) {
			return i, true
		}
	}
	return Issued{}, false
}
