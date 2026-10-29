package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/service"
)

// Nebula DNS: a lighthouse answers lookups for the network's hosts by cert
// name, and every host sends lookups under the network's Nebula-only domain
// to it. The lighthouse answers nothing else, which is why the domain must
// be one only Nebula uses.

const resolverHeader = "# Written by nebctl: names under this domain are looked up over Nebula."

// defaultDomain suggests nebula.<a domain the names point at>: the CA's
// name when it is a domain, else the domain of a host name such as
// hs01.example.com. Failing both, nebula.internal (reserved for private use).
func defaultDomain(caName string, hostNames ...string) string {
	try := []string{netconf.CleanDomain(caName)}
	for _, h := range hostNames {
		if _, parent, ok := strings.Cut(netconf.CleanDomain(h), "."); ok {
			try = append(try, strings.TrimPrefix(parent, "nebula."))
		}
	}
	for _, d := range try {
		if strings.Contains(d, ".") && netconf.ValidDomain("nebula."+d) == nil {
			return "nebula." + d
		}
	}
	return "nebula.internal"
}

func issuedNames(n *netconf.Network) []string {
	names := make([]string, len(n.Issued))
	for i, is := range n.Issued {
		names[i] = is.Name
	}
	return names
}

// askDomain asks for the network's DNS domain; blank means no DNS.
func (a *app) askDomain(def string) (string, error) {
	a.p.Println("\nHosts can find each other by name over Nebula, e.g. web01." + def + ".")
	a.p.Println("Use a domain only Nebula uses: the lighthouse answers nothing outside it.")
	d, err := a.p.AskValid("Domain for Nebula host names (- for none)", def, func(s string) error {
		if strings.TrimSpace(s) == "-" {
			return nil
		}
		return netconf.ValidDomain(s)
	})
	if err != nil || strings.TrimSpace(d) == "-" {
		return "", err
	}
	return netconf.CleanDomain(d), nil
}

// knownDomain is the network's domain as best this machine knows it: the
// CA's, then what a bundle said, then what was saved before.
func (a *app) knownDomain(h *netconf.Host, fromSource string) string {
	if a.haveCA() {
		if n, err := a.loadNetwork(); err == nil {
			return n.Domain
		}
	}
	if fromSource != "" {
		return fromSource
	}
	return h.Domain
}

// renameHint lists signed certs whose names DNS can't find.
func (a *app) renameHint(network *netconf.Network) {
	self := ""
	if c := a.currentCert(); c != nil {
		self = c.Name
	}
	if network.Domain == "" {
		return
	}
	var outside []string
	mine := false
	for _, i := range network.Issued {
		if !netconf.Under(i.Name, network.Domain) {
			outside = append(outside, i.Name)
			mine = mine || i.Name == self
		}
	}
	if len(outside) == 0 {
		return
	}
	a.p.Printf("\nThese certs aren't named under %s, so DNS can't find them:\n", network.Domain)
	for _, n := range outside {
		a.p.Printf("  %s -> %s\n", n, netconf.Qualify(netconf.ShortName(n), network.Domain))
	}
	a.p.Println("Rename one by signing its short name (`sudo nebctl ca sign`, then e.g. " + netconf.ShortName(outside[0]) + "):")
	a.p.Println("it keeps its address and groups, and its bundle sets up DNS on that host.")
	if mine {
		a.p.Println("For this machine's own cert, run `sudo nebctl dns` again and say yes to signing it again.")
	}
}

// askResolve asks whether this machine looks up the domain over Nebula.
func (a *app) askResolve(h *netconf.Host) error {
	servers := netconf.DNSServers(*h)
	if h.Domain == "" || len(servers) == 0 {
		h.Resolve = false
		return nil
	}
	ok, err := a.p.Confirm(fmt.Sprintf("Look up *.%s through %s?", h.Domain, strings.Join(servers, ", ")), true)
	h.Resolve = ok
	return err
}

// setResolver points the domain at the lighthouses' DNS. On macOS that is a
// file in /etc/resolver; on Linux the service sets it with resolvectl each
// time nebula starts, so this returns what the unit needs.
func (a *app) setResolver(h *netconf.Host) (service.DNS, error) {
	servers := netconf.DNSServers(*h)
	on := h.Resolve && h.Domain != "" && len(servers) > 0
	switch a.goos {
	case "darwin":
		return service.DNS{}, a.writeMacResolver(h.Domain, servers, on)
	case "linux":
		if !on {
			return service.DNS{}, nil
		}
		r, err := exec.LookPath("resolvectl")
		if err != nil {
			a.p.Printf("No systemd-resolved here, so point *.%s at %s yourself.\n", h.Domain, strings.Join(servers, ", "))
			return service.DNS{}, nil
		}
		if a.root == "" {
			if out, _ := exec.Command("systemctl", "is-active", "systemd-resolved").Output(); strings.TrimSpace(string(out)) != "active" {
				a.p.Println("systemd-resolved isn't running, so the Nebula DNS route has no effect until it is.")
			}
		}
		dns := service.DNS{Resolvectl: r, Dev: "nebula1", Servers: servers, Domain: h.Domain}
		if a.root != "" || a.noService {
			a.p.Printf("When nebula is up, run: sudo %s dns nebula1 %s && sudo %s domain nebula1 ~%s\n",
				r, strings.Join(servers, " "), r, h.Domain)
		}
		return dns, nil
	}
	return service.DNS{}, nil
}

// writeMacResolver writes /etc/resolver/<domain> and removes resolver files
// nebctl wrote for other domains.
func (a *app) writeMacResolver(domain string, servers []string, on bool) error {
	dir := a.path("/etc/resolver")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if on && e.Name() == domain {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if data, err := os.ReadFile(p); err == nil && strings.HasPrefix(string(data), resolverHeader) {
			os.Remove(p)
		}
	}
	if !on {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(resolverHeader + "\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	b.WriteString("timeout 2\n")
	if err := writeFile(filepath.Join(dir, domain), []byte(b.String()), 0o644); err != nil {
		return err
	}
	a.p.Printf("Wrote %s: *.%s is looked up through %s.\n", filepath.Join(dir, domain), domain, strings.Join(servers, ", "))
	return nil
}

// resolveHint says how to check a lookup works.
func (a *app) resolveHint(h *netconf.Host) {
	if !h.Resolve || h.Domain == "" {
		return
	}
	name := ""
	for _, l := range h.Lighthouses {
		if l.DNS && netconf.Under(l.Name, h.Domain) {
			name = l.Name
		}
	}
	if name == "" {
		if !netconf.Under(h.Name, h.Domain) {
			return
		}
		name = h.Name
	}
	if a.goos == "darwin" {
		a.p.Printf("Check a name: dscacheutil -q host -a name %s\n", name)
		a.p.Println("(dig and nslookup skip macOS's per-domain resolvers; ping and ssh use them.)")
	} else {
		a.p.Printf("Check a name: resolvectl query %s\n", name)
	}
}

// dnsCmd sets up Nebula DNS on a machine that is already set up: the
// network's domain (on the CA host), whether a lighthouse answers, which
// lighthouses answer, and whether this machine looks names up through them.
func (a *app) dnsCmd() error {
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
	self := ""
	if c := a.currentCert(); c != nil && len(c.Networks) > 0 {
		self, _, _ = strings.Cut(c.Networks[0], "/")
	}

	var network *netconf.Network
	if a.haveCA() {
		if network, err = a.loadNetwork(); err != nil {
			return err
		}
		def := network.Domain
		if def == "" {
			caName := ""
			if cas, err := a.tool().Inspect(a.caDirCrt()); err == nil {
				caName = cas[0].Name
			}
			def = defaultDomain(caName, append([]string{h.Name}, issuedNames(network)...)...)
		}
		if h.Domain, err = a.askDomain(def); err != nil {
			return err
		}
		network.Domain = h.Domain
		if err := network.Save(a.networkFile()); err != nil {
			return err
		}
		if h.Domain != "" && !netconf.Under(h.Name, h.Domain) {
			a.p.Printf("This machine's cert is for %s, so DNS can't find it.\n", h.Name)
			rename, err := a.p.Confirm("Sign it again as "+netconf.Qualify(netconf.ShortName(h.Name), h.Domain)+" (same address)?", true)
			if err != nil {
				return err
			}
			if rename {
				if _, err := a.certFromLocalCA(); err != nil {
					return err
				}
				if c := a.currentCert(); c != nil {
					h.Name = c.Name
					for i := range h.Lighthouses {
						if h.Lighthouses[i].NebulaIP == self {
							h.Lighthouses[i].Name = c.Name
						}
					}
				}
				if network, err = a.loadNetwork(); err != nil {
					return err
				}
				for k := range network.Lighthouses {
					if network.Lighthouses[k].NebulaIP == self {
						network.Lighthouses[k].Name = h.Name
					}
				}
			}
		}
	} else {
		def := h.Domain
		q := "The network's Nebula domain (`sudo nebctl ca list` on the CA host shows it; - for none)"
		d, err := a.p.AskValid(q, def, func(s string) error {
			if strings.TrimSpace(s) == "-" {
				return nil
			}
			return netconf.ValidDomain(s)
		})
		if err != nil {
			return err
		}
		h.Domain = ""
		if strings.TrimSpace(d) != "-" {
			h.Domain = netconf.CleanDomain(d)
		}
	}

	if h.Role == netconf.RoleLighthouse {
		q := fmt.Sprintf("Answer DNS for *.%s on %s:53 (reachable over Nebula only)?", h.Domain, self)
		if h.Domain == "" {
			q = fmt.Sprintf("Answer DNS for Nebula host names on %s:53 (reachable over Nebula only)?", self)
		}
		if h.DNS, err = a.p.Confirm(q, h.DNS || h.Domain != ""); err != nil {
			return err
		}
	}
	for i := range h.Lighthouses {
		l := &h.Lighthouses[i]
		if l.NebulaIP == self {
			l.DNS = h.DNS
			continue
		}
		label := l.NebulaIP
		if l.Name != "" {
			label = l.Name + " (" + l.NebulaIP + ")"
		}
		if l.DNS, err = a.p.Confirm("Does lighthouse "+label+" answer DNS?", l.DNS); err != nil {
			return err
		}
	}
	if network != nil {
		for _, l := range h.Lighthouses {
			for k := range network.Lighthouses {
				if network.Lighthouses[k].NebulaIP == l.NebulaIP {
					network.Lighthouses[k].DNS = l.DNS
				}
			}
		}
		if err := network.Save(a.networkFile()); err != nil {
			return err
		}
	}

	if err := a.askResolve(h); err != nil {
		return err
	}
	if err := a.apply(h); err != nil {
		return err
	}
	if h.Resolve && !netconf.Under(h.Name, h.Domain) {
		a.p.Printf("\nThis machine's cert is for %s, outside %s, so DNS can't find it.\n", h.Name, h.Domain)
	}
	if network != nil {
		a.renameHint(network)
		a.p.Println("\nHosts set up before this pick DNS up from their next bundle, or from `sudo nebctl dns` there.")
	}
	a.resolveHint(h)
	return nil
}
