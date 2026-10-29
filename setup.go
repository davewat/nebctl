package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davewat/nebctl/internal/bundle"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
	"github.com/davewat/nebctl/internal/service"
)

func (a *app) setupLighthouse() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.ensureNebula(); err != nil {
		return err
	}
	h, _, err := a.loadHost()
	if err != nil {
		return err
	}
	a.p.Println("\nSetting up this machine as a lighthouse: the host with a fixed public")
	a.p.Println("address that every other host checks in with to find the others.")
	got, err := a.obtainCert(netconf.RoleLighthouse)
	if err != nil {
		return err
	}
	c := a.currentCert()
	if c == nil || len(c.Networks) == 0 {
		return errors.New("no usable cert installed")
	}
	self := netip.MustParsePrefix(c.Networks[0]).Addr().String()

	if h.ListenPort == 0 {
		h.ListenPort = 4242
	}
	port, err := a.p.AskValid("UDP port to listen on", strconv.Itoa(h.ListenPort), validPort)
	if err != nil {
		return err
	}
	h.ListenPort, _ = strconv.Atoi(port)

	defHost := publicIPv4()
	for _, l := range h.Lighthouses {
		if l.NebulaIP == self && len(l.Endpoints) > 0 {
			defHost, _, _ = strings.Cut(l.Endpoints[0], ":")
		}
	}
	ep, err := a.p.AskValid("Public IP or DNS name other hosts reach this machine at", defHost,
		func(s string) error { _, err := netconf.ParseEndpoint(s, h.ListenPort); return err })
	if err != nil {
		return err
	}
	ep, _ = netconf.ParseEndpoint(ep, h.ListenPort)
	if h.Relay, err = a.p.Confirm("Relay traffic for hosts that can't reach each other directly (strict NAT)?", true); err != nil {
		return err
	}
	h.Domain = a.knownDomain(h, got.domain)
	q := fmt.Sprintf("Answer DNS for Nebula host names (on %s:53, reachable over Nebula only)?", self)
	if h.Domain != "" {
		q = fmt.Sprintf("Answer DNS for *.%s (on %s:53, reachable over Nebula only)?", h.Domain, self)
	}
	if h.DNS, err = a.p.Confirm(q, h.DNS || h.Domain != ""); err != nil {
		return err
	}

	h.Role, h.Name, h.NebulaIP = netconf.RoleLighthouse, c.Name, c.Networks[0]
	me := netconf.Lighthouse{Name: c.Name, NebulaIP: self, Endpoints: []string{ep}, Relay: h.Relay, DNS: h.DNS}
	for _, l := range got.lighthouses {
		h.Lighthouses = netconf.AddLighthouse(h.Lighthouses, l)
	}
	h.Lighthouses = netconf.AddLighthouse(h.Lighthouses, me)

	if a.haveCA() {
		network, err := a.loadNetwork()
		if err != nil {
			return err
		}
		network.Lighthouses = netconf.AddLighthouse(network.Lighthouses, me)
		if err := network.Save(a.networkFile()); err != nil {
			return err
		}
	}
	if err := a.askFirewall(h); err != nil {
		return err
	}
	if err := a.askResolve(h); err != nil {
		return err
	}
	if err := a.apply(h); err != nil {
		return err
	}
	a.firewallHint(h.ListenPort)

	if !a.haveCA() {
		a.p.Println("\nThe CA is on another machine. Record this lighthouse there so its bundles")
		a.p.Printf("carry it: run `sudo nebctl ca lighthouse` and enter %s at %s.\n", self, ep)
		return nil
	}
	for {
		more, err := a.p.Confirm("\nSign a cert for another host now?", true)
		if err != nil || !more {
			if err == nil {
				a.p.Println("Sign more any time with `sudo nebctl ca sign`.")
				if n, err := a.loadNetwork(); err == nil {
					a.renameHint(n)
				}
			}
			return err
		}
		if err := a.caSign(""); err != nil {
			return err
		}
	}
}

func (a *app) setupNode() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.ensureNebula(); err != nil {
		return err
	}
	h, _, err := a.loadHost()
	if err != nil {
		return err
	}
	a.p.Println("\nSetting up this machine as a node on a Nebula network.")
	got, err := a.obtainCert(netconf.RoleNode)
	if err != nil {
		return err
	}
	learned := got.lighthouses
	c := a.currentCert()
	if c == nil || len(c.Networks) == 0 {
		return errors.New("no usable cert installed")
	}
	if h.Role == netconf.RoleLighthouse {
		h.Lighthouses = nil // it was one of them; start from what we learn now
	}
	h.Role, h.Name, h.NebulaIP, h.ListenPort, h.Relay, h.DNS = netconf.RoleNode, c.Name, c.Networks[0], 0, false, false
	h.Domain = a.knownDomain(h, got.domain)

	if len(learned) == 0 && a.haveCA() {
		if network, err := a.loadNetwork(); err == nil {
			learned = network.Lighthouses
		}
	}
	switch {
	case len(learned) > 0:
		h.Lighthouses = learned
		a.p.Println("Lighthouses:")
		for _, l := range learned {
			a.p.Println("  " + l.String())
		}
	case len(h.Lighthouses) > 0:
		a.p.Println("Lighthouses:")
		for _, l := range h.Lighthouses {
			a.p.Println("  " + l.String())
		}
		keep, err := a.p.Confirm("Keep these?", true)
		if err != nil {
			return err
		}
		if !keep {
			h.Lighthouses = nil
		}
	}
	for len(h.Lighthouses) == 0 {
		a.p.Println("Which lighthouse should this host check in with?")
		l, err := a.askLighthouse("")
		if err != nil {
			return err
		}
		h.Lighthouses = append(h.Lighthouses, l)
		if more, err := a.p.Confirm("Add another lighthouse?", false); err != nil {
			return err
		} else if more {
			continue
		}
	}
	if err := a.askFirewall(h); err != nil {
		return err
	}
	if err := a.askResolve(h); err != nil {
		return err
	}
	if err := a.apply(h); err != nil {
		return err
	}
	a.p.Printf("\nTry it: ping %s\n", h.Lighthouses[0].NebulaIP)
	a.resolveHint(h)
	return nil
}

// learned is what a cert's source says about the network.
type learned struct {
	lighthouses []netconf.Lighthouse
	domain      string
}

// obtainCert leaves ca.crt, host.crt and host.key in the config directory,
// and returns what a bundle or the local CA said about the network.
func (a *app) obtainCert(role string) (learned, error) {
	if c := a.currentCert(); c != nil {
		ip := strings.Join(c.Networks, ",")
		d := daysLeft(c.NotAfter)
		a.p.Printf("This host has a cert for %s (%s), valid until %s.\n", c.Name, ip, c.NotAfter.Format("2006-01-02"))
		keep := d > 0
		if a.haveCA() {
			if n, err := a.loadNetwork(); err == nil && n.Domain != "" && !netconf.Under(c.Name, n.Domain) {
				a.p.Printf("Its name isn't under %s, so DNS can't find it; answer n to rename it.\n", n.Domain)
				keep = false
			}
		}
		keep, err := a.p.Confirm("Keep it?", keep)
		if err != nil || keep {
			if a.haveCA() {
				if n, err2 := a.loadNetwork(); err2 == nil {
					return learned{n.Lighthouses, n.Domain}, err
				}
			}
			return learned{}, err
		}
	}
	type option struct {
		label string
		run   func() (learned, error)
	}
	var opts []option
	if a.haveCA() {
		opts = append(opts, option{"Sign it with the CA on this machine", a.certFromLocalCA})
	} else if role == netconf.RoleLighthouse {
		opts = append(opts,
			option{"Create a new CA here, then sign this lighthouse's cert (a new network)", func() (learned, error) {
				if err := a.caInit(); err != nil {
					return learned{}, err
				}
				return a.certFromLocalCA()
			}},
			option{"Import an existing CA (ca.crt and ca.key), then sign this lighthouse's cert", func() (learned, error) {
				if err := a.caImport("", ""); err != nil {
					return learned{}, err
				}
				return a.certFromLocalCA()
			}})
	}
	opts = append(opts,
		option{"Paste a bundle made on the CA host (`nebctl ca sign`)", a.certFromBundle},
		option{"Keep the private key here: make a request for the CA host to sign", a.certFromRequest},
		option{"Import cert files I already have (ca.crt, this host's .crt and .key)", a.certFromFiles})
	labels := make([]string, len(opts))
	for i, o := range opts {
		labels[i] = o.label
	}
	i, err := a.p.Choose("How should this host get its certificate?", labels, 0)
	if err != nil {
		return learned{}, err
	}
	return opts[i].run()
}

func (a *app) certFromLocalCA() (learned, error) {
	network, err := a.loadNetwork()
	if err != nil {
		return learned{}, err
	}
	defName := hostname()
	if c := a.currentCert(); c != nil {
		defName = c.Name
	}
	r, err := a.askHostCert(network, defName, "")
	if err != nil {
		return learned{}, err
	}
	if err := os.MkdirAll(a.cfgDir(), 0o755); err != nil {
		return learned{}, err
	}
	// Sign into a temporary key so a failure leaves the running setup alone.
	tmpKey := a.hostKey() + ".new"
	_, crt, err := a.issue(network, r, "", tmpKey)
	if err != nil {
		return learned{}, err
	}
	defer os.Remove(tmpKey)
	caData, err := os.ReadFile(a.caDirCrt())
	if err != nil {
		return learned{}, err
	}
	crtData, err := os.ReadFile(crt)
	if err != nil {
		return learned{}, err
	}
	keyData, err := os.ReadFile(tmpKey)
	if err != nil {
		return learned{}, err
	}
	if _, err := a.installCert(caData, crtData, keyData); err != nil {
		return learned{}, err
	}
	return learned{network.Lighthouses, network.Domain}, nil
}

func (a *app) certFromBundle() (learned, error) {
	text, err := a.p.Paste("Paste the bundle, from its BEGIN line to its END line:", bundle.End(bundle.KindBundle))
	if err != nil {
		return learned{}, err
	}
	return a.installBundle(text)
}

func (a *app) installBundle(text string) (learned, error) {
	b, err := bundle.DecodeBundle(text)
	if err != nil {
		return learned{}, err
	}
	key := []byte(b.HostKey)
	if b.HostKey == "" {
		if key, err = a.waitingKey([]byte(b.HostCrt)); err != nil {
			return learned{}, err
		}
	}
	if _, err := a.installCert([]byte(b.CACrt), []byte(b.HostCrt), key); err != nil {
		return learned{}, err
	}
	os.Remove(a.pendingKey())
	os.Remove(a.pendingPub())
	return learned{b.Lighthouses, b.Domain}, nil
}

// waitingKey finds the key made here for a request that crt answers.
func (a *app) waitingKey(crt []byte) ([]byte, error) {
	certs, err := a.tool().InspectPEM(crt)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{a.pendingKey(), a.hostKey()} {
		key, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if ok, _ := pki.KeyMatches(key, certs[0]); ok {
			return key, nil
		}
	}
	if exists(a.pendingKey()) || exists(a.hostKey()) {
		return nil, errors.New("this bundle's cert is for a key made elsewhere (another machine, or an older request)")
	}
	return nil, errNoKey
}

func (a *app) certFromRequest() (learned, error) {
	if err := a.makeRequest(); err != nil {
		return learned{}, err
	}
	text, err := a.p.Paste("\nPaste the bundle the CA host gives back:", bundle.End(bundle.KindBundle))
	if err != nil {
		return learned{}, err
	}
	return a.installBundle(text)
}

// makeRequest makes a key pair here (once) and prints a request carrying
// the public half. The private key stays in pending.key until the signed
// cert comes back.
func (a *app) makeRequest() error {
	name, err := a.p.AskValid("Name for this host's cert", hostname(), netconf.ValidName)
	if err != nil {
		return err
	}
	ip, err := a.p.AskValid("Nebula address you want (blank lets the CA host choose)", "", func(s string) error {
		if s == "" {
			return nil
		}
		if _, err := netip.ParsePrefix(s); err == nil {
			return nil
		}
		return validAddr(s)
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfgDir(), 0o755); err != nil {
		return err
	}
	reuse := false
	if exists(a.pendingKey()) && exists(a.pendingPub()) {
		if reuse, err = a.p.Confirm("A key from an earlier request is waiting here. Reuse it?", true); err != nil {
			return err
		}
	}
	if !reuse {
		os.Remove(a.pendingKey())
		os.Remove(a.pendingPub())
		if err := a.tool().Keygen(a.pendingKey(), a.pendingPub()); err != nil {
			return err
		}
		os.Chmod(a.pendingKey(), 0o600)
	}
	pub, err := os.ReadFile(a.pendingPub())
	if err != nil {
		return err
	}
	text, err := bundle.EncodeRequest(bundle.Request{Name: name, PublicKey: string(pub), NebulaIP: ip})
	if err != nil {
		return err
	}
	a.p.Println("\nOn the CA host run `sudo nebctl ca sign-request` and paste this (it holds")
	a.p.Println("no secrets, so chat or email is fine):")
	a.p.Println()
	a.p.Print(text)
	a.p.Printf("\nThe private key stays in %s.\n", a.pendingKey())
	return nil
}

func (a *app) certFromFiles() (learned, error) {
	caPath, err := a.p.AskValid("Path to ca.crt", "ca.crt", fileExists)
	if err != nil {
		return learned{}, err
	}
	def := ""
	if h := hostname(); h != "" && exists(filepath.Join(filepath.Dir(caPath), h+".crt")) {
		def = filepath.Join(filepath.Dir(caPath), h+".crt")
	}
	crtPath, err := a.p.AskValid("Path to this host's .crt", def, fileExists)
	if err != nil {
		return learned{}, err
	}
	keyPath, err := a.p.AskValid("Path to this host's .key", strings.TrimSuffix(crtPath, ".crt")+".key", fileExists)
	if err != nil {
		return learned{}, err
	}
	var data [3][]byte
	for i, p := range []string{caPath, crtPath, keyPath} {
		if data[i], err = pki.CheckFile(p); err != nil {
			return learned{}, err
		}
	}
	_, err = a.installCert(data[0], data[1], data[2])
	return learned{}, err
}

// installCert checks the three files belong together, then writes them.
func (a *app) installCert(caData, crtData, keyData []byte) (pki.Cert, error) {
	cas, err := a.tool().InspectPEM(caData)
	if err != nil {
		return pki.Cert{}, fmt.Errorf("the CA cert: %w", err)
	}
	certs, err := a.tool().InspectPEM(crtData)
	if err != nil {
		return pki.Cert{}, fmt.Errorf("the host cert: %w", err)
	}
	c := certs[0]
	if c.IsCA {
		return pki.Cert{}, errors.New("that is a CA cert, not a host cert")
	}
	signed := false
	for _, ca := range cas {
		if ca.IsCA && ca.Fingerprint == c.Issuer {
			signed = true
		}
	}
	if !signed {
		return pki.Cert{}, errors.New("the host cert was not signed by that CA")
	}
	if !pki.IsPrivateKey(keyData) {
		return pki.Cert{}, errors.New("the key is not a private key")
	}
	if ok, err := pki.KeyMatches(keyData, c); err != nil || !ok {
		return pki.Cert{}, errors.New("the private key does not belong to the host cert")
	}
	if d := daysLeft(c.NotAfter); d < 0 {
		return pki.Cert{}, fmt.Errorf("the host cert expired on %s", c.NotAfter.Format("2006-01-02"))
	}
	if err := writeFile(a.caCrt(), caData, 0o644); err != nil {
		return pki.Cert{}, err
	}
	if err := writeFile(a.hostCrt(), crtData, 0o644); err != nil {
		return pki.Cert{}, err
	}
	if err := writeFile(a.hostKey(), keyData, 0o600); err != nil {
		return pki.Cert{}, err
	}
	a.p.Printf("Installed the cert for %s (%s), valid until %s.\n", c.Name, strings.Join(c.Networks, ","), c.NotAfter.Format("2006-01-02"))
	return c, nil
}

func (a *app) askFirewall(h *netconf.Host) error {
	if len(h.Inbound) > 0 {
		a.p.Println("Other Nebula hosts may reach this one with:")
		for _, r := range h.Inbound {
			a.p.Println("  " + r.String())
		}
		keep, err := a.p.Confirm("Keep these firewall rules?", true)
		if err != nil || keep {
			return err
		}
	}
	i, err := a.p.Choose("What may other Nebula hosts reach on this one?", []string{
		"Ping and SSH (recommended)",
		"Ping only",
		"Everything",
	}, 0)
	if err != nil {
		return err
	}
	switch i {
	case 0:
		h.Inbound = []netconf.Rule{netconf.PingRule, netconf.SSHRule}
	case 1:
		h.Inbound = []netconf.Rule{netconf.PingRule}
	default:
		h.Inbound = []netconf.Rule{netconf.AllRule}
		return nil
	}
	extra, err := a.p.AskValid("Other ports to open, e.g. tcp/443, udp/53, tcp/8000-8100 (blank for none)", "",
		func(s string) error { _, err := netconf.ParseRules(s); return err })
	if err != nil {
		return err
	}
	rules, _ := netconf.ParseRules(extra)
	h.Inbound = append(h.Inbound, rules...)
	return nil
}

// apply writes config.yml (after nebula accepts it) and starts nebula.
func (a *app) apply(h *netconf.Host) error {
	cfg := netconf.Render(*h, netconf.Files{
		CACrt: a.caCrt(), HostCrt: a.hostCrt(), HostKey: a.hostKey(), State: a.stateFile(),
	}, a.goos)
	tmp := a.cfgFile() + ".new"
	if err := writeFile(tmp, []byte(cfg), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command(a.nebulaBin(), "-test", "-config", tmp).CombinedOutput(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("nebula rejected the new config, so the old one is kept:\n%s", strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, a.cfgFile()); err != nil {
		return err
	}
	if err := h.Save(a.stateFile()); err != nil {
		return err
	}
	a.p.Printf("\nWrote %s (nebula -test passed).\n", a.cfgFile())
	dns, err := a.setResolver(h)
	if err != nil {
		return err
	}
	return a.startService(dns)
}

func (a *app) startService(dns service.DNS) error {
	if a.root != "" || a.noService {
		a.p.Printf("Start nebula with: sudo %s -config %s\n", a.nebulaBin(), a.cfgFile())
		return nil
	}
	if err := service.Install(a.goos, a.nebulaBin(), a.cfgFile(), dns); err != nil {
		return err
	}
	a.p.Println("nebula is running and starts at boot. Check it with `nebctl status`.")
	return nil
}

func (a *app) firewallHint(port int) {
	a.p.Printf("\nOther hosts must reach UDP %d here from the internet. Open it in your\n", port)
	a.p.Println("cloud provider's firewall if it has one, and on this machine:")
	switch {
	case a.goos == "darwin":
		a.p.Println("  allow nebula if macOS asks about incoming connections")
	case lookPath("ufw"):
		a.p.Printf("  sudo ufw allow %d/udp\n", port)
	case lookPath("firewall-cmd"):
		a.p.Printf("  sudo firewall-cmd --permanent --add-port=%d/udp && sudo firewall-cmd --reload\n", port)
	default:
		a.p.Println("  (no ufw or firewalld found; nothing to do if no host firewall runs)")
	}
}

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
