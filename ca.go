package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/bundle"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
)

func (a *app) caMenu() error {
	for {
		i, err := a.p.Choose("\nCertificate authority:", []string{
			"Create a new CA on this machine",
			"Import an existing CA (ca.crt and ca.key)",
			"Sign a cert for another host (you get a bundle to paste there)",
			"Sign a request from another host (its private key stays there)",
			"Make a bundle from cert files you already have",
			"Record a lighthouse (bundles tell new hosts where it is)",
			"List signed certs",
			"Back",
		}, 2)
		if err != nil {
			return err
		}
		switch i {
		case 0:
			err = a.caInit()
		case 1:
			err = a.caImport("", "")
		case 2:
			err = a.caSign("")
		case 3:
			err = a.caSignRequest("", "")
		case 4:
			err = a.caBundle("", "", "")
		case 5:
			err = a.caLighthouse()
		case 6:
			err = a.caList()
		default:
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (a *app) prepareCADir() error {
	if a.haveCA() {
		return fmt.Errorf("a CA already exists in %s", a.caDir())
	}
	if err := os.MkdirAll(a.issuedDir(), 0o700); err != nil {
		return err
	}
	return os.Chmod(a.caDir(), 0o700)
}

func (a *app) caInit() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.ensureNebula(); err != nil {
		return err
	}
	if a.haveCA() {
		return fmt.Errorf("a CA already exists in %s", a.caDir())
	}
	a.p.Println("\nThe CA signs a certificate for every host. Keep it on one trusted machine.")
	name, err := a.p.AskValid("Name for the CA (your organisation or domain)", "Nebula CA", nonEmpty)
	if err != nil {
		return err
	}
	cidr, err := a.p.AskValid("Nebula network; every host gets an address in it", "10.42.0.0/22", validCIDR)
	if err != nil {
		return err
	}
	years, err := a.p.AskValid("Years the CA is valid (host certs expire with it)", "5", positive)
	if err != nil {
		return err
	}
	encrypt, err := a.p.Confirm("Protect ca.key with a passphrase (asked each time you sign)?", false)
	if err != nil {
		return err
	}
	prefix := netip.MustParsePrefix(strings.TrimSpace(cidr)).Masked()
	n, _ := strconv.Atoi(years)

	if err := a.prepareCADir(); err != nil {
		return err
	}
	if err := a.tool().CreateCA(pki.CAOptions{
		Name: name, Duration: time.Duration(n) * 365 * 24 * time.Hour,
		Networks: []string{prefix.String()}, Encrypt: encrypt,
		OutCrt: a.caDirCrt(), OutKey: a.caDirKey(),
	}); err != nil {
		return err
	}
	network := &netconf.Network{CIDR: prefix.String()}
	if err := network.Save(a.networkFile()); err != nil {
		return err
	}
	certs, err := a.tool().Inspect(a.caDirCrt())
	if err != nil {
		return err
	}
	a.p.Printf("\nCreated CA %q for %s, valid until %s.\n", name, prefix, certs[0].NotAfter.Format("2006-01-02"))
	a.p.Printf("Back up %s somewhere offline. Anyone holding it can add hosts to\n", a.caDirKey())
	a.p.Println("your network, and losing it means re-issuing every cert.")
	return nil
}

// caImport adopts an existing ca.crt/ca.key. Certs already signed by it in
// the same directory are recorded, so their addresses are not handed out
// again.
func (a *app) caImport(crtPath, keyPath string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.ensureNebula(); err != nil {
		return err
	}
	if a.haveCA() {
		return fmt.Errorf("a CA already exists in %s", a.caDir())
	}
	var err error
	if crtPath == "" {
		if crtPath, err = a.p.AskValid("Path to ca.crt", "ca.crt", fileExists); err != nil {
			return err
		}
	}
	if keyPath == "" {
		def := filepath.Join(filepath.Dir(crtPath), "ca.key")
		if keyPath, err = a.p.AskValid("Path to ca.key", def, fileExists); err != nil {
			return err
		}
	}
	crtData, err := pki.CheckFile(crtPath)
	if err != nil {
		return err
	}
	keyData, err := pki.CheckFile(keyPath)
	if err != nil {
		return err
	}
	certs, err := a.tool().Inspect(crtPath)
	if err != nil {
		return err
	}
	ca := certs[0]
	if !ca.IsCA {
		return fmt.Errorf("%s is a host cert, not a CA", crtPath)
	}
	if !pki.IsPrivateKey(keyData) {
		return fmt.Errorf("%s is not a private key", keyPath)
	}
	if ok, err := pki.KeyMatches(keyData, ca); err == nil && !ok {
		return fmt.Errorf("%s is not the key for %s", keyPath, crtPath)
	}

	// Certs this CA signed, found beside it.
	var found []netconf.Issued
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(crtPath), "*.crt"))
	for _, m := range matches {
		cs, err := a.tool().Inspect(m)
		if err != nil || cs[0].IsCA || cs[0].Issuer != ca.Fingerprint || len(cs[0].Networks) == 0 {
			continue
		}
		c := cs[0]
		found = append(found, netconf.Issued{Name: c.Name, NebulaIP: c.Networks[0], Groups: c.Groups,
			Fingerprint: c.Fingerprint, NotAfter: c.NotAfter, IssuedAt: c.NotBefore})
	}

	cidr := ""
	if len(ca.Networks) > 0 {
		cidr = netip.MustParsePrefix(ca.Networks[0]).Masked().String()
	} else {
		def := "10.42.0.0/22"
		if len(found) > 0 {
			def = netip.MustParsePrefix(found[0].NebulaIP).Masked().String()
		}
		a.p.Println("This CA does not limit addresses, so tell me which network to hand them out from.")
		if cidr, err = a.p.AskValid("Nebula network", def, validCIDR); err != nil {
			return err
		}
		cidr = netip.MustParsePrefix(strings.TrimSpace(cidr)).Masked().String()
	}

	if err := a.prepareCADir(); err != nil {
		return err
	}
	if err := writeFile(a.caDirCrt(), crtData, 0o644); err != nil {
		return err
	}
	if err := writeFile(a.caDirKey(), keyData, 0o600); err != nil {
		return err
	}
	network := &netconf.Network{CIDR: cidr}
	for _, f := range found {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(crtPath), f.Name+".crt"))
		if err == nil {
			writeFile(filepath.Join(a.issuedDir(), f.Name+".crt"), data, 0o644)
		}
		network.Record(f)
	}
	if err := network.Save(a.networkFile()); err != nil {
		return err
	}
	a.p.Printf("\nImported CA %q (%s), valid until %s.\n", ca.Name, cidr, ca.NotAfter.Format("2006-01-02"))
	if len(found) > 0 {
		a.p.Printf("Recorded %d certs it already signed, so their addresses stay theirs:\n", len(found))
		for _, f := range found {
			a.p.Printf("  %-28s %s\n", f.Name, f.NebulaIP)
		}
	}
	a.p.Printf("The original files in %s are untouched; delete them once you have a backup.\n", filepath.Dir(crtPath))
	return nil
}

// askHostCert asks for a cert's name, address and groups. A name the CA
// signed before keeps its address, so a re-sign renews it.
func (a *app) askHostCert(network *netconf.Network, defName, defIP string) (string, netip.Prefix, []string, error) {
	name, err := a.p.AskValid("Host name for the cert", defName, netconf.ValidName)
	if err != nil {
		return "", netip.Prefix{}, nil, err
	}
	prev, renewing := network.Find(name)
	switch {
	case renewing:
		a.p.Printf("  %s already has %s; signing again renews it.\n", name, prev.NebulaIP)
		defIP = prev.NebulaIP
	case defIP != "":
		if p, err := netconf.ParseHostIP(defIP, network.CIDR); err != nil {
			defIP = ""
		} else if _, used := network.Owner(p.Addr()); used {
			defIP = ""
		}
	}
	if defIP == "" {
		if defIP, err = network.NextFree(); err != nil {
			return "", netip.Prefix{}, nil, err
		}
	}
	var ip netip.Prefix
	_, err = a.p.AskValid("Nebula address", defIP, func(s string) error {
		p, err := netconf.ParseHostIP(s, network.CIDR)
		if err != nil {
			return err
		}
		if owner, used := network.Owner(p.Addr()); used && owner != name {
			return fmt.Errorf("%s belongs to %s", p.Addr(), owner)
		}
		ip = p
		return nil
	})
	if err != nil {
		return "", netip.Prefix{}, nil, err
	}
	groups, err := a.p.Ask("Groups, comma separated (optional; firewall rules can match them)", strings.Join(prev.Groups, ","))
	if err != nil {
		return "", netip.Prefix{}, nil, err
	}
	return name, ip, splitList(groups), nil
}

// issue signs a cert for name into the CA's issued directory and records
// it. With pubPath it signs that public key; otherwise it writes a new
// private key to keyPath.
func (a *app) issue(network *netconf.Network, name string, ip netip.Prefix, groups []string, pubPath, keyPath string) (pki.Cert, string, error) {
	crt := filepath.Join(a.issuedDir(), name+".crt")
	if err := os.MkdirAll(a.issuedDir(), 0o700); err != nil {
		return pki.Cert{}, "", err
	}
	// nebula-cert refuses to overwrite; a re-sign replaces the old files.
	os.Remove(crt)
	if keyPath != "" {
		os.Remove(keyPath)
	}
	if err := a.tool().Sign(pki.SignOptions{
		CACrt: a.caDirCrt(), CAKey: a.caDirKey(), Name: name,
		Networks: []string{ip.String()}, Groups: groups,
		InPub: pubPath, OutCrt: crt, OutKey: keyPath,
	}); err != nil {
		return pki.Cert{}, "", err
	}
	if keyPath != "" {
		os.Chmod(keyPath, 0o600)
	}
	certs, err := a.tool().Inspect(crt)
	if err != nil {
		return pki.Cert{}, "", err
	}
	c := certs[0]
	network.Record(netconf.Issued{Name: name, NebulaIP: ip.String(), Groups: groups,
		Fingerprint: c.Fingerprint, NotAfter: c.NotAfter, IssuedAt: time.Now().UTC().Truncate(time.Second)})
	if err := network.Save(a.networkFile()); err != nil {
		return pki.Cert{}, "", err
	}
	a.p.Printf("Signed %s as %s, valid until %s.\n", name, ip, c.NotAfter.Format("2006-01-02"))
	return c, crt, nil
}

// ensureLighthouses makes sure bundles will say where the lighthouses are.
func (a *app) ensureLighthouses(network *netconf.Network) error {
	if len(network.Lighthouses) > 0 {
		return nil
	}
	a.p.Println("No lighthouse is recorded with this CA yet. Bundles carry the lighthouses'")
	a.p.Println("addresses so a new host can find the network without more typing.")
	ok, err := a.p.Confirm("Record one now?", true)
	if err != nil || !ok {
		return err
	}
	for {
		l, err := a.askLighthouse("")
		if err != nil {
			return err
		}
		network.Lighthouses = netconf.AddLighthouse(network.Lighthouses, l)
		if more, err := a.p.Confirm("Record another lighthouse?", false); err != nil || !more {
			if err == nil {
				err = network.Save(a.networkFile())
			}
			return err
		}
	}
}

func (a *app) askLighthouse(defIP string) (netconf.Lighthouse, error) {
	ip, err := a.p.AskValid("Lighthouse's Nebula address (e.g. 10.42.0.1)", defIP, validAddr)
	if err != nil {
		return netconf.Lighthouse{}, err
	}
	ep, err := a.p.AskValid("Lighthouse's public IP or DNS name (host or host:port, port 4242 if left off)", "",
		func(s string) error { _, err := netconf.ParseEndpoint(s, 4242); return err })
	if err != nil {
		return netconf.Lighthouse{}, err
	}
	ep, _ = netconf.ParseEndpoint(ep, 4242)
	relay, err := a.p.Confirm("Does it relay for hosts that can't connect directly?", true)
	if err != nil {
		return netconf.Lighthouse{}, err
	}
	return netconf.Lighthouse{NebulaIP: strings.TrimSpace(ip), Endpoints: []string{ep}, Relay: relay}, nil
}

func (a *app) caLighthouse() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	if len(network.Lighthouses) > 0 {
		a.p.Println("Recorded lighthouses:")
		for _, l := range network.Lighthouses {
			a.p.Println("  " + l.String())
		}
	}
	l, err := a.askLighthouse("")
	if err != nil {
		return err
	}
	network.Lighthouses = netconf.AddLighthouse(network.Lighthouses, l)
	if err := network.Save(a.networkFile()); err != nil {
		return err
	}
	a.p.Printf("Recorded lighthouse %s. Hosts set up before this need `sudo nebctl node` again to learn it.\n", l)
	return nil
}

// caSign signs a cert and key for another host and prints them as a bundle.
func (a *app) caSign(out string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	if err := a.ensureLighthouses(network); err != nil {
		return err
	}
	a.p.Println("\nSigning a cert for another host. Its private key is made here and goes in the bundle.")
	name, ip, groups, err := a.askHostCert(network, "", "")
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "nebctl-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	key := filepath.Join(tmp, "host.key")
	_, crt, err := a.issue(network, name, ip, groups, "", key)
	if err != nil {
		return err
	}
	b, err := a.bundleFor(network, name, crt, key)
	if err != nil {
		return err
	}
	return a.emitBundle(b, out)
}

func (a *app) bundleFor(network *netconf.Network, name, crtPath, keyPath string) (bundle.Bundle, error) {
	caData, err := os.ReadFile(a.caDirCrt())
	if err != nil {
		return bundle.Bundle{}, err
	}
	crtData, err := os.ReadFile(crtPath)
	if err != nil {
		return bundle.Bundle{}, err
	}
	b := bundle.Bundle{Name: name, CACrt: string(caData), HostCrt: string(crtData), Lighthouses: network.Lighthouses}
	if keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return bundle.Bundle{}, err
		}
		b.HostKey = string(keyData)
	}
	return b, nil
}

func (a *app) emitBundle(b bundle.Bundle, out string) error {
	text, err := bundle.EncodeBundle(b)
	if err != nil {
		return err
	}
	if b.HostKey != "" {
		a.p.Printf("\nThis bundle holds %s's private key. Move it only over something you trust\n", b.Name)
		a.p.Println("(an SSH session, a password manager), and don't leave it in chat or email.")
	} else {
		a.p.Println("\nThis bundle has no private key; it is safe to send by chat or email.")
	}
	if out != "" {
		if err := writeFile(out, []byte(text), 0o600); err != nil {
			return err
		}
		a.p.Printf("Saved the bundle to %s.\n", out)
	} else {
		a.p.Printf("On %s, run `sudo nebctl`, set it up as a node or lighthouse, choose\n", b.Name)
		a.p.Println("\"Paste a bundle\", and paste everything below including the BEGIN and END lines:")
		a.p.Println()
		a.p.Printf("%s\n", text)
	}
	return nil
}

func (a *app) caSignRequest(in, out string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	var text string
	if in != "" {
		data, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		text = string(data)
	} else if text, err = a.p.Paste("Paste the request, from its BEGIN line to its END line:", bundle.End(bundle.KindRequest)); err != nil {
		return err
	}
	req, err := bundle.DecodeRequest(text)
	if err != nil {
		return err
	}
	pub, err := pki.PublicKeyHex([]byte(req.PublicKey))
	if err != nil {
		return fmt.Errorf("the request's public key: %w", err)
	}
	a.p.Printf("Request from %q, public key %s...\n", req.Name, pub[:16])
	if err := a.ensureLighthouses(network); err != nil {
		return err
	}
	name, ip, groups, err := a.askHostCert(network, req.Name, req.NebulaIP)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "nebctl-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	pubPath := filepath.Join(tmp, "host.pub")
	if err := os.WriteFile(pubPath, []byte(req.PublicKey), 0o600); err != nil {
		return err
	}
	_, crt, err := a.issue(network, name, ip, groups, pubPath, "")
	if err != nil {
		return err
	}
	b, err := a.bundleFor(network, name, crt, "")
	if err != nil {
		return err
	}
	return a.emitBundle(b, out)
}

// caBundle packs cert files made earlier (by nebula-cert directly, say)
// into a bundle, and records the cert.
func (a *app) caBundle(crtPath, keyPath, out string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	if crtPath == "" {
		if crtPath, err = a.p.AskValid("Path to the host's .crt", "", fileExists); err != nil {
			return err
		}
	}
	if keyPath == "" {
		def := strings.TrimSuffix(crtPath, ".crt") + ".key"
		if !exists(def) {
			def = ""
		}
		if keyPath, err = a.p.Ask("Path to its .key (blank to leave the key out)", def); err != nil {
			return err
		}
	}
	certs, err := a.tool().Inspect(crtPath)
	if err != nil {
		return err
	}
	cas, err := a.tool().Inspect(a.caDirCrt())
	if err != nil {
		return err
	}
	c := certs[0]
	if c.IsCA || c.Issuer != cas[0].Fingerprint {
		return fmt.Errorf("%s was not signed by this machine's CA", crtPath)
	}
	if keyPath != "" {
		keyData, err := pki.CheckFile(keyPath)
		if err != nil {
			return err
		}
		if ok, err := pki.KeyMatches(keyData, c); err != nil || !ok {
			return fmt.Errorf("%s is not the key for %s", keyPath, crtPath)
		}
	}
	if err := a.ensureLighthouses(network); err != nil {
		return err
	}
	if len(c.Networks) > 0 {
		network.Record(netconf.Issued{Name: c.Name, NebulaIP: c.Networks[0], Groups: c.Groups,
			Fingerprint: c.Fingerprint, NotAfter: c.NotAfter, IssuedAt: c.NotBefore})
		if err := network.Save(a.networkFile()); err != nil {
			return err
		}
	}
	b, err := a.bundleFor(network, c.Name, crtPath, keyPath)
	if err != nil {
		return err
	}
	return a.emitBundle(b, out)
}

func (a *app) caList() error {
	network, err := a.loadNetwork()
	if err != nil {
		return err
	}
	if len(network.Issued) == 0 {
		a.p.Println("No certs signed yet.")
		return nil
	}
	a.p.Printf("Network %s\n\n", network.CIDR)
	a.p.Printf("  %-28s %-18s %-12s %s\n", "NAME", "ADDRESS", "EXPIRES", "GROUPS")
	for _, i := range network.Issued {
		exp := i.NotAfter.Format("2006-01-02")
		if d := daysLeft(i.NotAfter); d < 30 {
			exp += fmt.Sprintf(" (%dd)", d)
		}
		a.p.Printf("  %-28s %-18s %-12s %s\n", i.Name, i.NebulaIP, exp, strings.Join(i.Groups, ","))
	}
	if len(network.Lighthouses) > 0 {
		a.p.Println("\nLighthouses:")
		for _, l := range network.Lighthouses {
			a.p.Println("  " + l.String())
		}
	}
	return nil
}

var errNoKey = errors.New("this bundle has no private key and none is waiting here; choose \"Keep the private key on this machine\" first")
