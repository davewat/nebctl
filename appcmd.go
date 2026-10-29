package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/bundle"
	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
	"github.com/davewat/nebctl/internal/prompt"
	"github.com/davewat/nebctl/internal/release"
	"github.com/davewat/nebctl/internal/service"
)

// The Mac app (macos/) drives nebctl through `nebctl app ...`, which asks
// no questions. state, inspect and check only read, run as the user and
// print JSON; request and node change the machine and run as root.

type certInfo struct {
	Name     string    `json:"name"`
	Networks []string  `json:"networks"`
	Groups   []string  `json:"groups,omitempty"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
}

func infoOf(c pki.Cert) *certInfo {
	return &certInfo{c.Name, c.Networks, c.Groups, c.NotAfter, daysLeft(c.NotAfter)}
}

type appState struct {
	Nebctl    string        `json:"nebctl"`
	Nebula    string        `json:"nebula,omitempty"` // installed version
	Host      *netconf.Host `json:"host,omitempty"`   // nil before setup
	Cert      *certInfo     `json:"cert,omitempty"`
	CA        string        `json:"ca,omitempty"` // the installed CA cert's name
	HaveCA    bool          `json:"have_ca"`
	Pending   bool          `json:"pending_request"` // a request's key waits for its cert
	Service   string        `json:"service"`
	Hostname  string        `json:"hostname"`
	ConfigDir string        `json:"config_dir"`
	Admin     struct {
		Enabled bool   `json:"enabled"`
		Listen  string `json:"listen"`
	} `json:"admin"`
}

type inspected struct {
	Cert        *certInfo            `json:"cert"`
	CA          string               `json:"ca"`
	Lighthouses []netconf.Lighthouse `json:"lighthouses,omitempty"`
	Domain      string               `json:"domain,omitempty"`
	Key         string               `json:"key"` // "included", "waiting" (a request's, made here) or "file"
}

// nodePlan is everything `nebctl node` asks, answered.
type nodePlan struct {
	Cert struct {
		Source string `json:"source"`           // keep, bundle or files
		Bundle string `json:"bundle,omitempty"` // the pasted text
		CA     string `json:"ca,omitempty"`     // paths, for files
		Crt    string `json:"crt,omitempty"`
		Key    string `json:"key,omitempty"`
	} `json:"cert"`
	Lighthouses []netconf.Lighthouse `json:"lighthouses"`
	Firewall    string               `json:"firewall"` // keep, ping-ssh, ping or all
	ExtraPorts  string               `json:"extra_ports,omitempty"`
	Resolve     bool                 `json:"resolve"`
}

func (a *app) appCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nebctl app state|inspect|check|request|node, or a console command (see console.go)")
	}
	if ok, err := a.consoleCmd(args[0], args[1:]); ok {
		return err
	}
	fs := flag.NewFlagSet("app "+args[0], flag.ContinueOnError)
	in := fs.String("in", "", "read the plan (check, node) or bundle (inspect) from this file; - for stdin")
	ca := fs.String("ca", "", "inspect: the CA cert file")
	crt := fs.String("crt", "", "inspect: the host cert file")
	key := fs.String("key", "", "inspect: the host key file")
	name := fs.String("name", "", "request: the cert name to ask for")
	ip := fs.String("ip", "", "request: the Nebula address to ask for (blank lets the CA host choose)")
	fresh := fs.Bool("new", false, "request: make a new key even if one is waiting")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	// No questions: one asked by mistake fails instead of waiting.
	out := io.Writer(os.Stderr)
	if args[0] == "node" {
		out = os.Stdout
	}
	a.p = prompt.New(strings.NewReader(""), out)

	switch args[0] {
	case "state":
		return printJSON(a.appState())
	case "inspect":
		var r inspected
		var err error
		if *in != "" {
			r, err = a.inspectBundle(*in)
		} else {
			r, err = a.inspectFiles(*ca, *crt, *key)
		}
		if err != nil {
			return err
		}
		return printJSON(r)
	case "check":
		p, err := readPlan(*in)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Errors map[string]string `json:"errors"`
		}{a.checkPlan(p)})
	case "request":
		if err := a.requireRoot(); err != nil {
			return err
		}
		if err := netconf.ValidName(*name); err != nil {
			return fmt.Errorf("name: %w", err)
		}
		text, err := a.writeRequest(*name, strings.TrimSpace(*ip), !*fresh)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Request string `json:"request"`
		}{text})
	case "node":
		p, err := readPlan(*in)
		if err != nil {
			return err
		}
		return a.appNode(p)
	}
	return fmt.Errorf("unknown app command %q", args[0])
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readText(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
	return os.ReadFile(path)
}

func readPlan(path string) (nodePlan, error) {
	var p nodePlan
	if path == "" {
		return p, errors.New("give the plan with -in")
	}
	data, err := readText(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("reading the plan: %w", err)
	}
	return p, nil
}

func (a *app) appState() appState {
	s := appState{
		Nebctl:    version,
		Nebula:    release.InstalledVersion(a.nebulaBin()),
		HaveCA:    a.haveCA(),
		Pending:   a.pendingRequest(),
		Hostname:  hostname(),
		ConfigDir: a.cfgDir(),
		Service:   "not managed (test root)",
	}
	if h, ok, _ := a.loadHost(); ok {
		s.Host = h
		if h.Admin != nil {
			s.Admin.Enabled, s.Admin.Listen = true, h.Admin.Listen
		}
	}
	if c := a.currentCert(); c != nil {
		s.Cert = infoOf(*c)
	}
	if exists(a.caCrt()) && exists(a.certBin()) {
		if cas, err := a.tool().Inspect(a.caCrt()); err == nil {
			s.CA = cas[0].Name
		}
	}
	if a.root == "" {
		s.Service = service.Status(a.goos)
	}
	return s
}

func (a *app) needCertTool() error {
	if !exists(a.certBin()) {
		return errors.New("nebula isn't installed yet")
	}
	return nil
}

// inspectBundle reads a bundle without installing it. A bundle answering a
// request carries no key: the one waiting here is checked when it is
// installed (only root can read it).
func (a *app) inspectBundle(path string) (inspected, error) {
	if err := a.needCertTool(); err != nil {
		return inspected{}, err
	}
	text, err := readText(path)
	if err != nil {
		return inspected{}, err
	}
	b, err := bundle.DecodeBundle(string(text))
	if err != nil {
		return inspected{}, err
	}
	var key []byte
	kind := "included"
	if b.HostKey != "" {
		key = []byte(b.HostKey)
	} else if exists(a.pendingKey()) || exists(a.hostKey()) {
		kind = "waiting"
	} else {
		return inspected{}, errNoKey
	}
	ca, c, err := a.checkCert([]byte(b.CACrt), []byte(b.HostCrt), key)
	if err != nil {
		return inspected{}, err
	}
	return inspected{Cert: infoOf(c), CA: ca.Name, Lighthouses: b.Lighthouses, Domain: b.Domain, Key: kind}, nil
}

func (a *app) inspectFiles(caPath, crtPath, keyPath string) (inspected, error) {
	if err := a.needCertTool(); err != nil {
		return inspected{}, err
	}
	var data [3][]byte
	for i, p := range []string{caPath, crtPath, keyPath} {
		if p == "" {
			return inspected{}, errors.New("give -in for a bundle, or -ca, -crt and -key")
		}
		var err error
		if data[i], err = pki.CheckFile(p); err != nil {
			return inspected{}, err
		}
	}
	ca, c, err := a.checkCert(data[0], data[1], data[2])
	if err != nil {
		return inspected{}, err
	}
	return inspected{Cert: infoOf(c), CA: ca.Name, Key: "file"}, nil
}

// checkPlan returns what is wrong with a plan, by field: cert, lighthouses,
// lighthouses.N.nebula_ip, lighthouses.N.endpoints, firewall, extra_ports.
func (a *app) checkPlan(p nodePlan) map[string]string {
	errs := map[string]string{}
	switch p.Cert.Source {
	case "keep":
		if a.currentCert() == nil {
			errs["cert"] = "there is no cert here to keep"
		}
	case "bundle":
		if _, err := bundle.DecodeBundle(p.Cert.Bundle); err != nil {
			errs["cert"] = err.Error()
		}
	case "files":
		for _, f := range []string{p.Cert.CA, p.Cert.Crt, p.Cert.Key} {
			if err := fileExists(f); err != nil {
				errs["cert"] = err.Error()
			}
		}
	default:
		errs["cert"] = fmt.Sprintf("unknown cert source %q", p.Cert.Source)
	}
	if len(p.Lighthouses) == 0 {
		errs["lighthouses"] = "add the lighthouse this host checks in with"
	}
	for i, l := range p.Lighthouses {
		if err := validAddr(l.NebulaIP); err != nil {
			errs[fmt.Sprintf("lighthouses.%d.nebula_ip", i)] = err.Error()
		}
		if len(l.Endpoints) == 0 {
			errs[fmt.Sprintf("lighthouses.%d.endpoints", i)] = "required"
		}
		for _, e := range l.Endpoints {
			if _, err := netconf.ParseEndpoint(e, 4242); err != nil {
				errs[fmt.Sprintf("lighthouses.%d.endpoints", i)] = err.Error()
			}
		}
	}
	switch p.Firewall {
	case "keep":
		if h, ok, _ := a.loadHost(); !ok || len(h.Inbound) == 0 {
			errs["firewall"] = "there are no firewall rules here to keep"
		}
	default:
		if _, err := inbound(p.Firewall, ""); err != nil {
			errs["firewall"] = err.Error()
		} else if _, err := netconf.ParseRules(p.ExtraPorts); err != nil {
			errs["extra_ports"] = err.Error()
		}
	}
	return errs
}

// appNode is `nebctl node` with the answers given up front.
func (a *app) appNode(p nodePlan) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if errs := a.checkPlan(p); len(errs) > 0 {
		var msgs []string
		for f, m := range errs {
			msgs = append(msgs, f+": "+m)
		}
		sort.Strings(msgs)
		return errors.New(strings.Join(msgs, "; "))
	}
	if !exists(a.nebulaBin()) || !exists(a.certBin()) {
		if _, err := a.install("", false); err != nil {
			return err
		}
	}
	h, _, err := a.loadHost()
	if err != nil {
		return err
	}
	var got learned
	switch p.Cert.Source {
	case "bundle":
		got, err = a.installBundle(p.Cert.Bundle)
	case "files":
		var data [3][]byte
		for i, f := range []string{p.Cert.CA, p.Cert.Crt, p.Cert.Key} {
			if data[i], err = pki.CheckFile(f); err != nil {
				return err
			}
		}
		_, err = a.installCert(data[0], data[1], data[2])
	}
	if err != nil {
		return err
	}
	c := a.currentCert()
	if c == nil || len(c.Networks) == 0 {
		return errors.New("no usable cert installed")
	}
	a.becomeNode(h, c, got.domain)

	h.Lighthouses = nil
	for _, l := range p.Lighthouses {
		l.NebulaIP = strings.TrimSpace(l.NebulaIP)
		for i, e := range l.Endpoints {
			l.Endpoints[i], _ = netconf.ParseEndpoint(e, 4242)
		}
		h.Lighthouses = append(h.Lighthouses, l)
	}
	if p.Firewall != "keep" {
		if h.Inbound, err = inbound(p.Firewall, p.ExtraPorts); err != nil {
			return err
		}
	}
	h.Resolve = p.Resolve && h.Domain != "" && len(netconf.DNSServers(*h)) > 0
	if err := a.apply(h); err != nil {
		return err
	}
	a.p.Printf("\nTry it: ping %s\n", h.Lighthouses[0].NebulaIP)
	a.resolveHint(h)
	return nil
}
