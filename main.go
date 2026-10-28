// nebctl installs, updates and configures Nebula (github.com/slackhq/nebula)
// on macOS and Linux: a lighthouse, the nodes that join it, and the CA that
// signs their certificates. Run it with no arguments for a menu.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/prompt"
	"github.com/davewat/nebctl/internal/release"
	"github.com/davewat/nebctl/internal/service"
)

var version = "dev"

const usage = `nebctl - install and set up Nebula on macOS and Linux

Usage: sudo nebctl [flags] [command]

With no command, nebctl shows a menu.

Set up this machine:
  lighthouse                 set up a lighthouse (and a CA, for a new network)
  node                       set up a node that joins a network
  request                    make a key here and a request for the CA host to sign
  config                     rewrite config.yml from nebctl.json and restart nebula
  status                     show what is set up here

Nebula itself:
  install [-version vX.Y.Z] [-force]   install nebula and nebula-cert
  update  [-version vX.Y.Z] [-force]   update them and restart nebula
  service start|stop|restart|status|uninstall

Certificate authority (on the machine holding ca.key):
  ca init                    create a CA
  ca import [-crt F] [-key F]          adopt an existing ca.crt and ca.key
  ca sign [-out F]           sign a cert for another host; prints a bundle with its key
  ca sign-request [-in F] [-out F]     sign a request; prints a bundle without a key
  ca bundle [-crt F] [-key F] [-out F] bundle cert files made earlier
  ca lighthouse              record a lighthouse so bundles carry it
  ca list                    list signed certs

Flags:
`

func main() {
	fs := flag.NewFlagSet("nebctl", flag.ContinueOnError)
	root := fs.String("root", os.Getenv("NEBCTL_ROOT"), "prefix for every path, for testing without root (skips the service)")
	repo := fs.String("repo", release.DefaultRepo, "GitHub repository to install nebula from")
	noService := fs.Bool("no-service", false, "write the config but do not install or start the service")
	showVersion := fs.Bool("version", false, "print nebctl's version")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println("nebctl", version)
		return
	}
	a := &app{
		p:         prompt.New(os.Stdin, os.Stdout),
		root:      *root,
		repo:      *repo,
		goos:      runtime.GOOS,
		noService: *noService,
		http:      &http.Client{Timeout: 10 * time.Minute},
	}
	if a.goos != "linux" && a.goos != "darwin" {
		fmt.Fprintln(os.Stderr, "nebctl runs on macOS and Linux")
		os.Exit(1)
	}
	if err := a.run(fs.Args()); err != nil {
		if errors.Is(err, prompt.ErrClosed) {
			fmt.Fprintln(os.Stderr)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func (a *app) run(args []string) error {
	if len(args) == 0 {
		return a.menu()
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "lighthouse":
		return a.setupLighthouse()
	case "node":
		return a.setupNode()
	case "request":
		if err := a.requireRoot(); err != nil {
			return err
		}
		if err := a.ensureNebula(); err != nil {
			return err
		}
		if err := a.makeRequest(); err != nil {
			return err
		}
		a.p.Println("When the CA host answers, run `sudo nebctl node` and choose \"Paste a bundle\".")
		return nil
	case "config":
		return a.reconfigure()
	case "status":
		return a.status()
	case "install", "update":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		tag := fs.String("version", "", "release tag, e.g. v1.11.2 (default: latest)")
		force := fs.Bool("force", false, "reinstall even if this version is installed")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if err := a.requireRoot(); err != nil {
			return err
		}
		if cmd == "install" {
			_, err := a.install(*tag, *force)
			return err
		}
		return a.update(*tag, *force)
	case "service":
		return a.serviceCmd(rest)
	case "ca":
		return a.caCmd(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (try `nebctl help`)", cmd)
}

func (a *app) caCmd(args []string) error {
	if len(args) == 0 {
		if err := a.requireRoot(); err != nil {
			return err
		}
		return a.caMenu()
	}
	fs := flag.NewFlagSet("ca "+args[0], flag.ContinueOnError)
	crt := fs.String("crt", "", "certificate file")
	key := fs.String("key", "", "private key file")
	in := fs.String("in", "", "read the request from this file instead of pasting it")
	out := fs.String("out", "", "write the bundle to this file instead of printing it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "init":
		return a.caInit()
	case "import":
		return a.caImport(*crt, *key)
	case "sign":
		return a.caSign(*out)
	case "sign-request":
		return a.caSignRequest(*in, *out)
	case "bundle":
		return a.caBundle(*crt, *key, *out)
	case "lighthouse":
		return a.caLighthouse()
	case "list":
		return a.caList()
	}
	return fmt.Errorf("unknown ca command %q", args[0])
}

func (a *app) serviceCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: nebctl service start|stop|restart|status|uninstall")
	}
	if args[0] == "status" {
		a.p.Println(service.Status(a.goos))
		return nil
	}
	if a.root != "" {
		return errors.New("the service is not managed with -root set")
	}
	if err := a.requireRoot(); err != nil {
		return err
	}
	switch args[0] {
	case "start":
		return service.Start(a.goos)
	case "stop":
		return service.Stop(a.goos)
	case "restart":
		return service.Restart(a.goos)
	case "uninstall":
		return service.Uninstall(a.goos)
	}
	return fmt.Errorf("unknown service command %q", args[0])
}

func (a *app) reconfigure() error {
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
	return a.apply(h)
}

func (a *app) menu() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	for {
		a.p.Println()
		a.p.Println("nebctl: " + a.summary())
		i, err := a.p.Choose("What would you like to do?", []string{
			"Set up this machine as a lighthouse",
			"Set up this machine as a node",
			"Certificate authority: create, import, sign certs for other hosts",
			"Install or update nebula",
			"Status",
			"Quit",
		}, a.defaultChoice())
		if err != nil {
			return err
		}
		switch i {
		case 0:
			err = a.setupLighthouse()
		case 1:
			err = a.setupNode()
		case 2:
			err = a.caMenu()
		case 3:
			err = a.update("", false)
		case 4:
			err = a.status()
		default:
			return nil
		}
		if errors.Is(err, prompt.ErrClosed) {
			return err
		}
		if err != nil {
			a.p.Println("error:", err)
		}
	}
}

func (a *app) defaultChoice() int {
	if _, ok, _ := a.loadHost(); ok {
		return 4
	}
	return 0
}

func (a *app) summary() string {
	h, ok, _ := a.loadHost()
	if !ok {
		return "this machine is not set up yet"
	}
	s := fmt.Sprintf("this machine is the %s %s (%s)", h.Role, h.Name, h.NebulaIP)
	if a.haveCA() {
		s += " and holds the CA"
	}
	return s
}

func (a *app) status() error {
	ver := release.InstalledVersion(a.nebulaBin())
	if ver == "" {
		ver = "not installed (run `sudo nebctl install`)"
	} else {
		ver += " in " + a.binDir()
	}
	a.p.Printf("\nnebula       %s\n", ver)

	h, ok, err := a.loadHost()
	if err != nil {
		return err
	}
	if !ok {
		a.p.Println("this host    not set up (run `sudo nebctl`)")
	} else {
		a.p.Printf("this host    %s %s, %s\n", h.Role, h.Name, h.NebulaIP)
		if h.Role == netconf.RoleLighthouse {
			a.p.Printf("listening    UDP %d, relay %t\n", h.ListenPort, h.Relay)
		}
		for i, l := range h.Lighthouses {
			label := ""
			if i == 0 {
				label = "lighthouses"
			}
			a.p.Printf("%-12s %s\n", label, l)
		}
		rules := make([]string, len(h.Inbound))
		for i, r := range h.Inbound {
			rules[i] = r.String()
		}
		a.p.Printf("inbound      %s\n", strings.Join(rules, "; "))
	}
	if c := a.currentCert(); c != nil {
		a.p.Printf("cert         %s, expires %s%s\n", c.Name, c.NotAfter.Format("2006-01-02"), warnSoon(c.NotAfter))
	}
	if exists(a.caCrt()) && exists(a.certBin()) {
		if cas, err := a.tool().Inspect(a.caCrt()); err == nil {
			a.p.Printf("ca           %s, expires %s%s\n", cas[0].Name, cas[0].NotAfter.Format("2006-01-02"), warnSoon(cas[0].NotAfter))
		}
	}
	if a.root == "" {
		a.p.Printf("service      %s\n", service.Status(a.goos))
	}
	if a.haveCA() {
		if n, err := a.loadNetwork(); err == nil {
			a.p.Printf("CA here      %s, %d certs signed (`nebctl ca list`)\n", n.CIDR, len(n.Issued))
		}
	}
	return nil
}

func warnSoon(t time.Time) string {
	switch d := daysLeft(t); {
	case d < 0:
		return "  EXPIRED"
	case d < 30:
		return fmt.Sprintf("  (%d days left: renew it)", d)
	}
	return ""
}
