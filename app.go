package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
	"github.com/davewat/nebctl/internal/prompt"
	"github.com/davewat/nebctl/internal/release"
	"github.com/davewat/nebctl/internal/service"
)

type app struct {
	p         *prompt.Prompter
	root      string // prefix for every path; set for testing or unprivileged runs
	repo      string
	goos      string
	noService bool
	http      *http.Client
	renamed   string                               // the old name a cert just signed for another host replaces
	console   bool                                 // running a console command: never prompt
	caKey     *caKeyInput                          // the CA key handed in for this run, if any
	ufwCmd    func(args ...string) (string, error) // set by tests; nil runs the real ufw
}

func (a *app) path(p string) string {
	if a.root == "" {
		return p
	}
	return filepath.Join(a.root, p)
}

func (a *app) binDir() string    { return a.path("/usr/local/bin") }
func (a *app) nebulaBin() string { return filepath.Join(a.binDir(), "nebula") }
func (a *app) certBin() string   { return filepath.Join(a.binDir(), "nebula-cert") }

func (a *app) cfgDir() string     { return a.path("/etc/nebula") }
func (a *app) cfgFile() string    { return filepath.Join(a.cfgDir(), "config.yml") }
func (a *app) stateFile() string  { return filepath.Join(a.cfgDir(), "nebctl.json") }
func (a *app) caCrt() string      { return filepath.Join(a.cfgDir(), "ca.crt") }
func (a *app) hostCrt() string    { return filepath.Join(a.cfgDir(), "host.crt") }
func (a *app) hostKey() string    { return filepath.Join(a.cfgDir(), "host.key") }
func (a *app) pendingKey() string { return filepath.Join(a.cfgDir(), "pending.key") }
func (a *app) pendingPub() string { return filepath.Join(a.cfgDir(), "pending.pub") }

// The CA lives in its own 0700 directory under the config dir.
func (a *app) caDir() string       { return filepath.Join(a.cfgDir(), "ca") }
func (a *app) caDirCrt() string    { return filepath.Join(a.caDir(), "ca.crt") }
func (a *app) caDirKey() string    { return filepath.Join(a.caDir(), "ca.key") }
func (a *app) networkFile() string { return filepath.Join(a.caDir(), "network.json") }
func (a *app) issuedDir() string   { return filepath.Join(a.caDir(), "issued") }

func (a *app) tool() pki.Tool {
	return pki.Tool{Bin: a.certBin(), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

func (a *app) requireRoot() error {
	if a.root != "" || os.Geteuid() == 0 {
		return nil
	}
	return errors.New("this writes to /etc and /usr/local/bin: run it with sudo")
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// haveCA means this machine is the CA. Its key may be kept offline.
func (a *app) haveCA() bool { return exists(a.caDirCrt()) }

// loadHost returns the saved setup, or ok=false before any setup.
func (a *app) loadHost() (h *netconf.Host, ok bool, err error) {
	h, err = netconf.LoadHost(a.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return &netconf.Host{}, false, nil
	}
	return h, err == nil, err
}

func (a *app) loadNetwork() (*netconf.Network, error) {
	if !a.haveCA() {
		return nil, errors.New("there is no CA on this machine: create one with `nebctl ca init` or import one with `nebctl ca import`")
	}
	n, err := netconf.LoadNetwork(a.networkFile())
	if errors.Is(err, os.ErrNotExist) {
		return &netconf.Network{}, nil
	}
	return n, err
}

// currentCert is this host's installed cert, or nil.
func (a *app) currentCert() *pki.Cert {
	if !exists(a.hostCrt()) || !exists(a.certBin()) {
		return nil
	}
	certs, err := a.tool().Inspect(a.hostCrt())
	if err != nil {
		return nil
	}
	return &certs[0]
}

func (a *app) install(tag string, force bool) (changed bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rel, err := release.Get(ctx, a.http, a.repo, tag)
	if err != nil {
		return false, err
	}
	cur := release.InstalledVersion(a.nebulaBin())
	if cur == rel.Version() && !force {
		a.p.Printf("nebula %s is already installed (the latest from %s).\n", cur, a.repo)
		return false, nil
	}
	armv := ""
	if runtime.GOARCH == "arm" {
		armv = release.LinuxARMVersion()
	}
	asset, err := release.AssetName(a.goos, runtime.GOARCH, armv)
	if err != nil {
		return false, err
	}
	tmp, err := os.MkdirTemp("", "nebctl-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	a.p.Printf("Downloading nebula %s (%s)...\n", rel.Version(), asset)
	files, err := release.Download(ctx, a.http, rel, asset, tmp)
	if err != nil {
		return false, err
	}
	if err := release.Install(files, a.binDir()); err != nil {
		return false, fmt.Errorf("installing into %s: %w", a.binDir(), err)
	}
	if cur == "" {
		a.p.Printf("Installed nebula %s into %s (checksums verified).\n", rel.Version(), a.binDir())
	} else {
		a.p.Printf("Updated nebula %s -> %s in %s (checksums verified).\n", cur, rel.Version(), a.binDir())
	}
	return true, nil
}

func (a *app) update(tag string, force bool) error {
	changed, err := a.install(tag, force)
	if err != nil || !changed {
		return err
	}
	if a.root == "" && !a.noService && service.Installed(a.goos) {
		if err := service.Restart(a.goos); err != nil {
			return err
		}
		a.p.Println("Restarted nebula on the new version.")
	}
	return nil
}

func (a *app) ensureNebula() error {
	if exists(a.nebulaBin()) && exists(a.certBin()) {
		return nil
	}
	ok, err := a.p.Confirm(fmt.Sprintf("Nebula is not installed in %s. Install the latest release now?", a.binDir()), true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("nebula is needed first: run `sudo nebctl install`")
	}
	_, err = a.install("", false)
	return err
}

// writeFile writes data, creating its directory.
func writeFile(p string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return netconf.WriteFileAtomic(p, data, mode)
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "localhost" || h == "" {
		return ""
	}
	return h
}

// publicIPv4 guesses this machine's internet address from its interfaces;
// "" behind NAT.
func publicIPv4() string {
	addrs, _ := net.InterfaceAddrs()
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !isCGNAT(ip) {
			return ip.String()
		}
	}
	return ""
}

func isCGNAT(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func validAddr(s string) error {
	if _, err := netip.ParseAddr(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("%q is not an IP address", s)
	}
	return nil
}

func validCIDR(s string) error {
	if _, err := netip.ParsePrefix(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("%q is not a network like 10.42.0.0/22", s)
	}
	return nil
}

func validPort(s string) error {
	if n, err := strconv.Atoi(s); err != nil || n < 1 || n > 65535 {
		return errors.New("a port from 1 to 65535")
	}
	return nil
}

func positive(s string) error {
	if n, err := strconv.Atoi(s); err != nil || n < 1 {
		return errors.New("a whole number, 1 or more")
	}
	return nil
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("required")
	}
	return nil
}

func fileExists(s string) error {
	if !exists(s) {
		return fmt.Errorf("no file at %s", s)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func daysLeft(t time.Time) int { return int(time.Until(t).Hours() / 24) }
