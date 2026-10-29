package main

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/davewat/nebctl/internal/audit"
	"github.com/davewat/nebctl/internal/release"
)

// errAuditFailed makes nebctl exit 1 without another message: the report
// already says what failed.
var errAuditFailed = errors.New("audit found failures")

func (a *app) auditCmd(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	offline := fs.Bool("offline", false, "don't ask GitHub for the latest nebula release")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return a.audit(*asJSON, *offline)
}

func (a *app) audit(asJSON, offline bool) error {
	if a.root == "" && os.Geteuid() != 0 {
		return errors.New("the audit reads sshd's settings, ufw's rules and /etc/shadow: run it with sudo")
	}
	in := audit.Input{
		Sys:       audit.OS{},
		GOOS:      a.goos,
		ConfigDir: a.cfgDir(),
		BinDir:    a.binDir(),
		HostCert:  a.currentCert(),
		Nebula:    release.InstalledVersion(a.nebulaBin()),
		Now:       time.Now(),
	}
	if h, ok, _ := a.loadHost(); ok {
		in.Host = h
	}
	if exists(a.caCrt()) && exists(a.certBin()) {
		if cas, err := a.tool().Inspect(a.caCrt()); err == nil {
			in.CACert = &cas[0]
		}
	}
	if self, err := os.Executable(); err == nil {
		if self, err = filepath.EvalSymlinks(self); err == nil {
			in.Self = self
		}
	}
	if !offline && in.Nebula != "" {
		latest, err := a.latestNebula(15 * time.Second)
		if err != nil {
			in.LatestErr = err.Error()
		} else {
			in.Latest = latest
		}
	}

	findings := audit.Run(in)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Machine  string          `json:"machine"`
			Findings []audit.Finding `json:"findings"`
		}{audit.Header(in), findings}); err != nil {
			return err
		}
	} else {
		audit.Write(os.Stdout, audit.Header(in), findings)
	}
	if audit.Count(findings)[audit.Fail] > 0 {
		return errAuditFailed
	}
	return nil
}
