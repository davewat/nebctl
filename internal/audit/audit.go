// Package audit reviews the security of the machine nebula runs on. A
// lighthouse's UDP port has to face the internet, so the host around it
// matters as much as nebula's own setup. It only reads: every finding that
// needs work carries the commands that fix it, for a person to run.
package audit

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/davewat/nebctl/internal/netconf"
	"github.com/davewat/nebctl/internal/pki"
)

type Level int

const (
	Pass Level = iota
	Info
	Warn
	Fail
)

func (l Level) String() string { return [...]string{"pass", "info", "WARN", "FAIL"}[l] }

func (l Level) MarshalText() ([]byte, error) { return []byte(strings.ToLower(l.String())), nil }

type Finding struct {
	Section string   `json:"section"`
	Level   Level    `json:"level"`
	Title   string   `json:"title"`
	Detail  string   `json:"detail,omitempty"`
	Fix     []string `json:"fix,omitempty"` // shell lines; a line starting with # is a note
}

// File is what the checks need from a stat. UID is -1 when unknown.
type File struct {
	Mode    fs.FileMode
	UID     int
	ModTime time.Time
}

// System is the machine being audited, so tests can stand in for it.
type System interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (File, error)
	// Run returns the command's stdout; err is set when it can't start or
	// exits non-zero (the output is still returned).
	Run(name string, args ...string) (string, error)
	Has(cmd string) bool
}

// OS is the real machine.
type OS struct{}

func (OS) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

func (OS) Stat(p string) (File, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return File{}, err
	}
	f := File{Mode: fi.Mode(), UID: -1, ModTime: fi.ModTime()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		f.UID = int(st.Uid)
	}
	return f, nil
}

func (OS) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(resolve(name), args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}

func (OS) Has(name string) bool {
	_, err := exec.LookPath(resolve(name))
	return err == nil
}

// resolve finds admin tools (sshd, ufw) that a root PATH without sbin misses.
func resolve(name string) string {
	if _, err := exec.LookPath(name); err == nil {
		return name
	}
	for _, d := range []string{"/usr/sbin", "/sbin"} {
		if p := filepath.Join(d, name); fileExists(p) {
			return p
		}
	}
	return name
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

type Input struct {
	Sys       System
	GOOS      string
	Host      *netconf.Host // nil when nebctl hasn't set this machine up
	ConfigDir string        // /etc/nebula
	BinDir    string        // where nebula and nebula-cert are
	Self      string        // nebctl's own binary
	HostCert  *pki.Cert
	CACert    *pki.Cert
	Nebula    string // installed version, "" when missing
	Latest    string // latest nebula release, "" when not checked
	LatestErr string // why Latest is unknown
	Now       time.Time
}

type auditor struct {
	in      Input
	sys     System
	section string
	out     []Finding

	fw        firewall
	listeners []listener
	ssh       map[string][]string
}

func (a *auditor) add(l Level, title, detail string, fix ...string) {
	a.out = append(a.out, Finding{Section: a.section, Level: l, Title: title, Detail: detail, Fix: fix})
}

// Run audits the machine and returns the findings, section by section.
func Run(in Input) []Finding {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	a := &auditor{in: in, sys: in.Sys}
	a.nebula()
	if in.GOOS != "linux" {
		a.section = "Host"
		a.add(Info, "Host checks cover Linux (Ubuntu and Debian) only",
			"Only nebula's own setup was checked on "+in.GOOS+".")
		return a.out
	}
	a.gather()
	a.firewallChecks()
	a.portChecks()
	a.sshChecks()
	a.updateChecks()
	a.kernelChecks()
	a.accountChecks()
	return a.out
}

func (a *auditor) isLighthouse() bool {
	return a.in.Host != nil && a.in.Host.Role == netconf.RoleLighthouse
}

// Header names the machine: its nebula role and OS.
func Header(in Input) string {
	who := "this machine (not set up by nebctl)"
	if h := in.Host; h != nil {
		who = fmt.Sprintf("%s (%s, %s)", h.Name, h.Role, h.NebulaIP)
	}
	osName := in.GOOS
	if data, err := in.Sys.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				osName = strings.Trim(v, `"`)
			}
		}
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	return fmt.Sprintf("nebctl audit: %s, %s, %s", who, osName, now.UTC().Format("2006-01-02 15:04 UTC"))
}

// Count tallies findings by level.
func Count(fs []Finding) map[Level]int {
	n := map[Level]int{}
	for _, f := range fs {
		n[f.Level]++
	}
	return n
}

// Write prints the report: a pass is one line; anything else gets its
// detail and fix commands beneath it.
func Write(w io.Writer, header string, fs []Finding) {
	fmt.Fprintln(w, header)
	section := ""
	for _, f := range fs {
		if f.Section != section {
			fmt.Fprintf(w, "\n%s\n", f.Section)
			section = f.Section
		}
		fmt.Fprintf(w, "  %-4s  %s\n", f.Level, f.Title)
		for _, l := range wrap(f.Detail, 72) {
			fmt.Fprintf(w, "        %s\n", l)
		}
		for _, c := range f.Fix {
			if strings.HasPrefix(c, "#") {
				fmt.Fprintf(w, "        %s\n", c)
			} else {
				fmt.Fprintf(w, "        $ %s\n", c)
			}
		}
	}
	n := Count(fs)
	fmt.Fprintf(w, "\n%d FAIL, %d WARN, %d info, %d pass\n", n[Fail], n[Warn], n[Info], n[Pass])
	if n[Fail] > 0 {
		fmt.Fprintln(w, "Fix the FAIL lines first. nebctl exits 1 while any remain.")
	}
}

func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
