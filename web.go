package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/davewat/nebctl/internal/remote"
	"github.com/davewat/nebctl/internal/web"
)

// `nebctl web` serves the React console on 127.0.0.1 behind a one-time
// link. Every console action is a `nebctl app ...` command, run here or, for
// another machine, as root there over SSH. See web/CONTRACT.md.

const nebctlRepo = "davewat/nebctl"

type console struct {
	a        *app
	port     int
	mu       sync.Mutex
	tokens   map[string]bool      // one-time link tokens not used yet
	sessions map[string]time.Time // session id -> last use
	targets  map[string]*sshTarget
	nextID   int
	mux      *http.ServeMux
	stop     context.CancelFunc
}

type sshTarget struct {
	conn  *remote.Conn
	opts  remote.Options
	label string
	role  string
	ca    bool
}

func (a *app) webCmd(args []string) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	port := fs.Int("port", 7242, "port on 127.0.0.1 (0 picks a free one)")
	noOpen := fs.Bool("no-open", false, "print the link without opening a browser")
	urlFile := fs.String("url-file", "", "also write the link to this file (for the Mac app)")
	parent := fs.Int("parent-pid", 0, "stop when this process exits (for the Mac app)")
	owner := fs.Int("url-owner", -1, "give the -url-file to this user id (for the Mac app)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := a.requireRoot(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(*port))
	if err != nil && *port != 0 {
		ln, err = net.Listen("tcp", "127.0.0.1:0") // that port is taken
	}
	if err != nil {
		return err
	}
	c := &console{a: a, port: ln.Addr().(*net.TCPAddr).Port, tokens: map[string]bool{},
		sessions: map[string]time.Time{}, targets: map[string]*sshTarget{}}
	c.routes()
	link := c.link()
	if *urlFile != "" {
		if err := os.WriteFile(*urlFile, []byte(link+"\n"), 0o600); err != nil {
			return err
		}
		if *owner >= 0 {
			os.Chown(*urlFile, *owner, -1)
		}
	}
	fmt.Printf("nebctl console: %s\nThe link works once. Press Ctrl+C to stop the console.\n", link)
	if !*noOpen {
		openBrowser(link)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c.stop = stop
	if *parent > 0 {
		go func() {
			for ctx.Err() == nil {
				if syscall.Kill(*parent, 0) == syscall.ESRCH {
					stop()
				}
				time.Sleep(2 * time.Second)
			}
		}()
	}
	srv := &http.Server{Handler: c, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	c.mu.Lock()
	for _, t := range c.targets {
		t.conn.Close()
	}
	c.mu.Unlock()
	if *urlFile != "" {
		os.Remove(*urlFile)
	}
	return nil
}

// openBrowser opens link as the person who ran sudo, not as root.
func openBrowser(link string) {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	args := []string{opener, link}
	if u := os.Getenv("SUDO_USER"); u != "" && os.Geteuid() == 0 {
		args = append([]string{"sudo", "-u", u}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = nil, nil
	cmd.Start()
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// link makes a new one-time link.
func (c *console) link() string {
	t := randomHex(24)
	c.mu.Lock()
	c.tokens[t] = true
	c.mu.Unlock()
	return fmt.Sprintf("http://127.0.0.1:%d/?token=%s", c.port, t)
}

const sessionCookie = "nebctl_session"

func (c *console) hostOK(host string) bool {
	p := strconv.Itoa(c.port)
	return host == "127.0.0.1:"+p || host == "localhost:"+p
}

func (c *console) sessionOK(r *http.Request) bool {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.sessions {
		if subtle.ConstantTimeCompare([]byte(id), []byte(ck.Value)) == 1 {
			c.sessions[id] = time.Now()
			return true
		}
	}
	return false
}

func (c *console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.hostOK(r.Host) {
		http.Error(w, "nebctl's console answers only on 127.0.0.1", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/"):
		h.Set("Cache-Control", "no-store")
		if !c.sessionOK(r) {
			writeErr(w, http.StatusUnauthorized, errors.New("this console link has expired: run `sudo nebctl web` again for a new one"))
			return
		}
		if r.Header.Get("X-Nebctl") != "1" {
			writeErr(w, http.StatusForbidden, errors.New("missing the X-Nebctl header"))
			return
		}
		c.mux.ServeHTTP(w, r)
	case r.URL.Query().Has("token"):
		c.login(w, r)
	default:
		c.static(w, r)
	}
}

func (c *console) login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	t := q.Get("token")
	c.mu.Lock()
	ok := c.tokens[t]
	delete(c.tokens, t)
	c.mu.Unlock()
	dest := "/"
	if q.Get("embedded") == "1" {
		dest = "/?embedded=1"
	}
	if !ok {
		if c.sessionOK(r) {
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>nebctl</title><body style="background:#070B1A;color:#C9D3F2;font:16px system-ui;padding:3rem">`+
			`<p>This console link was already used, or isn't right. Run <code>sudo nebctl web</code> again for a new one.</p>`)
		return
	}
	id := randomHex(32)
	c.mu.Lock()
	c.sessions[id] = time.Now()
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (c *console) static(w http.ResponseWriter, r *http.Request) {
	files := web.Files()
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if st, err := fs.Stat(files, name); err != nil || st.IsDir() {
		name = "index.html" // the app routes the rest
	}
	data, err := fs.ReadFile(files, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// API

type apiError struct {
	status int
	body   map[string]any
}

func (e *apiError) Error() string { return fmt.Sprint(e.body["error"]) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.status, ae.body)
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// body reads a camelCase JSON request into snake_case fields of v.
func body(r *http.Request, v any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("reading the request: %w", err)
	}
	snaked, _ := json.Marshal(rekey(raw, snake, false))
	return json.Unmarshal(snaked, v)
}

func (c *console) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/targets", c.listTargets)
	m.HandleFunc("POST /api/targets", c.addTarget)
	m.HandleFunc("POST /api/targets/install", c.addTarget)
	m.HandleFunc("DELETE /api/targets/{id}", c.dropTarget)
	m.HandleFunc("POST /api/link", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"url": c.link() + "&embedded=0"})
	})
	m.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Stopping the console"})
		go func() { time.Sleep(200 * time.Millisecond); c.stop() }()
	})

	// app runs `nebctl app <args>` on the target, args built from the request.
	app := func(pattern string, args func(r *http.Request) ([]string, error)) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			a, err := args(r)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			out, err := c.run(r.PathValue("t"), a)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			var v any
			dec := json.NewDecoder(bytes.NewReader(out))
			dec.UseNumber()
			if err := dec.Decode(&v); err != nil {
				writeErr(w, http.StatusBadGateway, fmt.Errorf("nebctl answered something that isn't JSON: %.200s", out))
				return
			}
			writeJSON(w, http.StatusOK, rekey(v, camel, false))
		})
	}
	fixed := func(a ...string) func(*http.Request) ([]string, error) {
		return func(*http.Request) ([]string, error) { return a, nil }
	}
	addr := func(r *http.Request) (string, error) {
		v := r.PathValue("addr")
		if _, err := netip.ParseAddr(v); err != nil {
			return "", fmt.Errorf("%q is not a Nebula address", v)
		}
		return v, nil
	}

	app("GET /api/t/{t}/state", fixed("state"))
	app("POST /api/t/{t}/admin/enable", fixed("admin-enable"))
	app("GET /api/t/{t}/connections", fixed("connections"))
	app("GET /api/t/{t}/tunnel/{addr}", func(r *http.Request) ([]string, error) {
		a, err := addr(r)
		return []string{"tunnel", a}, err
	})
	app("POST /api/t/{t}/tunnel/{addr}/close", func(r *http.Request) ([]string, error) {
		var in struct {
			LocalOnly bool `json:"local_only"`
		}
		a, err := addr(r)
		if err == nil {
			err = body(r, &in)
		}
		args := []string{"close-tunnel"}
		if in.LocalOnly {
			args = append(args, "-local-only")
		}
		return append(args, a), err
	})
	app("POST /api/t/{t}/tunnel/{addr}/create", func(r *http.Request) ([]string, error) {
		var in struct {
			Address string `json:"address"`
		}
		a, err := addr(r)
		if err == nil {
			err = body(r, &in)
		}
		args := []string{"create-tunnel"}
		if in.Address != "" {
			args = append(args, "-address", in.Address)
		}
		return append(args, a), err
	})
	app("POST /api/t/{t}/tunnel/{addr}/remote", func(r *http.Request) ([]string, error) {
		var in struct {
			Address string `json:"address"`
		}
		a, err := addr(r)
		if err == nil {
			err = body(r, &in)
		}
		return []string{"change-remote", "-address", in.Address, a}, err
	})
	app("GET /api/t/{t}/lookup/{addr}", func(r *http.Request) ([]string, error) {
		a, err := addr(r)
		return []string{"lookup", a}, err
	})
	app("GET /api/t/{t}/log-level", fixed("log-level"))
	app("POST /api/t/{t}/log-level", func(r *http.Request) ([]string, error) {
		var in struct {
			Level string `json:"level"`
		}
		err := body(r, &in)
		return []string{"log-level", in.Level}, err
	})
	app("POST /api/t/{t}/reload", fixed("reload"))

	app("GET /api/t/{t}/certs", fixed("certs"))
	app("GET /api/t/{t}/certs/next-ip", fixed("next-ip"))
	signArgs := func(cmd string) func(r *http.Request) ([]string, error) {
		return func(r *http.Request) ([]string, error) {
			var in struct {
				Name    string    `json:"name"`
				IP      string    `json:"ip"`
				Groups  *[]string `json:"groups"`
				Request string    `json:"request"`
			}
			if err := body(r, &in); err != nil {
				return nil, err
			}
			args := []string{cmd}
			if in.Name != "" {
				args = append(args, "-name", in.Name)
			}
			if in.IP != "" {
				args = append(args, "-ip", in.IP)
			}
			if in.Groups != nil {
				args = append(args, "-groups", strings.Join(*in.Groups, ","))
			}
			if cmd == "sign-request" {
				args = append(args, "-request", in.Request)
			}
			return args, nil
		}
	}
	app("POST /api/t/{t}/certs", signArgs("sign"))
	app("POST /api/t/{t}/certs/request", signArgs("sign-request"))
	app("POST /api/t/{t}/certs/revoke", func(r *http.Request) ([]string, error) {
		var in struct {
			Fingerprint string `json:"fingerprint"`
		}
		err := body(r, &in)
		return []string{"revoke", "-fingerprint", in.Fingerprint}, err
	})
	app("PUT /api/t/{t}/blocklist", func(r *http.Request) ([]string, error) {
		var in struct {
			Fingerprints []string `json:"fingerprints"`
		}
		err := body(r, &in)
		return []string{"blocklist", "-set", strings.Join(in.Fingerprints, ",")}, err
	})

	app("GET /api/t/{t}/settings", fixed("settings"))
	app("PUT /api/t/{t}/settings", func(r *http.Request) ([]string, error) {
		var in json.RawMessage
		err := body(r, &in)
		return []string{"configure", "-json", string(in)}, err
	})
	app("GET /api/t/{t}/logs", func(r *http.Request) ([]string, error) {
		n := r.URL.Query().Get("lines")
		if n == "" {
			n = "200"
		}
		if _, err := strconv.Atoi(n); err != nil {
			return nil, errors.New("lines: a number")
		}
		return []string{"logs", "-lines", n}, nil
	})
	app("GET /api/t/{t}/siem", fixed("siem"))
	app("PUT /api/t/{t}/siem", func(r *http.Request) ([]string, error) {
		var in json.RawMessage
		err := body(r, &in)
		return []string{"siem", "-json", string(in)}, err
	})
	app("POST /api/t/{t}/siem/test", fixed("siem-test"))
	app("GET /api/t/{t}/health", fixed("health"))
	app("GET /api/t/{t}/audit", fixed("audit"))
	app("POST /api/t/{t}/update", fixed("update"))
	app("POST /api/t/{t}/service/{action}", func(r *http.Request) ([]string, error) {
		switch act := r.PathValue("action"); act {
		case "start", "stop", "restart":
			return []string{"service", act}, nil
		}
		return nil, errors.New("service: start, stop or restart")
	})
	c.mux = m
}

// run runs `nebctl app <args>` on a target.
func (c *console) run(id string, args []string) ([]byte, error) {
	if id == "local" {
		return c.runLocal(args)
	}
	c.mu.Lock()
	t := c.targets[id]
	c.mu.Unlock()
	if t == nil {
		return nil, &apiError{http.StatusNotFound, map[string]any{"error": "that machine isn't connected any more: connect to it again"}}
	}
	return t.conn.App(args)
}

func (c *console) runLocal(args []string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	var global []string
	if c.a.root != "" {
		global = append(global, "-root", c.a.root)
	}
	if c.a.noService {
		global = append(global, "-no-service")
	}
	cmd := exec.Command(exe, append(append(global, "app"), args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimPrefix(strings.TrimSpace(errb.String()), "error: ")
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), errors.New(msg)
	}
	return out.Bytes(), nil
}

// Targets

type targetOut struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Host   string `json:"host,omitempty"`
	User   string `json:"user,omitempty"`
	Role   string `json:"role,omitempty"`
	HaveCA bool   `json:"haveCa"`
}

func (c *console) localTarget() targetOut {
	t := targetOut{ID: "local", Kind: "local", Label: "This machine"}
	if runtime.GOOS == "darwin" {
		t.Label = "This Mac"
	}
	s := c.a.appState()
	t.HaveCA = s.HaveCA
	if s.Host != nil {
		t.Role = s.Host.Role
		t.Label += " (" + shortName(s.Host.Name) + ")"
	}
	return t
}

func shortName(n string) string {
	s, _, _ := strings.Cut(n, ".")
	return s
}

func (c *console) listTargets(w http.ResponseWriter, r *http.Request) {
	list := []targetOut{c.localTarget()}
	c.mu.Lock()
	ids := make([]string, 0, len(c.targets))
	for id := range c.targets {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	sortStrings(ids)
	for _, id := range ids {
		c.mu.Lock()
		t := c.targets[id]
		c.mu.Unlock()
		list = append(list, targetOut{ID: id, Label: t.label, Kind: "ssh", Host: t.opts.Host, User: t.opts.User, Role: t.role, HaveCA: t.ca})
	}
	writeJSON(w, http.StatusOK, list)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (c *console) dropTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c.mu.Lock()
	t := c.targets[id]
	delete(c.targets, id)
	c.mu.Unlock()
	if t != nil {
		t.conn.Close()
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Disconnected"})
}

func (c *console) addTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		remote.Options
		Install bool `json:"install"`
	}
	if err := body(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	in.Host, in.User = strings.TrimSpace(in.Host), strings.TrimSpace(in.User)
	if in.Host == "" || in.User == "" {
		writeErr(w, http.StatusBadRequest, errors.New("give the host and the user to log in as"))
		return
	}
	install := in.Install || strings.HasSuffix(r.URL.Path, "/install")
	conn, err := remote.Dial(in.Options, filepath.Join(c.a.cfgDir(), "admin", "known_hosts"))
	var hk *remote.HostKeyError
	var need *remote.NeedError
	switch {
	case errors.As(err, &hk):
		writeJSON(w, http.StatusConflict, map[string]any{"error": hk.Error(),
			"hostKey": map[string]any{"fingerprint": hk.Fingerprint, "type": hk.Type, "changed": hk.Changed}})
		return
	case errors.As(err, &need):
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": need.Msg, "need": need.Field})
		return
	case err != nil:
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	have, err := conn.FindNebctl()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if state := versionState(have, version); state != "" {
		goos, goarch, err := conn.Platform()
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		if !install {
			body := map[string]any{"error": "nebctl " + version + " isn't on " + in.Host + " yet",
				"nebctl": state, "arch": goos + "/" + goarch, "version": version}
			if have != "" {
				body["remoteVersion"] = have
				body["error"] = in.Host + " has nebctl " + have + ", older than this console's " + version
			}
			writeJSON(w, http.StatusPreconditionRequired, body)
			return
		}
		bin, err := c.nebctlBinary(r.Context(), goos, goarch)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		if err := conn.Install(bin); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
	}
	out, err := conn.App([]string{"state"})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	var st appState
	json.Unmarshal(out, &st)
	t := &sshTarget{conn: conn, opts: in.Options, label: in.Host, ca: st.HaveCA}
	if st.Host != nil {
		t.label, t.role = st.Host.Name, st.Host.Role
	}
	c.mu.Lock()
	c.nextID++
	id := "ssh-" + strconv.Itoa(c.nextID)
	c.targets[id] = t
	c.mu.Unlock()
	ok = true
	writeJSON(w, http.StatusOK, targetOut{ID: id, Label: t.label, Kind: "ssh", Host: in.Host, User: in.User, Role: t.role, HaveCA: t.ca})
}

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// versionState says whether the remote nebctl needs replacing: "missing",
// "old", or "" when it's the same or newer. A development build here wants
// exactly its own build there, since it may answer commands a release doesn't.
func versionState(remoteV, localV string) string {
	if remoteV == "" {
		return "missing"
	}
	if remoteV == localV {
		return ""
	}
	r, l := semverRe.FindStringSubmatch(remoteV), semverRe.FindStringSubmatch(localV)
	if r == nil || l == nil {
		return "old"
	}
	for i := 1; i <= 3; i++ {
		rv, _ := strconv.Atoi(r[i])
		lv, _ := strconv.Atoi(l[i])
		if rv != lv {
			if rv < lv {
				return "old"
			}
			return ""
		}
	}
	if len(localV) > len(l[0]) { // this is a development build of that release
		return "old"
	}
	return ""
}

// nebctlBinary finds this version of nebctl for another platform: this
// binary, a copy beside it (the Mac app carries Linux builds), $NEBCTL_DIST,
// or the GitHub release, checked against its SHA256SUMS.
func (c *console) nebctlBinary(ctx context.Context, goos, goarch string) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		return os.ReadFile(exe)
	}
	name := "nebctl-" + goos + "-" + goarch
	for _, dir := range []string{filepath.Dir(exe), os.Getenv("NEBCTL_DIST")} {
		if dir == "" {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			return data, nil
		}
	}
	if m := semverRe.FindString(version); m == "" || m != version {
		return nil, fmt.Errorf("this nebctl (%s) is a development build: put %s beside it, or set NEBCTL_DIST to a folder holding it (make dist)", version, name)
	}
	base := "https://github.com/" + nebctlRepo + "/releases/download/" + version + "/"
	get := func(u string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.a.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", u, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 100<<20))
	}
	sums, err := get(base + "SHA256SUMS")
	if err != nil {
		return nil, err
	}
	bin, err := get(base + name)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bin)
	for _, l := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == name {
			if f[0] != hex.EncodeToString(sum[:]) {
				return nil, fmt.Errorf("%s doesn't match the release's SHA256SUMS", name)
			}
			return bin, nil
		}
	}
	return nil, fmt.Errorf("%s isn't in the release's SHA256SUMS", name)
}

// Key case: nebctl's JSON is snake_case, the console's camelCase.

func camel(k string) string {
	var b strings.Builder
	up := false
	for _, r := range k {
		if r == '_' {
			up = true
			continue
		}
		if up {
			r, up = unicode.ToUpper(r), false
		}
		b.WriteRune(r)
	}
	return b.String()
}

func snake(k string) string {
	var b strings.Builder
	for i, r := range k {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// rekey renames object keys through f. Metric names are data, not
// fields, so a "metrics" object keeps its keys.
func rekey(v any, f func(string) string, keep bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nk := k
			if !keep {
				nk = f(k)
			}
			out[nk] = rekey(val, f, k == "metrics")
		}
		return out
	case []any:
		for i := range t {
			t[i] = rekey(t[i], f, false)
		}
		return t
	}
	return v
}
