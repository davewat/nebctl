// Package release finds a nebula release on GitHub, downloads the archive
// for this machine, checks it against the release's SHASUM256.txt and
// installs the nebula and nebula-cert binaries.
package release

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// DefaultRepo publishes nebula's official releases. DefinedNet/nebula
// stopped at v1.7.0-pre5 (2023).
const DefaultRepo = "slackhq/nebula"

// Binaries are the files taken from a release archive.
var Binaries = []string{"nebula", "nebula-cert"}

const maxDownload = 300 << 20

type Release struct {
	Tag    string
	Assets map[string]string // asset name -> download URL
}

// Version is the tag without its leading "v".
func (r *Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

// Get fetches a release: the latest one when tag is empty.
func Get(ctx context.Context, c *http.Client, repo, tag string) (*Release, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	if tag != "" {
		url = "https://api.github.com/repos/" + repo + "/releases/tags/" + tag
	}
	body, err := fetch(ctx, c, url, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("looking up the release: %w", err)
	}
	var r struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("reading the release: %w", err)
	}
	rel := &Release{Tag: r.TagName, Assets: map[string]string{}}
	for _, a := range r.Assets {
		rel.Assets[a.Name] = a.URL
	}
	return rel, nil
}

// AssetName is the release archive for goos/goarch. armVersion (5, 6 or 7)
// matters only for linux/arm.
func AssetName(goos, goarch, armVersion string) (string, error) {
	switch goos {
	case "darwin":
		return "nebula-darwin.zip", nil
	case "linux":
		switch goarch {
		case "amd64", "arm64", "386", "riscv64", "ppc64le", "loong64",
			"mips", "mipsle", "mips64", "mips64le":
			return "nebula-linux-" + goarch + ".tar.gz", nil
		case "arm":
			return "nebula-linux-arm-" + armVersion + ".tar.gz", nil
		}
	}
	return "", fmt.Errorf("no nebula release for %s/%s", goos, goarch)
}

// LinuxARMVersion reads the ARM revision from uname: 7, 6, or 5 otherwise.
func LinuxARMVersion() string {
	out, _ := exec.Command("uname", "-m").Output()
	m := strings.TrimSpace(string(out))
	switch {
	case strings.HasPrefix(m, "armv7"), strings.HasPrefix(m, "armv8"):
		return "7"
	case strings.HasPrefix(m, "armv6"):
		return "6"
	}
	return "5"
}

// ParseShasums reads SHASUM256.txt: "<hex>  <name>" per line, where a name
// like "nebula-darwin.zip/nebula" is a file inside an archive.
func ParseShasums(data []byte) map[string]string {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			sums[f[1]] = strings.ToLower(f[0])
		}
	}
	return sums
}

// Download fetches asset from rel, checks it and the binaries inside it
// against SHASUM256.txt, and extracts the binaries into dir. It returns
// binary name -> extracted path.
func Download(ctx context.Context, c *http.Client, rel *Release, asset, dir string) (map[string]string, error) {
	sumsURL, ok := rel.Assets["SHASUM256.txt"]
	if !ok {
		return nil, fmt.Errorf("release %s has no SHASUM256.txt; refusing to install unchecked binaries", rel.Tag)
	}
	assetURL, ok := rel.Assets[asset]
	if !ok {
		return nil, fmt.Errorf("release %s has no %s", rel.Tag, asset)
	}
	sumsData, err := fetch(ctx, c, sumsURL, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("downloading SHASUM256.txt: %w", err)
	}
	sums := ParseShasums(sumsData)
	want, ok := sums[asset]
	if !ok {
		return nil, fmt.Errorf("SHASUM256.txt has no entry for %s", asset)
	}

	archive := filepath.Join(dir, asset)
	got, err := download(ctx, c, assetURL, archive)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", asset, err)
	}
	if got != want {
		return nil, fmt.Errorf("%s checksum mismatch: got %s, want %s", asset, got, want)
	}

	var files map[string]string
	if strings.HasSuffix(asset, ".zip") {
		files, err = extractZip(archive, dir)
	} else {
		files, err = extractTarGz(archive, dir)
	}
	if err != nil {
		return nil, fmt.Errorf("unpacking %s: %w", asset, err)
	}
	for _, name := range Binaries {
		p, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("%s has no %s", asset, name)
		}
		if want, ok := sums[asset+"/"+name]; ok {
			if got, err := fileSHA256(p); err != nil || got != want {
				return nil, fmt.Errorf("%s/%s checksum mismatch", asset, name)
			}
		}
	}
	return files, nil
}

// Install copies the binaries into binDir, each replaced in one rename so a
// running nebula keeps its old file until it restarts.
func Install(files map[string]string, binDir string) error {
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	for _, name := range Binaries {
		dst := filepath.Join(binDir, name)
		tmp := filepath.Join(binDir, "."+name+".new")
		if err := copyFile(files[name], tmp, 0o755); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// InstalledVersion runs `nebula -version`; "" when it is missing.
func InstalledVersion(nebulaBin string) string {
	out, err := exec.Command(nebulaBin, "-version").Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	return strings.TrimSpace(strings.TrimPrefix(s, "Version:"))
}

func fetch(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := get(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func download(ctx context.Context, c *http.Client, url, dst string) (string, error) {
	resp, err := get(ctx, c, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return "", err
	}
	if n > maxDownload {
		return "", fmt.Errorf("larger than %d MB", maxDownload>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), f.Close()
}

func get(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nebctl")
	if strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

func wanted(name string) (string, bool) {
	base := path.Base(name)
	for _, b := range Binaries {
		if base == b {
			return b, true
		}
	}
	return "", false
}

func extractTarGz(archive, dir string) (map[string]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		name, ok := wanted(h.Name)
		if !ok || h.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join(dir, name)
		if err := writeFile(dst, io.LimitReader(tr, maxDownload), 0o755); err != nil {
			return nil, err
		}
		files[name] = dst
	}
}

func extractZip(archive, dir string) (map[string]string, error) {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	files := map[string]string{}
	for _, zf := range zr.File {
		name, ok := wanted(zf.Name)
		if !ok || zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(dir, name)
		err = writeFile(dst, io.LimitReader(rc, maxDownload), 0o755)
		rc.Close()
		if err != nil {
			return nil, err
		}
		files[name] = dst
	}
	return files, nil
}

func writeFile(dst string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeFile(dst, in, mode)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
