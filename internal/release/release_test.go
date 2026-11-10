package release

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssetName(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, arm, want string }{
		{"darwin", "arm64", "", "nebula-darwin.zip"},
		{"darwin", "amd64", "", "nebula-darwin.zip"},
		{"linux", "amd64", "", "nebula-linux-amd64.tar.gz"},
		{"linux", "arm64", "", "nebula-linux-arm64.tar.gz"},
		{"linux", "arm", "7", "nebula-linux-arm-7.tar.gz"},
	} {
		if got, err := AssetName(tc.goos, tc.goarch, tc.arm); err != nil || got != tc.want {
			t.Errorf("AssetName(%s, %s) = %q, %v", tc.goos, tc.goarch, got, err)
		}
	}
	if _, err := AssetName("windows", "amd64", ""); err == nil {
		t.Error("windows accepted")
	}
}

func TestParseShasums(t *testing.T) {
	sums := ParseShasums([]byte("AE23  nebula-darwin.zip\nb2ee  nebula-darwin.zip/nebula\n\njunk\n"))
	if sums["nebula-darwin.zip"] != "ae23" || sums["nebula-darwin.zip/nebula"] != "b2ee" || len(sums) != 2 {
		t.Fatalf("sums = %v", sums)
	}
}

// 2026-11-09: Install replaced nebula and nebula-cert with no previous copy,
// so a bad update could not be put back. It must keep the old binaries as
// <name>.prev (same mode), and leave .prev alone when reinstalling identical
// files.
func TestInstallKeepsPrevious(t *testing.T) {
	bin, src := t.TempDir(), t.TempDir()
	files := map[string]string{}
	write := func(content string) {
		for _, n := range Binaries {
			p := filepath.Join(src, n)
			if err := os.WriteFile(p, []byte(content+n), 0o755); err != nil {
				t.Fatal(err)
			}
			files[n] = p
		}
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	write("v1 ")
	if err := Install(files, bin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bin, "nebula.prev")); err == nil {
		t.Fatal("a first install has nothing to keep")
	}
	write("v2 ")
	if err := Install(files, bin); err != nil {
		t.Fatal(err)
	}
	for _, n := range Binaries {
		if got := read(filepath.Join(bin, n+".prev")); got != "v1 "+n {
			t.Fatalf("%s.prev = %q", n, got)
		}
		if got := read(filepath.Join(bin, n)); got != "v2 "+n {
			t.Fatalf("%s = %q", n, got)
		}
		if st, _ := os.Stat(filepath.Join(bin, n+".prev")); st.Mode().Perm() != 0o755 {
			t.Fatalf("%s.prev mode %v", n, st.Mode())
		}
	}
	if err := Install(files, bin); err != nil { // same again: .prev stays v1
		t.Fatal(err)
	}
	if got := read(filepath.Join(bin, "nebula.prev")); got != "v1 nebula" {
		t.Fatalf("a reinstall of identical files overwrote .prev: %q", got)
	}
}
