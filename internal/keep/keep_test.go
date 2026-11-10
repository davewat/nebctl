package keep

import (
	"os"
	"path/filepath"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 2026-11-09: nebctl overwrote config.yml and the nebula binaries with no
// previous copy, so a bad rewrite or update left nothing to go back to.
// Previous must keep the old bytes with the old mode, Swap must exchange
// the two (and be undoable), and a missing file or .prev must be harmless.
func TestPreviousAndSwap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yml")

	if kept, err := Previous(p); err != nil || kept {
		t.Fatalf("missing file: kept=%v err=%v, want nothing kept and no error", kept, err)
	}
	if err := Swap(p); err == nil {
		t.Fatal("Swap with no .prev should fail")
	}

	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if kept, err := Previous(p); err != nil || !kept {
		t.Fatalf("kept=%v err=%v", kept, err)
	}
	if err := os.WriteFile(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(Prev(p))
	if err != nil || st.Mode().Perm() != 0o600 || read(t, Prev(p)) != "old" {
		t.Fatalf("prev: %v %v %q", err, st, read(t, Prev(p)))
	}

	if err := Swap(p); err != nil {
		t.Fatal(err)
	}
	if read(t, p) != "old" || read(t, Prev(p)) != "new" {
		t.Fatalf("after swap: current %q, prev %q", read(t, p), read(t, Prev(p)))
	}
	if err := Swap(p); err != nil { // a second swap undoes the first
		t.Fatal(err)
	}
	if read(t, p) != "new" || read(t, Prev(p)) != "old" {
		t.Fatalf("after second swap: current %q, prev %q", read(t, p), read(t, Prev(p)))
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) > 0 {
		t.Fatalf("scratch files left behind: %v", left)
	}
	if _, err := os.Stat(p + ".swap"); err == nil {
		t.Fatal(".swap left behind")
	}
}

// 2026-11-09: re-applying an unchanged config (or reinstalling the same
// binary) must not overwrite the real previous copy with an identical one.
func TestPreviousUnlessSame(t *testing.T) {
	dir := t.TempDir()
	cur, next := filepath.Join(dir, "config.yml"), filepath.Join(dir, "config.yml.new")
	os.WriteFile(Prev(cur), []byte("real previous"), 0o600)
	os.WriteFile(cur, []byte("same"), 0o600)
	os.WriteFile(next, []byte("same"), 0o600)
	if kept, err := PreviousUnlessSame(cur, next); err != nil || kept {
		t.Fatalf("identical: kept=%v err=%v", kept, err)
	}
	if read(t, Prev(cur)) != "real previous" {
		t.Fatalf("the previous copy was overwritten: %q", read(t, Prev(cur)))
	}
	os.WriteFile(next, []byte("different"), 0o600)
	if kept, err := PreviousUnlessSame(cur, next); err != nil || !kept {
		t.Fatalf("different: kept=%v err=%v", kept, err)
	}
	if read(t, Prev(cur)) != "same" {
		t.Fatalf("prev = %q", read(t, Prev(cur)))
	}
}
