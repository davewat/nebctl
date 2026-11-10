package netconf

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
)

// 2026-11-09: nebctl.json and network.json had no lock, and every nebctl
// command is its own process, so two parallel updates could both read the
// same state and the later save dropped the earlier one. With the state lock
// held across load-modify-save, interleaved updates from separate stores on
// one directory must all land.
func TestStoreInterleavedUpdatesLoseNone(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir+"/ca", 0o700)
	if err := (&Network{CIDR: "10.7.0.0/22"}).Save(Store{Dir: dir}.NetworkPath()); err != nil {
		t.Fatal(err)
	}
	const writers, each = 4, 15
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := Store{Dir: dir} // each writer has its own, as separate processes would
			for i := 0; i < each; i++ {
				unlock, err := s.Lock()
				if err != nil {
					t.Error(err)
					return
				}
				n, err := LoadNetwork(s.NetworkPath())
				if err == nil {
					n.Record(Issued{Name: fmt.Sprintf("w%d-%d", w, i), NebulaIP: "10.7.0.9/22"})
					err = n.Save(s.NetworkPath())
				}
				unlock()
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	n, err := LoadNetwork(Store{Dir: dir}.NetworkPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Issued) != writers*each {
		t.Fatalf("recorded %d of %d updates: the rest were lost", len(n.Issued), writers*each)
	}
}

// 2026-11-09: two parallel signs both took NextFree from the same state and
// issued one overlay IP twice. Allocating under the lock must give N
// concurrent callers N distinct addresses.
func TestStoreConcurrentAllocationsAreDistinct(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir+"/ca", 0o700)
	if err := (&Network{CIDR: "10.7.0.0/22"}).Save(Store{Dir: dir}.NetworkPath()); err != nil {
		t.Fatal(err)
	}
	const n = 40
	got := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := Store{Dir: dir}
			unlock, err := s.Lock()
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			net, err := LoadNetwork(s.NetworkPath())
			if err != nil {
				t.Error(err)
				return
			}
			ip, err := net.NextFree()
			if err != nil {
				t.Error(err)
				return
			}
			got[i] = ip
			net.Record(Issued{Name: fmt.Sprintf("h%d", i), NebulaIP: ip})
			if err := net.Save(s.NetworkPath()); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, ip := range got {
		if ip == "" || seen[ip] {
			t.Fatalf("address %q handed out twice or not at all: %v", ip, got)
		}
		seen[ip] = true
	}
}

// 2026-11-09: releasing twice (a deferred and an early release) must not
// break the lock for the next taker.
func TestLockUnlockTwiceIsHarmless(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	unlock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock()
	again, err := s.Lock() // free again
	if err != nil {
		t.Fatal(err)
	}
	again()
}

// 2026-11-09: a save from a copy loaded before another writer's change would
// drop that change. CheckUnchanged lets the caller refuse first.
func TestHostCheckUnchanged(t *testing.T) {
	path := t.TempDir() + "/nebctl.json"
	if err := (&Host{Name: "a"}).Save(path); err != nil {
		t.Fatal(err)
	}
	h, err := LoadHost(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.CheckUnchanged(path); err != nil {
		t.Fatalf("untouched file: %v", err)
	}
	other, _ := LoadHost(path)
	other.Name = "b"
	other.Save(path)
	if err := h.CheckUnchanged(path); !errors.Is(err, ErrChanged) {
		t.Fatalf("after another save: %v, want ErrChanged", err)
	}
	if err := (&Host{}).CheckUnchanged(path); err != nil { // never loaded: not checked
		t.Fatalf("fresh host: %v", err)
	}
	if err := h.Save(path); err != nil || h.CheckUnchanged(path) != nil {
		t.Fatalf("after its own save the copy is current again: %v", err)
	}
}
