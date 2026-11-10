package netconf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Store names the state files under one config directory (normally
// /etc/nebula) and the one lock that guards all of them. Every process that
// changes nebctl.json or network.json (the CLI, the console's `nebctl app`
// commands, a host reached over SSH) takes the same lock, so a load-modify-save
// is never interleaved with another's.
type Store struct{ Dir string }

func (s Store) HostPath() string    { return filepath.Join(s.Dir, "nebctl.json") }
func (s Store) NetworkPath() string { return filepath.Join(s.Dir, "ca", "network.json") }
func (s Store) LockPath() string    { return filepath.Join(s.Dir, ".nebctl.lock") }

// Lock takes the exclusive lock, waiting for whoever holds it. The returned
// function releases it and is safe to call more than once. The lock is an
// flock on a file, so it also serialises two goroutines of one process (each
// Lock opens its own file description) and is dropped by the kernel if the
// holder dies. It is not reentrant: taking it twice in one goroutine waits
// forever.
//
// Hold it only across a load-modify-save. Never hold it while waiting on a
// terminal prompt or the network.
func (s Store) Lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.LockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the state lock: %w", err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("locking %s: %w", s.LockPath(), err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			f.Close()
		})
	}, nil
}
