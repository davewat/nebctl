// Package keep keeps the previous copy of a file (path.prev) before nebctl
// overwrites it, and swaps it back when the operator asks. It never restores
// anything by itself.
package keep

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Suffix is appended to a file's name for its previous copy.
const Suffix = ".prev"

// Prev is where path's previous copy lives.
func Prev(path string) string { return path + Suffix }

// Previous copies path to path.prev, atomically and with the same mode and
// (when permitted) owner, replacing an older .prev. A missing path is not an
// error: there is nothing to keep yet.
func Previous(path string) (kept bool, err error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, copyAtomic(path, Prev(path))
}

// PreviousUnlessSame is Previous, except that when path already holds exactly
// what replaces it (newFile), the existing .prev is left alone: copying would
// overwrite the real previous version with an identical one.
func PreviousUnlessSame(path, newFile string) (kept bool, err error) {
	if same(path, newFile) {
		return false, nil
	}
	return Previous(path)
}

func same(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()
	sa, err1 := fa.Stat()
	sb, err2 := fb.Stat()
	if err1 != nil || err2 != nil || sa.Size() != sb.Size() {
		return false
	}
	ba, bb := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		na, ea := io.ReadFull(fa, ba)
		nb, eb := io.ReadFull(fb, bb)
		if na != nb || string(ba[:na]) != string(bb[:nb]) {
			return false
		}
		if ea != nil { // sizes match, so both ended together
			return errors.Is(ea, io.EOF) || errors.Is(ea, io.ErrUnexpectedEOF)
		}
		if eb != nil {
			return false
		}
	}
}

// Swap exchanges path and path.prev: the previous copy becomes current and
// the current one becomes the new .prev, so a second Swap undoes the first.
// It errors, touching nothing, when there is no .prev.
func Swap(path string) error {
	prev := Prev(path)
	if _, err := os.Stat(prev); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("there is no previous copy at %s", prev)
		}
		return err
	}
	if _, err := os.Stat(path); err != nil {
		// Nothing current to keep: just put the previous copy back.
		return os.Rename(prev, path)
	}
	// Keep the current file under a scratch name first, so a failure leaves
	// both copies where they were.
	hold := path + ".swap"
	if err := copyAtomic(path, hold); err != nil {
		os.Remove(hold)
		return err
	}
	if err := os.Rename(prev, path); err != nil {
		os.Remove(hold)
		return err
	}
	return os.Rename(hold, prev)
}

func copyAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		// Only root can give a file away; anyone else keeps their own ownership.
		_ = tmp.Chown(int(sys.Uid), int(sys.Gid))
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
