package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// CheckPrivate returns an error when path exists and is accessible by other
// users, or isn't owned by the current user. A missing path is fine.
func CheckPrivate(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return apperr.New(apperr.ConfigNotOwned, fmt.Sprintf("%s belongs to another user; Make-It-Safer only uses files you own", path))
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		want := "600"
		if info.IsDir() {
			want = "700"
		}
		return apperr.New(apperr.ConfigPermissionsTooOpen,
			fmt.Sprintf("%s can be accessed by other users (mode %o); fix it with: chmod %s %q", path, perm, want, path))
	}
	return nil
}

// WriteFileAtomic writes data to path with mode 0600. Readers see either the
// old or the new content, never a partial file.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot write "+path)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot write "+path)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot protect "+path)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot write "+path)
	}
	if err := tmp.Close(); err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot write "+path)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return apperr.Wrap(apperr.ConfigWriteFailed, err, "cannot write "+path)
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // dir is the parent of a path in our own layout; syncing it persists the rename
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Lock takes an exclusive advisory lock on path (created if missing) and
// returns the function that releases it. The CLI and the daemon use it to
// serialise read-modify-write cycles on state files.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path comes from our own Paths layout
	if err != nil {
		return nil, apperr.Wrap(apperr.ConfigLockFailed, err, "cannot open lock "+path)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, apperr.Wrap(apperr.ConfigLockFailed, err, "cannot lock "+path)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
