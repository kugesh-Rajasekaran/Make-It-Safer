package feeds

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// PruneDir deletes the files in dir that were last written more than maxAge
// before now, and returns how many it deleted. Cache directories that get
// one file per record would otherwise grow for ever. Subdirectories are left
// alone and a missing dir is not an error.
func PruneDir(dir string, maxAge time.Duration, now time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, apperr.Wrap(apperr.ConfigUnreadable, err, "cannot read "+dir)
	}
	removed := 0
	var errs []error
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed meanwhile
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if now.Sub(info.ModTime()) <= maxAge {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	if len(errs) > 0 {
		return removed, apperr.Wrap(apperr.ConfigWriteFailed, errors.Join(errs...), "cannot clean "+dir)
	}
	return removed, nil
}
