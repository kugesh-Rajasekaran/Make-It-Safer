package vault

import "golang.org/x/sys/unix"

// Harden stops other processes of the same user from attaching a debugger
// or reading this process's memory through /proc. Core dumps are already
// disabled by memguard.
func Harden() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func totalMemory() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return info.Totalram * uint64(info.Unit)
}
