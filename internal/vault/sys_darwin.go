package vault

import "golang.org/x/sys/unix"

// Harden stops debuggers from attaching to this process. Core dumps are
// already disabled by memguard.
func Harden() error {
	return unix.PtraceDenyAttach()
}

func totalMemory() uint64 {
	n, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return n
}
