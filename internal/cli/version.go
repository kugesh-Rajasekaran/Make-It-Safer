package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set at build time: -ldflags "-X …/internal/cli.version=v0.1.0".
var version = "dev"

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the mis version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := versionInfo{Version: version, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
			if bi, ok := debug.ReadBuildInfo(); ok {
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" && len(s.Value) >= 12 {
						info.Commit = s.Value[:12]
					}
				}
			}
			return a.emit(info, func(w io.Writer) {
				_, _ = fmt.Fprintf(w, "mis %s (%s, %s/%s)\n", info.Version, info.Go, info.OS, info.Arch)
			})
		},
	}
}
