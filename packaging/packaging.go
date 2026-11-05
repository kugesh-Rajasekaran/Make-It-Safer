// Package packaging embeds the files that install Make-It-Safer's background
// service: a LaunchAgent on macOS and a systemd user unit on Linux.
package packaging

import _ "embed"

// LaunchAgent is the macOS LaunchAgent template.
//
//go:embed launchd.plist.tmpl
var LaunchAgent string

// SystemdUnit is the Linux systemd user unit template.
//
//go:embed mis.service.tmpl
var SystemdUnit string
