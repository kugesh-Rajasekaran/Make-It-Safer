// Package server embeds the scripts Make-It-Safer installs on, or runs on,
// your servers: the read-only collector and the setup/teardown scripts.
// They are shown to you before anything runs.
package server

import _ "embed"

// Collector is installed as /usr/local/lib/mis/collect and is the only thing
// the "mis" user can run.
//
//go:embed collect.sh
var Collector string

// SetupTemplate creates the read-only "mis" user (see setup.sh.tmpl).
//
//go:embed setup.sh.tmpl
var SetupTemplate string

// Teardown removes everything setup added.
//
//go:embed teardown.sh
var Teardown string
