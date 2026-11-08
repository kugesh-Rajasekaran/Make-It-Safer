// Command mis is Make-It-Safer. It tracks vulnerabilities on your Ubuntu and
// Debian servers, tells you which servers are affected and helps you fix them.
//
// See docs/design.md for how it works.
package main

import (
	"os"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
