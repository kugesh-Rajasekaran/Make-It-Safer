// Package cli implements the mis command-line interface.
//
// Every command returns *apperr.Error values, prints human-readable text by
// default and the {"ok": …} envelope with --json.
package cli

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/daemon"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// app carries what every command needs: output mode, streams and logging.
type app struct {
	json    bool
	verbose bool
	stdin   *os.File
	in      *bufio.Reader // line reader over stdin for ordinary prompts
	stdout  io.Writer
	stderr  io.Writer
	log     *slog.Logger

	unlocked *vault.Key // set while mis init holds the key, so it isn't asked for again
	// Replaced in tests.
	kdf            func() vault.Params
	installService func(config.Paths) (*daemon.ServiceInfo, error)
}

// Execute runs mis with the process arguments and returns the exit code.
// Locked memory holding secrets is wiped on exit and on Ctrl-C.
func Execute() int {
	memguard.CatchInterrupt()
	defer memguard.Purge()
	return run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	return newApp(args, stdin, stdout, stderr).execute(args)
}

func newApp(args []string, stdin *os.File, stdout, stderr io.Writer) *app {
	return &app{
		json:   slices.Contains(args, "--json"), // known even if flag parsing fails
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		log:    slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),

		kdf:            vault.DefaultParams,
		installService: daemon.InstallService,
	}
}

func (a *app) execute(args []string) int {
	stdout, stderr := a.stdout, a.stderr
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		a.printError(err)
		return 1
	}
	return 0
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mis",
		Short: "Make-It-Safer: know which of your servers are vulnerable, and fix them",
		Long: `Make-It-Safer tracks vulnerabilities on your Ubuntu and Debian servers.
It tells you which servers are affected and opens an SSH session with the
fix command already typed in.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(*cobra.Command, []string) {
			level := slog.LevelWarn
			if a.verbose {
				level = slog.LevelDebug
			}
			a.log = slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: level}))
		},
	}
	root.PersistentFlags().BoolVar(&a.json, "json", a.json, "print results as JSON")
	root.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "log what mis is doing to stderr")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperr.Wrap(apperr.CLIUsage, err, "invalid flag")
	})

	root.AddCommand(a.versionCmd(), a.initCmd(), a.passphraseCmd(), a.serverCmd(),
		a.checkCmd(), a.findingsCmd(), a.showCmd(), a.ackCmd(),
		a.daemonCmd(), a.unlockCmd(), a.autoUnlockCmd(), a.configCmd(), a.lockCmd(), a.statusCmd(), a.serviceCmd(),
		a.fixCmd(), a.pickCmd(), a.notifyCmd(), a.doctorCmd())
	return root
}

// asAppError makes sure every error has a code. Commands return
// *apperr.Error; anything else comes from cobra's argument parsing.
func asAppError(err error) *apperr.Error {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e
	}
	return apperr.Wrap(apperr.CLIUsage, err, "invalid command")
}
