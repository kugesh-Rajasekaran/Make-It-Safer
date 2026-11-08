//go:build integration

package termlaunch

import (
	"strings"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/fixcmd"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/testenv"
)

// TestRemoteScript runs the prompt in a real SSH terminal: nothing runs
// without Enter, the line can be edited, and Ctrl-C (at the prompt or while
// the command runs) always leaves you in a normal shell.
func TestRemoteScript(t *testing.T) {
	srv := testenv.Start(t, testenv.Images[len(testenv.Images)-1])
	open := func(command string) *testenv.Terminal {
		cmd := &fixcmd.Command{Root: command, Sudo: command}
		tm := srv.AdminTerminal(t, RemoteCommand(RemoteScript([]string{"Make-It-Safer · it"}, cmd)))
		tm.WaitFor(t, "~$ "+command, 30*time.Second) // typed in after the prompt
		time.Sleep(200 * time.Millisecond)
		return tm
	}
	shellWorks := func(tm *testenv.Terminal) {
		t.Helper()
		time.Sleep(300 * time.Millisecond)
		tm.Type("echo SHELL-$((2+2))\r")
		tm.WaitFor(t, "SHELL-4", 15*time.Second)
	}

	t.Run("enter runs it", func(t *testing.T) {
		tm := open("echo RAN-$((1+1))")
		tm.Type("\r")
		tm.WaitFor(t, "RAN-2", 15*time.Second)
		shellWorks(tm)
	})
	t.Run("edited first", func(t *testing.T) {
		tm := open("echo RAN-$((1+1))")
		tm.Type(strings.Repeat("\x7f", 8) + "EDITED\r")
		tm.WaitFor(t, "RAN-EDITED", 15*time.Second)
	})
	t.Run("ctrl-c skips", func(t *testing.T) {
		tm := open("echo RAN-$((1+1))")
		tm.Type("\x03")
		shellWorks(tm)
		if strings.Contains(tm.Output(), "RAN-2") {
			t.Fatalf("Ctrl-C ran the command:\n%s", tm.Output())
		}
	})
	t.Run("ctrl-c stops the command", func(t *testing.T) {
		tm := open("sleep 30; echo AFTER-$((3+3))")
		tm.Type("\r")
		time.Sleep(time.Second)
		tm.Type("\x03")
		shellWorks(tm)
		if strings.Contains(tm.Output(), "AFTER-6") {
			t.Fatalf("Ctrl-C didn't stop the whole command:\n%s", tm.Output())
		}
	})
}
