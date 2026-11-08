package cli

import (
	"fmt"
	"time"
)

// spinnerFrames are drawn one after another while work runs.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// withSpinner runs work while showing a simple activity line with the time
// so far, e.g. "⠹ Checking this Mac and web-1… 12s", then "✓ Done in 47s".
// Without a terminal (scripts, --json) it prints msg once.
func (a *app) withSpinner(msg string, work func() error) error {
	if a.json || !a.interactive() {
		a.say("%s…\n", msg)
		return work()
	}
	start := time.Now()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(120 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			a.say("\r%s %s… %s", cyan(spinnerFrames[i%len(spinnerFrames)]), msg, dim(elapsed(start)))
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	err := work()
	close(stop)
	<-stopped
	a.say("\r\x1b[2K") // clear the activity line
	if err == nil {
		a.say("%s %s\n", green("✓"), dim(fmt.Sprintf("Done in %s", elapsed(start))))
	}
	return err
}

func elapsed(start time.Time) string {
	d := time.Since(start).Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
