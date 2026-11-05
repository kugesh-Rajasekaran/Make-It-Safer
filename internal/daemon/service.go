package daemon

import (
	"bytes"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/packaging"
)

// ServiceInfo describes the installed background service.
type ServiceInfo struct {
	File      string `json:"file"`
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
}

// serviceValues are the values the service files need.
type serviceValues struct {
	Label  string
	Binary string // this mis binary
	Home   string // MIS_HOME, only when it was set
	Log    string // daemon log file (macOS)
}

const launchLabel = "com.makeitsafer.daemon"

func valuesFor(paths config.Paths) (serviceValues, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return serviceValues{}, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot find the mis binary")
	}
	v := serviceValues{Label: launchLabel, Binary: exe, Log: filepath.Join(paths.Logs, "daemon.log")}
	if os.Getenv(config.EnvHome) != "" {
		v.Home = paths.Home
	}
	for _, s := range []string{v.Binary, v.Home, v.Log} {
		if strings.ContainsAny(s, "\"\\%\n\r") {
			return v, apperr.New(apperr.ServiceInstallFailed, "paths containing \", \\ or % can't be used in service files: "+s)
		}
	}
	return v, nil
}

// renderLaunchAgent returns the macOS LaunchAgent (values are XML-escaped).
func renderLaunchAgent(v serviceValues) (string, error) {
	esc := serviceValues{Label: html.EscapeString(v.Label), Binary: html.EscapeString(v.Binary), Home: html.EscapeString(v.Home), Log: html.EscapeString(v.Log)}
	return render(packaging.LaunchAgent, esc)
}

// renderSystemdUnit returns the Linux systemd user unit.
func renderSystemdUnit(v serviceValues) (string, error) {
	return render(packaging.SystemdUnit, v)
}

func render(tmpl string, v serviceValues) (string, error) {
	t, err := template.New("service").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", apperr.Wrap(apperr.ServiceInstallFailed, err, "invalid service template")
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return "", apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot render the service file")
	}
	return buf.String(), nil
}

// run executes a service-manager command and wraps its output into errors.
func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec // fixed tools (launchctl, systemctl, journalctl) with our own arguments
	if err != nil {
		return string(out), apperr.Wrap(apperr.ServiceInstallFailed, err, name+" "+strings.Join(args, " ")+": "+strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
