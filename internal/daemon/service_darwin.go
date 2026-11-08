package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

func agentFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot find your home directory")
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel+".plist"), nil
}

func guiDomain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

// InstallService installs the LaunchAgent and starts it. It then starts at
// every login.
func InstallService(paths config.Paths) (*ServiceInfo, error) {
	v, err := valuesFor(paths)
	if err != nil {
		return nil, err
	}
	content, err := renderLaunchAgent(v)
	if err != nil {
		return nil, err
	}
	file, err := agentFile()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil { //nolint:gosec // ~/Library/LaunchAgents is a standard, non-secret directory
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot create "+filepath.Dir(file))
	}
	if err := os.MkdirAll(paths.Logs, 0o700); err != nil {
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot create "+paths.Logs)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil { //nolint:gosec // launchd needs to read it; it holds no secrets
		return nil, apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot write "+file)
	}
	stopAgent()
	// launchd can still refuse right after a stop ("Input/output error"), so
	// try a few times.
	for attempt := 1; ; attempt++ {
		_, err := run("launchctl", "bootstrap", guiDomain(), file)
		if err == nil {
			break
		}
		if attempt == 3 {
			return nil, err
		}
		time.Sleep(time.Second)
	}
	return ServiceState(paths), nil
}

// stopAgent unloads the running service and waits until launchd has really
// stopped it: bootout returns before that, and starting the new one too
// early fails. Not loaded at all is fine.
func stopAgent() {
	target := guiDomain() + "/" + launchLabel
	_, _ = run("launchctl", "bootout", target)
	for range 50 {
		if _, err := run("launchctl", "print", target); err != nil {
			return // gone
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// UninstallService stops the LaunchAgent and removes it.
func UninstallService(paths config.Paths) error {
	file, err := agentFile()
	if err != nil {
		return err
	}
	stopAgent()
	if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.ServiceInstallFailed, err, "cannot remove "+file)
	}
	return nil
}

// ServiceState reports whether the LaunchAgent is installed and loaded.
func ServiceState(paths config.Paths) *ServiceInfo {
	file, _ := agentFile()
	_, statErr := os.Stat(file)
	_, runErr := run("launchctl", "print", guiDomain()+"/"+launchLabel)
	return &ServiceInfo{File: file, Installed: statErr == nil, Active: runErr == nil}
}

// ServiceLogs returns the last lines of the daemon log.
func ServiceLogs(paths config.Paths, lines int) (string, error) {
	data, err := os.ReadFile(filepath.Join(paths.Logs, "daemon.log"))
	if err != nil {
		return "", apperr.Wrap(apperr.ConfigUnreadable, err, "no daemon log yet")
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return strings.Join(all[max(0, len(all)-lines):], "\n") + "\n", nil
}
