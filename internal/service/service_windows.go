//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/zukhovich/ssh-tun/internal/i18n"
	"golang.org/x/sys/windows"
)

var validWindowsName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@ -]{0,63}$`)

func isElevated() bool {
	return windows.Token(0).IsElevated()
}

func validServiceName(name string) bool { return validWindowsName.MatchString(name) }
func validAccountName(string) bool      { return true }

func detectManager(requested string) (string, error) {
	if requested == "" || requested == "auto" || requested == "windows" {
		return "windows", nil
	}
	return "", fmt.Errorf(i18n.T("unsupported Windows service manager %q"), requested)
}

func installPlatform(manager string, o Options) (string, error) {
	if _, err := queryService(o.Name); err == nil {
		if !o.Force {
			return "", fmt.Errorf(i18n.T("service %q already exists; use --service-force"), o.Name)
		}
		_, _ = run("sc.exe", "stop", o.Name)
		if _, err := run("sc.exe", "delete", o.Name); err != nil {
			return "", err
		}
	}
	command := quoteWindowsArg(o.Binary) + " --config " + quoteWindowsArg(o.Config)
	startMode := "demand"
	if o.Enable {
		startMode = "auto"
	}
	if _, err := run("sc.exe", "create", o.Name, "binPath=", command, "start=", startMode, "DisplayName=", o.Description); err != nil {
		return "", err
	}
	if _, err := run("sc.exe", "description", o.Name, o.Description); err != nil {
		return "", err
	}
	if _, err := run("sc.exe", "failure", o.Name, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000"); err != nil {
		return "", err
	}
	if o.Start {
		if _, err := run("sc.exe", "start", o.Name); err != nil {
			return "", err
		}
	}
	return manager, nil
}

func removePlatform(manager string, o Options) (string, error) {
	_, _ = run("sc.exe", "stop", o.Name)
	if _, err := run("sc.exe", "delete", o.Name); err != nil {
		return "", err
	}
	return manager, nil
}

func queryService(name string) (string, error) {
	output, err := exec.Command("sc.exe", "query", name).CombinedOutput()
	return string(output), err
}

func run(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(i18n.T("%s %s: %s: %w"), name, strings.Join(args, " "), strings.TrimSpace(string(output)), err)
	}
	return string(output), nil
}
