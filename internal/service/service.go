// Package service installs and removes Linux service definitions.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Options struct {
	Manager, Name, Description, Binary, Config, User, Group string
	Enable, Start, Force                                    bool
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)

func Detect(requested string) (string, error) {
	if requested != "" && requested != "auto" {
		if requested != "systemd" && requested != "openrc" {
			return "", fmt.Errorf("unsupported service manager %q", requested)
		}
		return requested, nil
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemctl"); err == nil {
			return "systemd", nil
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc", nil
	}
	return "", fmt.Errorf("systemd or OpenRC was not detected")
}

func Install(options Options) (string, error) {
	manager, err := validate(&options)
	if err != nil {
		return "", err
	}
	content, path := render(manager, options)
	if _, err := os.Stat(path); err == nil && !options.Force {
		return "", fmt.Errorf("service file %s already exists; use --force", path)
	}
	mode := os.FileMode(0644)
	if manager == "openrc" {
		mode = 0755
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return "", fmt.Errorf("write service file: %w", err)
	}
	if manager == "systemd" {
		if err := run("systemctl", "daemon-reload"); err != nil {
			return "", err
		}
		if options.Enable {
			if err := run("systemctl", "enable", options.Name); err != nil {
				return "", err
			}
		}
		if options.Start {
			if err := run("systemctl", "start", options.Name); err != nil {
				return "", err
			}
		}
	} else {
		if options.Enable {
			if err := run("rc-update", "add", options.Name, "default"); err != nil {
				return "", err
			}
		}
		if options.Start {
			if err := run("rc-service", options.Name, "start"); err != nil {
				return "", err
			}
		}
	}
	return manager, nil
}

func Remove(options Options) (string, error) {
	manager, err := validate(&options)
	if err != nil {
		return "", err
	}
	_, path := render(manager, options)
	if manager == "systemd" {
		_ = run("systemctl", "stop", options.Name)
		_ = run("systemctl", "disable", options.Name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if err := run("systemctl", "daemon-reload"); err != nil {
			return "", err
		}
	} else {
		_ = run("rc-service", options.Name, "stop")
		_ = run("rc-update", "del", options.Name, "default")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return manager, nil
}

func validate(options *Options) (string, error) {
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("service management requires root privileges")
	}
	if !validName.MatchString(options.Name) {
		return "", fmt.Errorf("invalid service name %q", options.Name)
	}
	manager, err := Detect(options.Manager)
	if err != nil {
		return "", err
	}
	for _, path := range []*string{&options.Binary, &options.Config} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return "", err
		}
		*path = absolute
	}
	if info, err := os.Stat(options.Binary); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return "", fmt.Errorf("binary %q is not an executable regular file", options.Binary)
	}
	if info, err := os.Stat(options.Config); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("configuration %q is not a regular file", options.Config)
	}
	return manager, nil
}

func render(manager string, o Options) (string, string) {
	if manager == "systemd" {
		content := fmt.Sprintf("[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=%s\nGroup=%s\nExecStart=%s --config %s\nRestart=on-failure\nRestartSec=5s\nKillSignal=SIGTERM\nTimeoutStopSec=30s\n\n[Install]\nWantedBy=multi-user.target\n", sanitize(o.Description), o.User, o.Group, systemdEscape(o.Binary), systemdEscape(o.Config))
		return content, filepath.Join("/etc/systemd/system", o.Name+".service")
	}
	content := fmt.Sprintf("#!/sbin/openrc-run\n\nname=%q\ndescription=%q\ncommand=%q\ncommand_args=%q\ncommand_user=%q\nsupervisor=supervise-daemon\n\ndepend() {\n    need net\n}\n", o.Name, o.Description, o.Binary, "--config "+o.Config, o.User+":"+o.Group)
	return content, filepath.Join("/etc/init.d", o.Name)
}

func sanitize(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " ")
}
func systemdEscape(value string) string { return strings.ReplaceAll(value, " ", `\x20`) }
func run(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(output)), err)
	}
	return nil
}
