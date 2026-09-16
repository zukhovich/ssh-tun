package sysproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

type envValue struct {
	value   string
	present bool
}

type Manager struct {
	logger       *logger.Logger
	httpAddr     string
	socksAddr    string
	enabled      bool
	origSettings map[string]string
	origEnv      map[string]envValue
	run          func(string, ...string) ([]byte, error)
	mu           sync.Mutex
}

func NewManager(log *logger.Logger, httpListenAddr, socksListenAddr string) *Manager {
	normalize := func(address, fallback string) string {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			log.Warnf(i18n.T("Failed to parse address %s: %v; using %s"), address, err, fallback)
			return fallback
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, port)
	}
	m := &Manager{
		logger:       log,
		httpAddr:     normalize(httpListenAddr, "127.0.0.1:8080"),
		origSettings: make(map[string]string),
		origEnv:      make(map[string]envValue),
	}
	if socksListenAddr != "" {
		m.socksAddr = normalize(socksListenAddr, "")
	}
	m.run = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	return m
}

func (m *Manager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enabled {
		return nil
	}
	if err := m.saveCurrentSettings(); err != nil {
		return fmt.Errorf(i18n.T("failed to save system proxy settings: %w"), err)
	}
	if err := m.applySettings(); err != nil {
		return errors.Join(err, m.restoreSettings())
	}
	m.enabled = true
	m.logger.Infof(i18n.T("System proxy configured for HTTP %s"), m.httpAddr)
	return nil
}

func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return nil
	}
	if err := m.restoreSettings(); err != nil {
		return err
	}
	m.enabled = false
	m.logger.Info(i18n.T("System proxy settings restored"))
	return nil
}

func (m *Manager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

var settingKeys = []struct{ key, schema, property string }{
	{"mode", "org.gnome.system.proxy", "mode"},
	{"http_host", "org.gnome.system.proxy.http", "host"},
	{"http_port", "org.gnome.system.proxy.http", "port"},
	{"https_host", "org.gnome.system.proxy.https", "host"},
	{"https_port", "org.gnome.system.proxy.https", "port"},
	{"socks_host", "org.gnome.system.proxy.socks", "host"},
	{"socks_port", "org.gnome.system.proxy.socks", "port"},
	{"ignore_hosts", "org.gnome.system.proxy", "ignore-hosts"},
}

func (m *Manager) saveCurrentSettings() error {
	for _, setting := range settingKeys {
		output, err := m.run("gsettings", "get", setting.schema, setting.property)
		if err != nil {
			return fmt.Errorf(i18n.T("gsettings get %s %s: %s: %w"), setting.schema, setting.property, strings.TrimSpace(string(output)), err)
		}
		m.origSettings[setting.key] = strings.TrimSpace(string(output))
	}
	for _, key := range []string{"http_proxy", "https_proxy", "no_proxy"} {
		value, present := os.LookupEnv(key)
		m.origEnv[key] = envValue{value: value, present: present}
	}
	return nil
}

func (m *Manager) applySettings() error {
	host, port, _ := net.SplitHostPort(m.httpAddr)
	commands := [][]string{
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", port},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", port},
	}
	if m.socksAddr != "" {
		socksHost, socksPort, _ := net.SplitHostPort(m.socksAddr)
		commands = append(commands,
			[]string{"set", "org.gnome.system.proxy.socks", "host", socksHost},
			[]string{"set", "org.gnome.system.proxy.socks", "port", socksPort},
		)
	}
	commands = append(commands,
		[]string{"set", "org.gnome.system.proxy", "ignore-hosts", "[]"},
		[]string{"set", "org.gnome.system.proxy", "mode", "manual"},
	)
	for _, args := range commands {
		if err := m.runCommand(args...); err != nil {
			return err
		}
	}
	if err := os.Setenv("http_proxy", "http://"+m.httpAddr); err != nil {
		return err
	}
	if err := os.Setenv("https_proxy", "http://"+m.httpAddr); err != nil {
		return err
	}
	return os.Setenv("no_proxy", "")
}

func (m *Manager) restoreSettings() error {
	var errs []error
	// Restore the mode last, after all other settings.
	for _, setting := range settingKeys[1:] {
		if value, ok := m.origSettings[setting.key]; ok {
			if err := m.runCommand("set", setting.schema, setting.property, value); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if value, ok := m.origSettings["mode"]; ok {
		if err := m.runCommand("set", "org.gnome.system.proxy", "mode", value); err != nil {
			errs = append(errs, err)
		}
	}
	for key, original := range m.origEnv {
		var err error
		if original.present {
			err = os.Setenv(key, original.value)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) runCommand(args ...string) error {
	output, err := m.run("gsettings", args...)
	if err != nil {
		return fmt.Errorf(i18n.T("gsettings %s: %s: %w"), strings.Join(args, " "), strings.TrimSpace(string(output)), err)
	}
	return nil
}
