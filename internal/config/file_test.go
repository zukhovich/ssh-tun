package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	content := `version: 1
language: ru # deprecated compatibility field; must be ignored
ssh:
  target: alice@example.com
  timeout: 15s
proxy:
  http: ":9090"
  system: false
tun:
  nat:
    - "10.0.0.0/24:192.168.0.0/24"
service:
  manager: openrc
  name: tunnel
  user: root
  group: root
  enable: true
  start: true
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, aliases, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSHServer != "alice@example.com" || cfg.Timeout != 15*time.Second || cfg.ListenAddr != ":9090" {
		t.Fatalf("unexpected loaded configuration: %+v", cfg)
	}
	if len(aliases) != 1 || cfg.ServiceManager != "openrc" || cfg.ServiceName != "tunnel" || !cfg.ServiceEnable || !cfg.ServiceStart {
		t.Fatalf("unexpected aliases/service configuration: %v, %+v", aliases, cfg)
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nunknown: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFile(path); err == nil {
		t.Fatal("expected an unknown-field error")
	}
}

func TestLoadFileKeepsServiceDefaultsWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nssh:\n  target: user@example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ServiceEnable || !cfg.ServiceStart {
		t.Fatalf("omitted service booleans must keep defaults: %+v", cfg)
	}
}

func TestLoadFileRejectsMultipleDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n---\nversion: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFile(path); err == nil {
		t.Fatal("expected a multiple-document error")
	}
}

func TestLoadFileReconnectSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	content := "version: 1\nssh:\n  target: user@example.com\n  config_file: ~/.ssh/config\n  auto_reconnect: true\n  reconnect_interval: 7s\n  keepalive_interval: 9s\n  health_check_target: google.com:443\n  health_check_timeout: 3s\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoReconnect || cfg.ReconnectInterval != 7*time.Second || cfg.KeepAliveInterval != 9*time.Second || cfg.HealthCheckTarget != "google.com:443" || cfg.HealthCheckTimeout != 3*time.Second || cfg.SSHConfigFile != "~/.ssh/config" {
		t.Fatalf("unexpected reconnect settings: %+v", cfg)
	}
}
