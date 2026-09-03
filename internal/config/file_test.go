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
language: ru
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
	cfg, language, aliases, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if language != "ru" || cfg.SSHServer != "alice@example.com" || cfg.Timeout != 15*time.Second || cfg.ListenAddr != ":9090" {
		t.Fatalf("unexpected loaded configuration: %+v, %q", cfg, language)
	}
	if len(aliases) != 1 || cfg.ServiceManager != "openrc" || cfg.ServiceName != "tunnel" {
		t.Fatalf("unexpected aliases/service configuration: %v, %+v", aliases, cfg)
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nunknown: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadFile(path); err == nil {
		t.Fatal("expected an unknown-field error")
	}
}
