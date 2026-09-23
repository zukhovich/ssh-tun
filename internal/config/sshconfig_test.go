package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveSSHConfigAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := `Host gateway
  HostName gateway.example.com
  User jump
  Port 2200

Host production
  HostName app.internal
  User deploy
  Port 2222
  IdentityFile ~/.ssh/prod_ed25519
  ProxyJump gateway,bastion@example.net:2201
  UserKnownHostsFile ~/.ssh/known_hosts.prod
  ConnectTimeout 7
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	cfg.SSHConfigFile = path
	if err := ResolveSSHConfig(cfg, "production"); err != nil {
		t.Fatal(err)
	}
	if cfg.SSHServer != "app.internal" || cfg.SSHUser != "deploy" || cfg.SSHPort != "2222" {
		t.Fatalf("unexpected resolved target: %+v", cfg)
	}
	if len(cfg.SSHKeyFiles) != 1 || filepath.Base(cfg.SSHKeyFiles[0]) != "prod_ed25519" {
		t.Fatalf("unexpected identities: %v", cfg.SSHKeyFiles)
	}
	if len(cfg.JumpHosts) != 2 || cfg.JumpHosts[0] != "gateway" || cfg.JumpHosts[1] != "bastion@example.net:2201" {
		t.Fatalf("unexpected proxy jumps: %v", cfg.JumpHosts)
	}
	if cfg.Timeout != 7*time.Second || filepath.Base(cfg.KnownHostsFile) != "known_hosts.prod" {
		t.Fatalf("unexpected timeout/known_hosts: %+v", cfg)
	}
}

func TestResolveSSHConfigExplicitAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("Host server\n  HostName example.com\n  User configured\n  Port 2200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	cfg.SSHConfigFile = path
	if err := ResolveSSHConfig(cfg, "explicit@server:2222"); err != nil {
		t.Fatal(err)
	}
	if cfg.SSHUser != "explicit" || cfg.SSHServer != "example.com" || cfg.SSHPort != "2222" {
		t.Fatalf("explicit address must override SSH config: %+v", cfg)
	}
}

func TestResolveSSHConfigExplicitUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("Host server\n  HostName example.com\n  User configured\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := NewConfig()
	cfg.SSHConfigFile = path
	if err := ResolveSSHConfig(cfg, "explicit@server"); err != nil {
		t.Fatal(err)
	}
	if cfg.SSHUser != "explicit" || cfg.SSHServer != "example.com" {
		t.Fatalf("explicit user must override SSH config: %+v", cfg)
	}
}

func TestSSHConfigAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	content := "Host prod staging *.example.com !blocked\n  User deploy\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	aliases, err := SSHConfigAliases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 2 || aliases[0] != "prod" || aliases[1] != "staging" {
		t.Fatalf("unexpected aliases: %v", aliases)
	}
}
