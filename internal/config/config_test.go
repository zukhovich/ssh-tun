package config

import (
	"testing"
	"time"
)

func TestParseJumpHost(t *testing.T) {
	tests := []struct{ value, user, host, port string }{
		{"host", "", "host", "22"},
		{"user@host:2222", "user", "host", "2222"},
		{"user@[2001:db8::1]:2222", "user", "2001:db8::1", "2222"},
	}
	for _, test := range tests {
		user, host, port, err := parseJumpHost(test.value)
		if err != nil {
			t.Fatalf("parseJumpHost(%q): %v", test.value, err)
		}
		if user != test.user || host != test.host || port != test.port {
			t.Errorf("parseJumpHost(%q) = %q, %q, %q", test.value, user, host, port)
		}
	}
}

func TestParseSubnetAlias(t *testing.T) {
	rule, err := ParseSubnetAlias("10.0.0.123/24:192.168.1.99/24")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Src.String() != "10.0.0.0/24" || rule.Dst.String() != "192.168.1.0/24" {
		t.Fatalf("unexpected rule: %s -> %s", rule.Src, rule.Dst)
	}
	if _, err := ParseSubnetAlias("10.0.0.0/24:192.168.0.0/16"); err == nil {
		t.Fatal("expected a mask mismatch error")
	}
}

func TestSystemProxyIsOptIn(t *testing.T) {
	if NewConfig().SystemProxy {
		t.Fatal("system proxy integration must be disabled by default")
	}
}

func TestValidateTimeoutAndAddresses(t *testing.T) {
	cfg := NewConfig()
	cfg.SSHServer = "example.com:22"
	cfg.SSHUser = "user"
	cfg.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("a zero timeout must be rejected")
	}
	cfg.Timeout = 10 * time.Second
	cfg.ReconnectInterval = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("a zero reconnect interval must be rejected")
	}
	cfg.ReconnectInterval = 5 * time.Second
	cfg.KeepAliveInterval = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("a negative keepalive interval must be rejected")
	}
}

func TestValidatePortAndTUNRoutes(t *testing.T) {
	cfg := NewConfig()
	cfg.SSHServer = "example.com:22"
	cfg.SSHUser = "user"
	cfg.SSHPort = "70000"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an invalid SSH port must be rejected")
	}
	cfg.SSHPort = "22"
	cfg.TunMode = true
	cfg.TunRoute = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("an invalid TUN route must be rejected")
	}
}

func TestValidateAllowsNonInteractiveAgentAuthentication(t *testing.T) {
	cfg := NewConfig()
	cfg.SSHServer = "example.com:22"
	cfg.SSHUser = "user"
	cfg.InteractiveAuth = false
	cfg.SSHPassword = ""
	cfg.SSHKeyFile = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("agent/default-key authentication must be allowed without explicit credentials: %v", err)
	}
}
