package cli

import (
	"testing"
)

func TestParseSSHTarget(t *testing.T) {
	user, host, err := parseSSHTarget("alice@[2001:db8::1]")
	if err != nil || user != "alice" || host != "[2001:db8::1]" {
		t.Fatalf("parseSSHTarget = %q, %q, %v", user, host, err)
	}
	if _, _, err := parseSSHTarget("alice@@example.com"); err == nil {
		t.Fatal("multiple @ separators must be rejected")
	}
}

func TestLanguageFlagRemoved(t *testing.T) {
	if flag := rootCmd.PersistentFlags().Lookup("lang"); flag != nil {
		t.Fatal("--lang must not exist; gettext locale environment controls translations")
	}
}

func TestAddressWithDefaultPort(t *testing.T) {
	tests := map[string]string{
		"example.com":        "example.com:22",
		"example.com:2222":   "example.com:2222",
		"[2001:db8::1]":      "[2001:db8::1]:22",
		"[2001:db8::1]:2222": "[2001:db8::1]:2222",
	}
	for input, want := range tests {
		got, err := addressWithDefaultPort(input, "22")
		if err != nil || got != want {
			t.Errorf("addressWithDefaultPort(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := addressWithDefaultPort("example.com:70000", "22"); err == nil {
		t.Fatal("invalid explicit port must be rejected")
	}
}
