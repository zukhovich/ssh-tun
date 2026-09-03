package cli

import "testing"

func TestParseSSHTarget(t *testing.T) {
	user, host, err := parseSSHTarget("alice@[2001:db8::1]")
	if err != nil || user != "alice" || host != "[2001:db8::1]" {
		t.Fatalf("parseSSHTarget = %q, %q, %v", user, host, err)
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
}
