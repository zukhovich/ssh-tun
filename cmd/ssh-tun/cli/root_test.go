package cli

import (
	"testing"
)

func TestLanguageFlagRemoved(t *testing.T) {
	if flag := rootCmd.PersistentFlags().Lookup("lang"); flag != nil {
		t.Fatal("--lang must not exist; gettext locale environment controls translations")
	}
}

func TestCompletionCommandExists(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"completion", "bash"})
	if err != nil || command == rootCmd || command.Name() != "completion" {
		t.Fatalf("completion command is not registered: %v", err)
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
