package cli

import (
	"os"
	"testing"

	"github.com/zukhovich/ssh-tun/internal/i18n"
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

func TestBootstrapLanguageDefaultsToEnglish(t *testing.T) {
	originalArgs, originalLanguage := os.Args, language
	t.Cleanup(func() {
		os.Args, language = originalArgs, originalLanguage
		_ = i18n.Set("en")
	})

	language = "en"
	os.Args = []string{"ssh-tun"}
	bootstrapLanguage()
	if got := i18n.Language(); got != "en" {
		t.Fatalf("Language() = %q, want en", got)
	}

	os.Args = []string{"ssh-tun", "--lang", "ru"}
	bootstrapLanguage()
	if got := i18n.Language(); got != "ru" {
		t.Fatalf("Language() = %q, want ru", got)
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
