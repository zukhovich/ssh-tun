package router

import (
	"os"
	"path/filepath"
	"testing"
)

func loadRouter(t *testing.T, content string) *Router {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRouter(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRouterMatch(t *testing.T) {
	r := loadRouter(t, "mode: rule\nrules:\n  - DOMAIN-SUFFIX, example.com, DIRECT\n  - DOMAIN, blocked.example, REJECT\n  - IP-CIDR, 10.0.0.0/8, DIRECT\n")
	tests := []struct {
		host string
		want Action
	}{
		{"API.EXAMPLE.COM.:443", ActionDirect},
		{"notexample.com", ActionProxy},
		{"blocked.example", ActionReject},
		{"10.1.2.3:80", ActionDirect},
	}
	for _, test := range tests {
		if got := r.Match(test.host); got != test.want {
			t.Errorf("Match(%q) = %s, want %s", test.host, got, test.want)
		}
	}
}

func TestRouterRejectsInvalidConfiguration(t *testing.T) {
	for _, content := range []string{
		"mode: invalid\n",
		"rules:\n  - DOMAIN\n",
		"rules:\n  - DOMAIN,example.com,UNKNOWN\n",
		"rules:\n  - IP-CIDR,invalid,DIRECT\n",
	} {
		path := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRouter(path); err == nil {
			t.Errorf("NewRouter() accepted configuration %q", content)
		}
	}
}
