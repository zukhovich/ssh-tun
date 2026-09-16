package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTemplateForLinux(t *testing.T) {
	template := Template("linux")
	for _, want := range []string{"identity_file: '~/.ssh/id_ed25519'", "user: root", "group: root", "auto_reconnect: false"} {
		if !strings.Contains(template, want) {
			t.Errorf("linux template missing %q", want)
		}
	}
	if strings.Contains(template, "USERPROFILE") {
		t.Error("linux template must not contain Windows paths")
	}
}

func TestTemplateForWindows(t *testing.T) {
	template := Template("windows")
	for _, want := range []string{"user: SYSTEM", "group: SYSTEM", "identity_file: '${USERPROFILE}", "auto_reconnect: false"} {
		if !strings.Contains(template, want) {
			t.Errorf("windows template missing %q", want)
		}
	}
	if strings.Contains(template, "~/.ssh") {
		t.Error("windows template must not contain Unix paths")
	}
}

func TestTemplateLoadsForEveryPlatform(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		path := filepath.Join(t.TempDir(), "ssh-tun.yaml")
		if err := os.WriteFile(path, []byte(Template(goos)), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := LoadFile(path)
		if err != nil {
			t.Fatalf("LoadFile(%s) failed: %v", goos, err)
		}
		if cfg.SSHPort != "22" || cfg.Timeout != 10*time.Second || !cfg.InteractiveAuth {
			t.Fatalf("unexpected defaults for %s: %+v", goos, cfg)
		}
		if goos == "windows" && !strings.Contains(cfg.SSHKeyFile, "USERPROFILE") {
			t.Fatalf("windows identity path must survive the YAML round-trip: %+v", cfg)
		}
	}
}
