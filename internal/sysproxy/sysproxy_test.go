package sysproxy

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/zukhovich/ssh-tun/internal/logger"
)

func TestManagerNormalizesAddresses(t *testing.T) {
	m := NewManager(logger.NewLogger(false), ":8080", ":1080")
	if m.httpAddr != "127.0.0.1:8080" || m.socksAddr != "127.0.0.1:1080" {
		t.Fatalf("incorrect addresses: %s, %s", m.httpAddr, m.socksAddr)
	}
}

func TestMissingGsettingsReturnsClearError(t *testing.T) {
	m := NewManager(logger.NewLogger(false), ":8080", "")
	m.run = func(name string, _ ...string) ([]byte, error) {
		return nil, &exec.Error{Name: name, Err: errors.New("not found")}
	}
	err := m.Enable()
	if err == nil || !strings.Contains(err.Error(), "gsettings") {
		t.Fatalf("expected a gsettings availability error, got %v", err)
	}
	if m.IsEnabled() {
		t.Fatal("manager must not be enabled when gsettings is missing")
	}
}

func TestEnableFailureDoesNotMarkEnabled(t *testing.T) {
	m := NewManager(logger.NewLogger(false), ":8080", "")
	m.run = func(_ string, args ...string) ([]byte, error) {
		if args[0] == "get" {
			return []byte("'none'\n"), nil
		}
		return []byte("error"), errors.New("failure")
	}
	if err := m.Enable(); err == nil {
		t.Fatal("expected an error")
	}
	if m.IsEnabled() {
		t.Fatal("manager must not be enabled after an error")
	}
}
