//go:build !windows

package service

import (
	"strings"
	"testing"
)

func TestRenderServices(t *testing.T) {
	options := Options{Name: "ssh-tun", Description: "ssh-tun SSH proxy", Binary: "/usr/local/bin/ssh-tun", Config: "/etc/ssh-tun/config.yaml", User: "root", Group: "root"}
	unit, path := render("systemd", options)
	if path != "/etc/systemd/system/ssh-tun.service" || !strings.Contains(unit, "ExecStart=/usr/local/bin/ssh-tun --config /etc/ssh-tun/config.yaml") {
		t.Fatalf("unexpected systemd unit: %s, %s", path, unit)
	}
	script, path := render("openrc", options)
	if path != "/etc/init.d/ssh-tun" || !strings.Contains(script, "#!/sbin/openrc-run") {
		t.Fatalf("unexpected OpenRC script: %s, %s", path, script)
	}
}

func TestValidServiceName(t *testing.T) {
	if !validServiceName("ssh-tun@office") || validServiceName("../ssh-tun") {
		t.Fatal("service name validation failed")
	}
	if !validAccountName("ssh-tun") || validAccountName("root:wheel") {
		t.Fatal("service account validation failed")
	}
}

func TestSystemdEscape(t *testing.T) {
	if got := systemdEscape(`/opt/ssh tun/%i`); got != `/opt/ssh\x20tun/%%i` {
		t.Fatalf("systemdEscape() = %q", got)
	}
}
