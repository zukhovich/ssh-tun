//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

func isElevated() bool { return os.Geteuid() == 0 }

func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf(i18n.Text("failed to get executable path: %w", "не удалось получить путь к исполняемому файлу: %w"), err)
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New(i18n.Text("sudo was not found; run ssh-tun as root", "sudo не найден; запустите ssh-tun от имени root"))
	}
	args := append([]string{"sudo", exe}, os.Args[1:]...)
	return syscall.Exec(sudo, args, os.Environ())
}
