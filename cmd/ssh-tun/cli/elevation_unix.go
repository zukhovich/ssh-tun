//go:build !windows

package cli

import (
	"errors"
	"os"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

func isElevated() bool { return os.Geteuid() == 0 }

func elevationError() error {
	return errors.New(i18n.T("TUN mode requires root privileges; rerun ssh-tun as root"))
}
