//go:build windows

package cli

import (
	"errors"

	"golang.org/x/sys/windows"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

func isElevated() bool { return windows.Token(0).IsElevated() }

func elevationError() error {
	return errors.New(i18n.T("TUN mode requires an elevated Administrator console"))
}
