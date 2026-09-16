//go:build windows

package cli

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isElevated() bool { return windows.Token(0).IsElevated() }

func relaunchElevated() error {
	return errors.New("TUN mode requires an elevated Administrator console; sudo is not used on Windows")
}
