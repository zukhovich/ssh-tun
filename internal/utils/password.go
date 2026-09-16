package utils

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/term"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

// ReadPasswordFromTerminal reads a password without terminal echo.
func ReadPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)

	passwordByte, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf(i18n.T("failed to read the password: %w"), err)
	}

	return string(passwordByte), nil
}

// GetSSHPassword reads the configured password or prompts for one.
func GetSSHPassword(configPassword string, interactive bool, user, server string) (string, error) {
	if configPassword != "" {
		return configPassword, nil
	}
	if !interactive {
		return "", errors.New(i18n.T("no password was configured and interactive authentication is disabled"))
	}

	prompt := fmt.Sprintf(i18n.T("Enter password for %s@%s: "), user, server)
	return ReadPasswordFromTerminal(prompt)
}
