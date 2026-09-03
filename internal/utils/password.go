package utils

import (
	"fmt"
	"syscall"

	"golang.org/x/term"
)

// ReadPasswordFromTerminal reads a password without terminal echo.
func ReadPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)

	passwordByte, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("ошибка чтения пароля: %w", err)
	}

	return string(passwordByte), nil
}

// GetSSHPassword reads the configured password or prompts for one.
func GetSSHPassword(configPassword string, interactive bool, user, server string) (string, error) {
	if configPassword != "" {
		return configPassword, nil
	}
	if !interactive {
		return "", fmt.Errorf("пароль не указан, интерактивная аутентификация отключена")
	}

	prompt := fmt.Sprintf("Введите пароль для %s@%s: ", user, server)
	return ReadPasswordFromTerminal(prompt)
}
