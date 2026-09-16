// Package service installs and removes native operating-system services.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

type Options struct {
	Manager, Name, Description, Binary, Config, User, Group string
	Enable, Start, Force                                    bool
}

func Detect(requested string) (string, error) { return detectManager(requested) }

func Install(options Options) (string, error) {
	manager, err := validate(&options)
	if err != nil {
		return "", err
	}
	return installPlatform(manager, options)
}

func Remove(options Options) (string, error) {
	manager, err := validate(&options)
	if err != nil {
		return "", err
	}
	return removePlatform(manager, options)
}

func validate(options *Options) (string, error) {
	if !isElevated() {
		if runtime.GOOS == "windows" {
			return "", errors.New(i18n.T("service management requires an elevated Administrator console"))
		}
		return "", errors.New(i18n.T("service management requires root privileges"))
	}
	if !validServiceName(options.Name) {
		return "", fmt.Errorf(i18n.T("invalid service name %q"), options.Name)
	}
	if runtime.GOOS != "windows" {
		if !validAccountName(options.User) {
			return "", fmt.Errorf(i18n.T("invalid service user %q"), options.User)
		}
		if !validAccountName(options.Group) {
			return "", fmt.Errorf(i18n.T("invalid service group %q"), options.Group)
		}
	}
	manager, err := Detect(options.Manager)
	if err != nil {
		return "", err
	}
	for _, path := range []*string{&options.Binary, &options.Config} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return "", err
		}
		*path = absolute
	}
	if info, err := os.Stat(options.Binary); err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode()&0111 == 0) {
		return "", fmt.Errorf(i18n.T("binary %q is not an executable regular file"), options.Binary)
	}
	if info, err := os.Stat(options.Config); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf(i18n.T("configuration %q is not a regular file"), options.Config)
	}
	return manager, nil
}

func quoteWindowsArg(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
