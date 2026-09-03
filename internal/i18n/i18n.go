// Package i18n provides the built-in English and Russian message catalogs.
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type ID string

const (
	AppShort           ID = "app.short"
	AppLong            ID = "app.long"
	FlagConfig         ID = "flag.config"
	FlagLanguage       ID = "flag.language"
	FlagServiceInstall ID = "flag.service.install"
	FlagServiceRemove  ID = "flag.service.remove"
	FlagServiceName    ID = "flag.service.name"
	FlagServiceUser    ID = "flag.service.user"
	FlagServiceGroup   ID = "flag.service.group"
	FlagSSHPort        ID = "flag.ssh.port"
	FlagPassword       ID = "flag.password"
	FlagIdentity       ID = "flag.identity"
	FlagKnownHosts     ID = "flag.known_hosts"
	FlagInsecure       ID = "flag.insecure"
	FlagJump           ID = "flag.jump"
	FlagTimeout        ID = "flag.timeout"
	FlagListen         ID = "flag.listen"
	FlagHTTP           ID = "flag.http"
	FlagSOCKS          ID = "flag.socks"
	FlagSysProxy       ID = "flag.sys_proxy"
	FlagUpstream       ID = "flag.upstream"
	FlagTUN            ID = "flag.tun"
	FlagTUNGlobal      ID = "flag.tun_global"
	FlagTUNIP          ID = "flag.tun_ip"
	FlagTUNRoute       ID = "flag.tun_route"
	FlagTUNNAT         ID = "flag.tun_nat"
	FlagVerbose        ID = "flag.verbose"
	FlagLog            ID = "flag.log"
	FlagRules          ID = "flag.rules"
	Started            ID = "app.started"
	PressExit          ID = "app.press_exit"
	ServiceInstalled   ID = "service.installed"
	ServiceRemoved     ID = "service.removed"
)

var catalogs = map[string]map[ID]string{
	"en": {
		AppShort:   "Lightweight SSH-based HTTP proxy",
		AppLong:    "ssh-tun is a command-line HTTP, SOCKS5, and TUN proxy over SSH.\nIt provides secure access to private networks or uses a remote host as an Internet gateway.",
		FlagConfig: "Path to the YAML configuration file", FlagLanguage: "Interface language: en or ru",
		FlagServiceInstall: "Install a service using auto, systemd, or openrc", FlagServiceRemove: "Remove a service using auto, systemd, or openrc",
		FlagServiceName: "Service name", FlagServiceUser: "Service user", FlagServiceGroup: "Service group",
		FlagSSHPort: "SSH server port", FlagPassword: "SSH password (unsafe; interactive authentication is recommended)",
		FlagIdentity: "Private key file", FlagKnownHosts: "known_hosts file (default: ~/.ssh/known_hosts)",
		FlagInsecure: "Disable SSH host key verification (unsafe)", FlagJump: "Comma-separated SSH jump hosts (user@host:port)",
		FlagTimeout: "Connection timeout", FlagListen: "Local HTTP proxy address (deprecated; use --http)",
		FlagHTTP: "Local HTTP proxy address", FlagSOCKS: "SOCKS5 proxy address (for example :1080)",
		FlagSysProxy: "Configure and restore the GNOME system proxy", FlagUpstream: "Force HTTP requests through an upstream host:port",
		FlagTUN: "Enable TUN mode", FlagTUNGlobal: "Route all traffic through TUN", FlagTUNIP: "TUN device CIDR",
		FlagTUNRoute: "Add a static TUN route (repeatable)", FlagTUNNAT: "NAT mapping in SrcCIDR:DstCIDR format",
		FlagVerbose: "Enable verbose logging", FlagLog: "Log file path", FlagRules: "Routing rules file",
		Started: "Proxy service started", PressExit: "Press Ctrl+C to exit",
		ServiceInstalled: "%s service %q installed", ServiceRemoved: "%s service %q removed",
	},
	"ru": {
		AppShort:   "Лёгкий HTTP-прокси на основе SSH",
		AppLong:    "ssh-tun — инструмент командной строки для HTTP-, SOCKS5- и TUN-прокси через SSH.\nОн обеспечивает безопасный доступ к частным сетям или использует удалённый узел как шлюз в Интернет.",
		FlagConfig: "Путь к файлу конфигурации YAML", FlagLanguage: "Язык интерфейса: en или ru",
		FlagServiceInstall: "Установить службу через auto, systemd или openrc", FlagServiceRemove: "Удалить службу через auto, systemd или openrc",
		FlagServiceName: "Имя службы", FlagServiceUser: "Пользователь службы", FlagServiceGroup: "Группа службы",
		FlagSSHPort: "Порт SSH-сервера", FlagPassword: "Пароль SSH (небезопасно; рекомендуется интерактивная аутентификация)",
		FlagIdentity: "Файл закрытого ключа", FlagKnownHosts: "Файл known_hosts (по умолчанию ~/.ssh/known_hosts)",
		FlagInsecure: "Отключить проверку ключа SSH-сервера (небезопасно)", FlagJump: "Промежуточные SSH-узлы через запятую (user@host:port)",
		FlagTimeout: "Таймаут подключения", FlagListen: "Локальный адрес HTTP-прокси (устарело; используйте --http)",
		FlagHTTP: "Локальный адрес HTTP-прокси", FlagSOCKS: "Адрес SOCKS5-прокси (например :1080)",
		FlagSysProxy: "Настроить и восстановить системный прокси GNOME", FlagUpstream: "Направить HTTP-запросы на вышестоящий host:port",
		FlagTUN: "Включить TUN-режим", FlagTUNGlobal: "Направить весь трафик через TUN", FlagTUNIP: "CIDR TUN-устройства",
		FlagTUNRoute: "Добавить статический маршрут TUN (можно повторять)", FlagTUNNAT: "NAT-отображение в формате SrcCIDR:DstCIDR",
		FlagVerbose: "Включить подробное журналирование", FlagLog: "Путь к файлу журнала", FlagRules: "Файл правил маршрутизации",
		Started: "Прокси-сервис запущен", PressExit: "Нажмите Ctrl+C для выхода",
		ServiceInstalled: "Служба %s %q установлена", ServiceRemoved: "Служба %s %q удалена",
	},
}

var current = "en"
var mu sync.RWMutex

func Detect() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if strings.HasPrefix(strings.ToLower(os.Getenv(key)), "ru") {
			return "ru"
		}
	}
	return "en"
}

func Set(language string) error {
	language = strings.ToLower(strings.TrimSpace(language))
	if _, ok := catalogs[language]; !ok {
		return fmt.Errorf("unsupported language %q (supported: en, ru)", language)
	}
	mu.Lock()
	current = language
	mu.Unlock()
	return nil
}

func Language() string { mu.RLock(); defer mu.RUnlock(); return current }

func T(id ID, args ...any) string {
	mu.RLock()
	language := current
	mu.RUnlock()
	message := catalogs[language][id]
	if message == "" {
		message = catalogs["en"][id]
	}
	return fmt.Sprintf(message, args...)
}

// Text selects an English or Russian message using the active language.
func Text(english, russian string, args ...any) string {
	if Language() == "ru" {
		return fmt.Sprintf(russian, args...)
	}
	return fmt.Sprintf(english, args...)
}
