// Package i18n provides gettext-based localization for ssh-tun itself.
package i18n

import (
	"embed"
	"os"
	"strings"

	"github.com/leonelquinteros/gotext"
)

// locales embeds catalogs synchronized from po/*.po before release builds.
// The English fallback is kept in the repository so bare go builds work.
//
//go:embed all:locales
var locales embed.FS

const domain = "ssh-tun"

var locale = newLocale("en")

func newLocale(language string) *gotext.Locale {
	catalog := gotext.NewLocaleFSWithPath(language, locales, "locales")
	catalog.AddDomain(domain)
	catalog.SetDomain(domain)
	return catalog
}

// Init initializes gettext localization. An empty language selects the locale
// from LANGUAGE, LC_ALL, LC_MESSAGES, and LANG, in that order.
func Init(language string) {
	if language == "" {
		language = detectLanguage()
	}
	locale = newLocale(language)
}

func detectLanguage() string {
	for _, name := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		value := os.Getenv(name)
		if value == "" {
			continue
		}
		if name == "LANGUAGE" {
			value = strings.SplitN(value, ":", 2)[0]
		}
		value = gotext.SimplifiedLocale(value)
		if value == "" || value == "C" || value == "POSIX" {
			continue
		}
		return value
	}
	return "en"
}

// T translates msgid using the active gettext catalog and falls back to msgid.
func T(msgid string) string {
	if locale == nil {
		return msgid
	}
	get := locale.Get
	return get(msgid)
}
