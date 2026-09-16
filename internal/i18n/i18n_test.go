package i18n

import "testing"

func clearLocaleEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LANGUAGE", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")
}

func TestDetectLanguagePriorityAndNormalization(t *testing.T) {
	clearLocaleEnv(t)
	t.Setenv("LANGUAGE", "ru_RU.UTF-8:en_US")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	if got := detectLanguage(); got != "ru_RU" {
		t.Fatalf("detectLanguage() = %q, want ru_RU", got)
	}
}

func TestDetectLanguageFallsBackToEnglish(t *testing.T) {
	clearLocaleEnv(t)
	if got := detectLanguage(); got != "en" {
		t.Fatalf("detectLanguage() = %q, want en", got)
	}
}

func TestTFallbackWhenUninitialized(t *testing.T) {
	old := locale
	locale = nil
	t.Cleanup(func() { locale = old })
	if got := T("Hello"); got != "Hello" {
		t.Fatalf("T fallback = %q, want Hello", got)
	}
}
