package i18n

import "testing"

func TestCatalogs(t *testing.T) {
	defer Set("en")
	if err := Set("ru"); err != nil {
		t.Fatal(err)
	}
	if got := T(Started); got != "Прокси-сервис запущен" {
		t.Fatalf("Russian message = %q", got)
	}
	if err := Set("en"); err != nil {
		t.Fatal(err)
	}
	if got := T(Started); got != "Proxy service started" {
		t.Fatalf("English message = %q", got)
	}
	if err := Set("de"); err == nil {
		t.Fatal("expected unsupported language error")
	}
}
