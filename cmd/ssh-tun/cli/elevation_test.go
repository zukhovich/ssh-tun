package cli

import (
	"runtime"
	"testing"
)

func TestNeedsElevation(t *testing.T) {
	if needsElevation(false) {
		t.Fatal("proxy-only mode must never request elevation")
	}
}

func TestElevationOnWindowsTunMode(t *testing.T) {
	if runtime.GOOS == "windows" && !needsElevation(true) {
		t.Fatal("TUN mode must request elevation on Windows")
	}
}
