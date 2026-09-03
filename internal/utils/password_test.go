package utils

import "testing"

func TestGetSSHPasswordFromConfig(t *testing.T) {
	password, err := GetSSHPassword("secret", true, "user", "example.com")
	if err != nil {
		t.Fatalf("GetSSHPassword() returned an error: %v", err)
	}
	if password != "secret" {
		t.Errorf("GetSSHPassword() = %q, want %q", password, "secret")
	}
}

func TestGetSSHPasswordWithoutAvailableMethod(t *testing.T) {
	_, err := GetSSHPassword("", false, "user", "example.com")
	if err == nil {
		t.Fatal("GetSSHPassword() did not return an error with interactive authentication disabled")
	}
}
