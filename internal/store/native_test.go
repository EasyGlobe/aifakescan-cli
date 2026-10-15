package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

// This integration test touches only a fresh random test namespace, never a
// configured account namespace. It is opt-in because OS stores may prompt.
func TestNativeCredentialStore(t *testing.T) {
	if os.Getenv("AIFAKESCAN_TEST_NATIVE_KEYRING") != "1" {
		t.Skip("set AIFAKESCAN_TEST_NATIVE_KEYRING=1 to test the native credential store")
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("cannot generate synthetic test namespace")
	}
	namespace := "com.aifakescan.cli.integration-test." + hex.EncodeToString(random[:12])
	vault := Keyring{Service: namespace}
	key := "synthetic-test-only"
	value := "synthetic-" + hex.EncodeToString(random[12:])
	defer func() {
		if err := vault.Delete(key); err != nil {
			t.Error("native test credential cleanup failed")
		}
	}()
	if err := vault.Set(key, value); err != nil {
		t.Fatal("native credential write failed")
	}
	got, err := vault.Get(key)
	if err != nil || got != value {
		t.Fatal("native credential read did not match the synthetic value")
	}
	if err = vault.Delete(key); err != nil {
		t.Fatal("native credential deletion failed")
	}
	if _, err = vault.Get(key); !errors.Is(err, ErrNotFound) {
		t.Fatal("native synthetic credential remained after deletion")
	}
}
