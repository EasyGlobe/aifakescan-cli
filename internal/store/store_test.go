package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileVaultPermissionsAndIsolation(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, e := NewFileVault("unused"); e == nil {
			t.Fatal("insecure Windows fallback")
		}
		return
	}
	d := t.TempDir()
	os.Chmod(d, 0700)
	p := filepath.Join(d, "credentials")
	f, e := NewFileVault(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Set("test", "synthetic"); e != nil {
		t.Fatal(e)
	}
	s, _ := os.Stat(p)
	if s.Mode().Perm() != 0600 {
		t.Fatal("wrong mode")
	}
	v, e := f.Get("test")
	if e != nil || v != "synthetic" {
		t.Fatal(e)
	}
	os.Chmod(p, 0644)
	if _, e = f.Get("test"); e == nil {
		t.Fatal("insecure file read")
	}
	if Service("https://api.aifakescan.com") == Service("http://127.0.0.1:1234") {
		t.Fatal("endpoint credential collision")
	}
}
func TestExclusiveProcessLock(t *testing.T) {
	d := t.TempDir()
	u, e := Lock(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Lock(d); e == nil {
		t.Fatal("concurrent process lock failed")
	}
	u()
	u, e = Lock(d)
	if e != nil {
		t.Fatal(e)
	}
	u()
}

func TestAtomicReplacesOwnExistingFile(t *testing.T) {
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	if e := SecureDir(d); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(d, "manifest.json")
	if e := Atomic(path, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(path, []byte("second")); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != "second" {
		t.Fatal("replacement did not persist")
	}
}
