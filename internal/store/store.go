// Package store keeps credentials separate from non-secret batch manifests.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/zalando/go-keyring"
)

var ErrNotFound = errors.New("credential not found")

type Vault interface {
	Get(string) (string, error)
	Set(string, string) error
	Delete(string) error
}
type Keyring struct{ Service string }

func (k Keyring) Get(id string) (string, error) {
	v, e := keyring.Get(k.Service, id)
	if errors.Is(e, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if e != nil {
		return "", errors.New("OS credential store unavailable; unlock it or explicitly choose --credential-file")
	}
	return v, nil
}
func (k Keyring) Set(id, v string) error {
	if e := keyring.Set(k.Service, id, v); e != nil {
		return errors.New("cannot persist credentials in OS store; unlock it or explicitly choose --credential-file")
	}
	return nil
}
func (k Keyring) Delete(id string) error {
	e := keyring.Delete(k.Service, id)
	if errors.Is(e, keyring.ErrNotFound) {
		return nil
	}
	if e != nil {
		return errors.New("cannot remove OS credential")
	}
	return nil
}
func Service(endpoint string) string {
	s := sha256.Sum256([]byte(endpoint))
	return "com.aifakescan.cli." + hex.EncodeToString(s[:8])
}

type FileVault struct {
	Path string
	mu   sync.Mutex
}

func NewFileVault(path string) (*FileVault, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("credential files are unsupported on Windows; use Credential Manager")
	}
	if e := SecureDir(filepath.Dir(path)); e != nil {
		return nil, e
	}
	f := &FileVault{Path: path}
	if _, e := f.read(); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	return f, nil
}
func (f *FileVault) read() (map[string]string, error) {
	s, e := os.Lstat(f.Path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || (runtime.GOOS != "windows" && s.Mode().Perm()&0077 != 0) {
		return nil, errors.New("credential file must be a regular file with mode 0600")
	}
	b, e := os.ReadFile(f.Path)
	if e != nil {
		return nil, e
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return nil, errors.New("invalid credential file")
	}
	return m, nil
}
func (f *FileVault) Get(k string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, e := f.read()
	if errors.Is(e, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if e != nil {
		return "", e
	}
	v, ok := m[k]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (f *FileVault) Set(k, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, e := f.read()
	if errors.Is(e, os.ErrNotExist) {
		m = map[string]string{}
	} else if e != nil {
		return e
	}
	m[k] = v
	b, _ := json.Marshal(m)
	return Atomic(f.Path, b)
}
func (f *FileVault) Delete(k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, e := f.read()
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	delete(m, k)
	b, _ := json.Marshal(m)
	return Atomic(f.Path, b)
}
func SecureDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return errors.New("cannot create private state directory")
	}
	s, e := os.Lstat(path)
	if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be a real directory")
	}
	if runtime.GOOS != "windows" && s.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must have mode 0700")
	}
	return securePlatformDir(path)
}
func Atomic(path string, b []byte) error {
	if s, e := os.Lstat(path); e == nil && (!s.Mode().IsRegular() || (runtime.GOOS != "windows" && s.Mode().Perm()&0077 != 0)) {
		return errors.New("refusing unsafe local file")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".afs-*")
	if e != nil {
		return errors.New("cannot save local state")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	if e != nil {
		return errors.New("cannot durably save local state")
	}
	return nil
}
func Lock(dir string) (func(), error) { return LockFile(filepath.Join(dir, "active.lock")) }

// OS locks are released automatically on process exit, including crashes. Keep
// the empty file in place: unlinking an advisory lock introduces inode races.
func LockFile(path string) (func(), error) {
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0)) {
		return nil, errors.New("unsafe process lock file")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.New("cannot open process lock")
	}
	release, err := platformLock(f)
	if err != nil {
		f.Close()
		return nil, errors.New("another CLI process is using this state or credential store")
	}
	return func() { release(); f.Close() }, nil
}
