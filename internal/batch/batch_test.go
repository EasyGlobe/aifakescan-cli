package batch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverPrivacyAndDeterminism(t *testing.T) {
	d := t.TempDir()
	for _, n := range []string{"b.png", "a.jpg", ".hidden.png", "ignore.txt"} {
		if e := os.WriteFile(filepath.Join(d, n), []byte("synthetic"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	os.Mkdir(filepath.Join(d, "nested"), 0700)
	os.WriteFile(filepath.Join(d, "nested", "c.mp4"), []byte("synthetic"), 0600)
	os.Symlink(filepath.Join(d, "a.jpg"), filepath.Join(d, "link.jpg"))
	items, e := Discover([]string{d}, false, 0)
	if e != nil || len(items) != 2 || items[0].Name != "a.jpg" {
		t.Fatalf("%v %#v", e, items)
	}
	items, e = Discover([]string{d}, true, 0)
	if e != nil || len(items) != 3 {
		t.Fatal(e, len(items))
	}
	if _, e = Discover([]string{filepath.Join(d, "link.jpg")}, true, 0); e == nil {
		t.Fatal("symlink accepted")
	}
	items, e = Discover([]string{d}, true, 1)
	if e != nil || len(items) != 1 {
		t.Fatal("limit")
	}
}
func TestHashDetectsSameSizeMutation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "photo.jpg")
	os.WriteFile(p, []byte("aaaa"), 0600)
	items, e := Discover([]string{p}, false, 0)
	if e != nil {
		t.Fatal(e)
	}
	f, e := OpenVerified(items[0])
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	os.WriteFile(p, []byte("bbbb"), 0600)
	if _, e = OpenVerified(items[0]); e == nil {
		t.Fatal("mutation accepted")
	}
}
func TestRejectMalformedPathsAndEmptyMedia(t *testing.T) {
	if _, e := Load(t.TempDir(), "../../account"); e == nil {
		t.Fatal("path traversal accepted")
	}
	p := filepath.Join(t.TempDir(), "empty.png")
	os.WriteFile(p, nil, 0600)
	x, e := Discover([]string{p}, false, 0)
	if e != nil || x[0].State != "failed" {
		t.Fatal("empty file not marked failed")
	}
}
