package batch

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EasyGlobe/aifakescan-cli/internal/api"
	"github.com/EasyGlobe/aifakescan-cli/internal/store"
)

type Item struct {
	Path     string      `json:"path"`
	Name     string      `json:"name"`
	Size     int64       `json:"size"`
	MIME     string      `json:"content_type"`
	Media    string      `json:"media_type"`
	SHA256   string      `json:"sha256"`
	Key      string      `json:"idempotency_key"`
	ScanID   string      `json:"scan_id,omitempty"`
	Identity string      `json:"identity,omitempty"`
	State    string      `json:"state"`
	Error    string      `json:"error_code,omitempty"`
	Report   *api.Report `json:"report,omitempty"`
}
type Batch struct {
	Version   string  `json:"schema_version"`
	ID        string  `json:"id"`
	Endpoint  string  `json:"endpoint"`
	CreatedAt string  `json:"created_at"`
	Policy    string  `json:"upload_policy"`
	Items     []*Item `json:"items"`
}

func ID(prefix string) string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("system random unavailable")
	}
	return prefix + hex.EncodeToString(b)
}
func New(endpoint string, items []*Item) *Batch {
	return &Batch{Version: "1", ID: ID("batch_"), Endpoint: endpoint, CreatedAt: time.Now().UTC().Format(time.RFC3339), Items: items}
}
func (b *Batch) Save(dir string) error {
	data, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	return store.Atomic(filepath.Join(dir, b.ID+".json"), data)
}
func Load(dir, id string) (*Batch, error) {
	if !api.ValidID(id) || !strings.HasPrefix(id, "batch_") {
		return nil, errors.New("invalid batch ID")
	}
	p := filepath.Join(dir, id+".json")
	s, e := os.Lstat(p)
	if e != nil || !s.Mode().IsRegular() {
		return nil, errors.New("batch not found")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var b Batch
	if json.NewDecoder(io.LimitReader(f, 16<<20)).Decode(&b) != nil || b.Version != "1" || b.ID != id {
		return nil, errors.New("invalid batch manifest")
	}
	return &b, nil
}

var types = map[string][2]string{".jpg": {"image/jpeg", "image"}, ".jpeg": {"image/jpeg", "image"}, ".png": {"image/png", "image"}, ".webp": {"image/webp", "image"}, ".avif": {"image/avif", "image"}, ".heic": {"image/heic", "image"}, ".heif": {"image/heif", "image"}, ".mp4": {"video/mp4", "video"}, ".mov": {"video/quicktime", "video"}, ".webm": {"video/webm", "video"}, ".mkv": {"video/x-matroska", "video"}}

func Discover(paths []string, recursive bool, limit int) ([]*Item, error) {
	if len(paths) == 0 {
		return nil, errors.New("provide one or more media paths")
	}
	all := map[string]*Item{}
	add := func(p string, explicit bool) error {
		info, e := os.Lstat(p)
		if e != nil {
			return errors.New("input path cannot be read")
		}
		if !info.Mode().IsRegular() {
			if explicit {
				return errors.New("input must be a regular file or directory; symlinks are not followed")
			}
			return nil
		}
		typ, ok := types[strings.ToLower(filepath.Ext(p))]
		if !ok {
			if explicit {
				return errors.New("unsupported input file extension")
			}
			return nil
		}
		abs, e := filepath.Abs(p)
		if e != nil {
			return e
		}
		name := filepath.Base(p)
		if !filepath.IsAbs(p) {
			name = filepath.Clean(p)
		}
		it := &Item{Path: abs, Name: name, Size: info.Size(), MIME: typ[0], Media: typ[1], Key: ID("cli_"), State: "pending"}
		max := int64(20 << 20)
		if it.Media == "video" {
			max = 200 << 20
		}
		if it.Size == 0 || it.Size > max {
			it.State = "failed"
			it.Error = "invalid_file_size"
		}
		all[abs] = it
		return nil
	}
	for _, p := range paths {
		info, e := os.Lstat(p)
		if e != nil {
			return nil, errors.New("input path cannot be read")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink input is not allowed")
		}
		if !info.IsDir() {
			if e = add(p, true); e != nil {
				return nil, e
			}
			continue
		}
		e = filepath.WalkDir(p, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("cannot enumerate input directory")
			}
			if path == p {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			return add(path, false)
		})
		if e != nil {
			return nil, e
		}
	}
	keys := make([]string, 0, len(all))
	for p := range all {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	var out []*Item
	selected := 0
	for _, p := range keys {
		if limit > 0 && selected >= limit {
			break
		}
		out = append(out, all[p])
		if all[p].State == "pending" {
			selected++
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no supported media files found")
	}
	return out, nil
}

// OpenVerified rejects changed files before network requests and returns the same
// open descriptor used for upload. The service independently verifies the digest.
func OpenVerified(it *Item) (*os.File, error) {
	before, e := os.Lstat(it.Path)
	if e != nil || !before.Mode().IsRegular() {
		return nil, errors.New("file unavailable or not regular")
	}
	f, e := os.Open(it.Path)
	if e != nil {
		return nil, errors.New("file unavailable")
	}
	info, e := f.Stat()
	if e != nil || !os.SameFile(before, info) || info.Size() != it.Size {
		f.Close()
		return nil, errors.New("input file changed")
	}
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil || n != it.Size {
		f.Close()
		return nil, errors.New("input file changed")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if it.SHA256 != "" && it.SHA256 != sum {
		f.Close()
		return nil, errors.New("input file changed; original task was not resubmitted")
	}
	it.SHA256 = sum
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
