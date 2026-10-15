package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/EasyGlobe/aifakescan-cli/internal/api"
	"github.com/EasyGlobe/aifakescan-cli/internal/batch"
	"github.com/EasyGlobe/aifakescan-cli/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryVault struct {
	mu        sync.Mutex
	m         map[string]string
	failOwner bool
}

func (v *memoryVault) Get(k string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	x, ok := v.m[k]
	if !ok {
		return "", store.ErrNotFound
	}
	return x, nil
}
func (v *memoryVault) Set(k, s string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failOwner && strings.HasPrefix(k, "scan:") {
		return errors.New("vault unavailable")
	}
	v.m[k] = s
	return nil
}
func (v *memoryVault) Delete(k string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.m, k)
	return nil
}
func guestVault() *memoryVault {
	v := &memoryVault{m: map[string]string{}}
	g := api.Token{AccessToken: "afs_guest_synthetic", TokenType: "Bearer", ExpiresIn: 86400, ExpiresAt: time.Now().Add(time.Hour)}
	b, _ := json.Marshal(g)
	v.Set("guest", string(b))
	return v
}
func newTestApp(t *testing.T, h http.Handler, v *memoryVault) (*App, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	c, e := api.New(s.URL, true)
	if e != nil {
		t.Fatal(e)
	}
	d := t.TempDir()
	os.Chmod(d, 0700)
	a := &App{Client: c, Vault: v, Dir: d, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, In: strings.NewReader("")}
	return a, s
}
func TestLostCreateResponseRecoversSameScanBeforeUpload(t *testing.T) {
	v := guestVault()
	creates, recoveries, uploads := 0, 0, 0
	var endpoint string
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/scans":
			creates++
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("no idempotency key")
			}
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		case "/v1/scans/recover":
			recoveries++
			if r.Header.Get("Authorization") != "Bearer afs_guest_synthetic" {
				t.Error("wrong recovery identity")
			}
			json.NewEncoder(w).Encode(api.Created{ScanID: "scan_synthetic", OwnerToken: "owner_synthetic", UploadURL: endpoint + "/upload", UploadMethod: "PUT"})
		case "/upload":
			uploads++
			if _, e := v.Get("scan:scan_synthetic"); e != nil {
				t.Error("owner not persisted before upload")
			}
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-Scan-Token") != "" {
				t.Error("credentials leaked to upload")
			}
			data, _ := io.ReadAll(r.Body)
			if string(data) != "synthetic" {
				t.Error("upload changed")
			}
			w.WriteHeader(200)
		case "/v1/scans/scan_synthetic/uploaded":
			w.Write([]byte(`{}`))
		case "/v1/scans/scan_synthetic":
			if r.Header.Get("X-Scan-Token") != "owner_synthetic" {
				t.Error("owner missing")
			}
			w.Write([]byte(`{"id":"scan_synthetic","status":"complete","result":{"verdict":"inconclusive","limitations":["Not calibrated"],"coverage":{"audio":"not_tested"}}}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}), v)
	defer s.Close()
	endpoint = s.URL
	p := filepath.Join(t.TempDir(), "test.png")
	os.WriteFile(p, []byte("synthetic"), 0600)
	items, _ := batch.Discover([]string{p}, false, 0)
	it := items[0]
	saves := 0
	e := a.process(context.Background(), it, func() error {
		saves++
		if it.SHA256 == "" || it.Key == "" {
			t.Error("intent missing digest or key")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if creates != 1 || recoveries != 1 || uploads != 1 || it.State != "complete" || saves < 4 {
		t.Fatalf("create=%d recover=%d uploads=%d state=%s saves=%d", creates, recoveries, uploads, it.State, saves)
	}
}
func TestCredentialFailurePreventsUpload(t *testing.T) {
	v := guestVault()
	v.failOwner = true
	uploaded := false
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/scans" {
			w.Write([]byte(`{"scan_id":"scan_test","owner_token":"synthetic","upload_method":"PUT","upload_url":"https://bucket.r2.cloudflarestorage.com/test"}`))
			return
		}
		uploaded = true
		w.WriteHeader(500)
	}), v)
	defer s.Close()
	p := filepath.Join(t.TempDir(), "photo.jpg")
	os.WriteFile(p, []byte("synthetic"), 0600)
	items, _ := batch.Discover([]string{p}, false, 0)
	if e := a.process(context.Background(), items[0], func() error { return nil }); e == nil || uploaded {
		t.Fatal("upload proceeded without durable ownership")
	}
}
func TestExpiredAccountDoesNotFallbackToGuest(t *testing.T) {
	v := guestVault()
	expired := api.Token{AccessToken: "afs_access_old", RefreshToken: "synthetic", ExpiresAt: time.Now().Add(-time.Minute)}
	raw, _ := json.Marshal(expired)
	v.Set("account", string(raw))
	calls := 0
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/cli/token" {
			t.Fatal("guest fallback")
		}
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}), v)
	defer s.Close()
	_, _, e := a.identity(context.Background(), true)
	if api.Exit(e) != 3 || calls != 1 {
		t.Fatalf("error %v calls %d", e, calls)
	}
}
func TestPendingGuestResumeKeepsOriginalIdentityAfterLogin(t *testing.T) {
	v := guestVault()
	token := api.Token{AccessToken: "afs_access_synthetic", RefreshToken: "synthetic", ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(token)
	v.Set("account", string(raw))
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/scans/recover" {
			if r.Header.Get("Authorization") != "Bearer afs_guest_synthetic" {
				t.Error("switched recovery identity")
			}
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"session_expired"}`))
			return
		}
		t.Error("unexpected resubmission")
		w.WriteHeader(500)
	}), v)
	defer s.Close()
	p := filepath.Join(t.TempDir(), "photo.jpg")
	os.WriteFile(p, []byte("synthetic"), 0600)
	items, _ := batch.Discover([]string{p}, false, 0)
	items[0].State = "creating"
	items[0].Identity = "guest"
	if e := a.process(context.Background(), items[0], func() error { return nil }); api.Exit(e) != 3 {
		t.Fatal(e)
	}
}
func TestDryRunAndInvalidArgsNeverNeedCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "image.jpg")
	os.WriteFile(p, []byte("synthetic"), 0600)
	var out, err bytes.Buffer
	code := Run(context.Background(), []string{"scan", p, "--dry-run", "--format", "jsonl"}, strings.NewReader(""), &out, &err)
	if code != 0 || !strings.Contains(out.String(), `"type":"summary"`) {
		t.Fatal(code, err.String())
	}
	code = Run(context.Background(), []string{"scan", p, "--concurrency", "99"}, strings.NewReader(""), &out, &err)
	if code != 2 {
		t.Fatal("invalid flags accepted")
	}
}
func TestParallelBatchSavesAndPartialFailure(t *testing.T) {
	v := guestVault()
	token := api.Token{AccessToken: "afs_access_synthetic", RefreshToken: "synthetic", ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(token)
	v.Set("account", string(raw))
	var endpoint string
	var lock sync.Mutex
	next := 0
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/quota":
			w.Write([]byte(`{"kind":"account","remaining":20,"max_in_flight":2}`))
		case r.URL.Path == "/v1/scans":
			lock.Lock()
			next++
			n := next
			lock.Unlock()
			json.NewEncoder(w).Encode(api.Created{ScanID: fmt.Sprintf("scan_%d", n), UploadURL: endpoint + "/upload", UploadMethod: "PUT"})
		case r.URL.Path == "/upload":
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(200)
		case strings.HasSuffix(r.URL.Path, "/uploaded"):
			w.Write([]byte(`{}`))
		default:
			id := filepath.Base(r.URL.Path)
			json.NewEncoder(w).Encode(api.Report{ID: id, Status: "complete", Result: &api.Result{Verdict: "inconclusive"}})
		}
	}), v)
	defer s.Close()
	endpoint = s.URL
	var items []*batch.Item
	for i := 0; i < 5; i++ {
		p := filepath.Join(t.TempDir(), "photo.jpg")
		os.WriteFile(p, []byte("synthetic"), 0600)
		x, _ := batch.Discover([]string{p}, false, 0)
		items = append(items, x[0])
	}
	items = append(items, &batch.Item{Name: "empty.png", State: "failed", Error: "invalid_file_size"})
	b := batch.New(endpoint, items)
	code, e := a.runBatch(context.Background(), b, options{format: "jsonl", concurrency: 2})
	if e != nil || code != 5 {
		t.Fatal(code, e)
	}
	saved, e := batch.Load(a.Dir, b.ID)
	if e != nil || len(saved.Items) != 6 {
		t.Fatal(e)
	}
	if next != 5 {
		t.Fatal("wrong creates", next)
	}
}

func TestBatchClassifiesStorageRejectionSeparatelyFromAPILogin(t *testing.T) {
	cases := []struct {
		name, failureAt, errorCode, savedState string
		status, exit                           int
		login                                  bool
	}{
		{"storage unauthorized", "upload", "upload_failed", "uploading", 401, 6, false},
		{"storage forbidden", "upload", "upload_failed", "uploading", 403, 6, false},
		{"API invalid token", "create", "invalid_token", "creating", 401, 3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := guestVault()
			var endpoint string
			var mu sync.Mutex
			creates, recoveries, uploads := 0, 0, 0
			recovered := false
			a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.URL.Path == "/v1/quota":
					w.Write([]byte(`{"kind":"guest","remaining":3,"max_in_flight":1}`))
				case r.URL.Path == "/v1/scans":
					creates++
					if tc.failureAt == "create" {
						w.WriteHeader(tc.status)
						w.Write([]byte(`{"detail":{"code":"invalid_token"}}`))
						return
					}
					json.NewEncoder(w).Encode(api.Created{ScanID: fmt.Sprintf("scan_%d", creates), OwnerToken: "synthetic_owner", UploadURL: endpoint + "/upload?X-Amz-Signature=synthetic-secret", UploadMethod: "PUT"})
				case r.URL.Path == "/v1/scans/recover":
					recoveries++
					json.NewEncoder(w).Encode(api.Created{ScanID: "scan_1", OwnerToken: "rotated_owner", UploadURL: endpoint + "/upload", UploadMethod: "PUT"})
				case r.URL.Path == "/upload":
					uploads++
					io.Copy(io.Discard, r.Body)
					if !recovered {
						w.WriteHeader(tc.status)
						w.Write([]byte(`<Error><Message>private-storage-detail</Message></Error>`))
					}
				case strings.HasSuffix(r.URL.Path, "/uploaded"):
					w.Write([]byte(`{}`))
				default:
					json.NewEncoder(w).Encode(api.Report{ID: filepath.Base(r.URL.Path), Status: "complete", Result: &api.Result{Verdict: "inconclusive"}})
				}
			}), v)
			defer s.Close()
			endpoint = s.URL
			var items []*batch.Item
			for i := 0; i < 2; i++ {
				p := filepath.Join(t.TempDir(), "photo.jpg")
				os.WriteFile(p, []byte("synthetic"), 0600)
				x, err := batch.Discover([]string{p}, false, 0)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, x[0])
			}
			b := batch.New(endpoint, items)
			code, err := a.runBatch(context.Background(), b, options{format: "jsonl", concurrency: 1})
			if code != tc.exit || api.Code(err) != tc.errorCode {
				t.Fatalf("exit=%d error=%v, want exit=%d code=%s", code, err, tc.exit, tc.errorCode)
			}
			stderr := a.Err.(*bytes.Buffer).String()
			if strings.Contains(stderr, "aifakescan auth login") != tc.login || !strings.Contains(stderr, "aifakescan batch resume "+b.ID) {
				t.Fatal("wrong recovery guidance")
			}
			output := stderr + a.Out.(*bytes.Buffer).String() + err.Error()
			for _, forbidden := range []string{endpoint, "synthetic-secret", "private-storage-detail", "<Error>"} {
				if strings.Contains(output, forbidden) {
					t.Fatal("storage details exposed in output")
				}
			}
			saved, err := batch.Load(a.Dir, b.ID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.Items[0].State != tc.savedState || saved.Items[1].State != "pending" {
				t.Fatal("blocked task was marked failed or subsequent work started")
			}
			mu.Lock()
			initialCreates := creates
			recovered = true
			mu.Unlock()
			if initialCreates != 1 {
				t.Fatal("batch continued after blocking error")
			}
			if tc.failureAt == "upload" {
				code, err = a.runBatch(context.Background(), saved, options{format: "jsonl", concurrency: 1})
				if code != 0 || err != nil {
					t.Fatalf("resume failed: exit=%d error=%v", code, err)
				}
				mu.Lock()
				countsCorrect := creates == 2 && recoveries == 1 && uploads == 3
				mu.Unlock()
				if !countsCorrect || saved.Items[0].State != "complete" || saved.Items[1].State != "complete" {
					t.Fatal("resume did not recover the existing scan and finish both files")
				}
			}
		})
	}
}

func TestGuestQuotaThenLoginResumesOnlyUncreatedFourthFile(t *testing.T) {
	v := guestVault()
	var endpoint string
	guestAccepted, accountAccepted, guestAttempts := 0, 0, 0
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer afs_access_")
		switch {
		case r.URL.Path == "/v1/quota":
			w.Write([]byte(`{"kind":"account","remaining":20,"max_in_flight":2}`))
		case r.URL.Path == "/v1/scans/recover":
			if account {
				t.Error("must recover original guest intent before switching account")
			}
			w.WriteHeader(404)
			w.Write([]byte(`{"detail":{"code":"idempotency_not_found"}}`))
		case r.URL.Path == "/v1/scans":
			id := ""
			owner := ""
			if account {
				accountAccepted++
				id = "scan_account"
			} else {
				guestAttempts++
				if guestAccepted >= 3 {
					w.WriteHeader(401)
					w.Write([]byte(`{"detail":{"code":"login_required"}}`))
					return
				}
				guestAccepted++
				id = fmt.Sprintf("scan_guest_%d", guestAccepted)
				owner = "synthetic_owner"
			}
			json.NewEncoder(w).Encode(api.Created{ScanID: id, OwnerToken: owner, UploadURL: endpoint + "/upload", UploadMethod: "PUT"})
		case r.URL.Path == "/upload":
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(200)
		case strings.HasSuffix(r.URL.Path, "/uploaded"):
			w.Write([]byte(`{}`))
		default:
			json.NewEncoder(w).Encode(api.Report{ID: filepath.Base(r.URL.Path), Status: "complete", Result: &api.Result{Verdict: "inconclusive"}})
		}
	}), v)
	defer s.Close()
	endpoint = s.URL
	var items []*batch.Item
	for i := 0; i < 4; i++ {
		p := filepath.Join(t.TempDir(), "photo.jpg")
		os.WriteFile(p, []byte("synthetic"), 0600)
		x, _ := batch.Discover([]string{p}, false, 0)
		items = append(items, x[0])
	}
	b := batch.New(endpoint, items)
	code, e := a.runBatch(context.Background(), b, options{format: "jsonl", concurrency: 2})
	if code != 3 || e == nil || guestAccepted != 3 || guestAttempts != 4 {
		t.Fatalf("guest run: code=%d err=%v accepted=%d attempts=%d", code, e, guestAccepted, guestAttempts)
	}
	token := api.Token{AccessToken: "afs_access_synthetic", RefreshToken: "synthetic", ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(token)
	v.Set("account", string(raw))
	saved, e := batch.Load(a.Dir, b.ID)
	if e != nil {
		t.Fatal(e)
	}
	code, e = a.runBatch(context.Background(), saved, options{format: "jsonl", concurrency: 2})
	if code != 0 || e != nil || guestAccepted != 3 || guestAttempts != 4 || accountAccepted != 1 {
		t.Fatalf("account resume: code=%d err=%v guest=%d attempts=%d account=%d", code, e, guestAccepted, guestAttempts, accountAccepted)
	}
}

func TestLogoutClearsRejectedAccountButKeepsGuestOwnership(t *testing.T) {
	v := guestVault()
	token := api.Token{AccessToken: "afs_access_expired", RefreshToken: "synthetic", ExpiresAt: time.Now().Add(-time.Hour)}
	raw, _ := json.Marshal(token)
	v.Set("account", string(raw))
	v.Set("scan:scan_guest", "synthetic_owner")
	a, s := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}), v)
	defer s.Close()
	code, e := a.authCommand(context.Background(), []string{"logout"})
	if e != nil || code != 0 {
		t.Fatal(code, e)
	}
	if _, e = v.Get("account"); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("rejected account remained")
	}
	for _, key := range []string{"guest", "scan:scan_guest"} {
		if _, e = v.Get(key); e != nil {
			t.Fatal("guest recovery credential removed")
		}
	}
}
