package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointAndUploadBoundaries(t *testing.T) {
	for _, u := range []string{"http://api.aifakescan.com", "https://api.aifakescan.com.evil.example", "https://user:secret@api.aifakescan.com", "https://api.aifakescan.com?token=x"} {
		if _, e := New(u, false); e == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	c, _ := New(DefaultEndpoint, false)
	for _, u := range []string{"https://evil.example/file", "http://bucket.r2.cloudflarestorage.com/file", "https://bucket.r2.cloudflarestorage.com.evil.example/file", "https://u:p@bucket.r2.cloudflarestorage.com/file"} {
		if e := c.Upload(context.Background(), u, "PUT", "image/png", 1, strings.NewReader("x")); e == nil {
			t.Fatalf("accepted upload %s", u)
		}
	}
}
func TestRedirectDoesNotLeakCredentials(t *testing.T) {
	received := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, 307) }))
	defer srv.Close()
	c, _ := New(srv.URL, true)
	_, e := c.Request(context.Background(), "GET", "/v1/quota", "sensitive", "owner", "", nil, nil, false)
	if e == nil || received {
		t.Fatal("redirect was followed")
	}
	if strings.Contains(e.Error(), "sensitive") || strings.Contains(e.Error(), evil.URL) {
		t.Fatal("error leaked data")
	}
}
func TestMalformedAndRetry(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			w.Write([]byte(`{"detail":{"code":"capacity_exceeded"}}`))
			return
		}
		w.Write([]byte(`bad json`))
	}))
	defer s.Close()
	c, _ := New(s.URL, true)
	var q Quota
	_, e := c.Request(context.Background(), "GET", "/v1/quota", "", "", "", nil, &q, true)
	if e == nil || calls != 2 {
		t.Fatal("expected bounded retry then malformed failure")
	}
}
func TestErrorRedactionAndExitCodes(t *testing.T) {
	cases := map[string]int{"guest_quota_exhausted": 3, "auth_required": 3, "account_daily_limit": 4, "capacity_exceeded": 4}
	for code, want := range cases {
		status := 429
		if code == "auth_required" {
			status = 401
		}
		if got := Exit(&Error{Status: status, Code: code}); got != want {
			t.Fatalf("%s = %d", code, got)
		}
	}
	if Exit(context.Canceled) != 130 || Exit(nil) != 0 {
		t.Fatal("bad exit")
	}
	if retryDelay("99999", 0) > 60*time.Second {
		t.Fatal("unbounded retry")
	}
	if ValidID("../../account") {
		t.Fatal("unsafe id")
	}
}
func TestTokenResponseValidation(t *testing.T) {
	x := Token{AccessToken: "afs_guest_synthetic", TokenType: "Bearer", ExpiresIn: 1}
	if x.Validate(true) == nil {
		t.Fatal("guest token accepted as account")
	}
	if e := x.Validate(false); e != nil {
		t.Fatal(e)
	}
}

func TestPublicReportDropsUnknownNestedFields(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.aifakescan.cli.v1+json" {
			t.Error("public DTO Accept header missing")
		}
		w.Write([]byte(`{"schema_version":"1","id":"scan_example","status":"complete","internal_root":"private","result":{"verdict":"inconclusive","authenticity_proven":true,"probability":0.99,"coverage":{"provenance":"partial","internal_threshold":0.75},"evidence":[{"type":"provenance","title":"Example","summary":"Synthetic","strength":"weak","status":"neutral","details":{"private_path":"secret"}}]}}`))
	}))
	defer s.Close()
	c, _ := New(s.URL, true)
	var r Report
	if _, e := c.Request(context.Background(), "GET", "/v1/scans/scan_example", "", "owner", "", nil, &r, false); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	raw := string(b)
	for _, forbidden := range []string{"internal_root", "internal_threshold", "private_path", "secret", "0.99"} {
		if strings.Contains(raw, forbidden) {
			t.Fatal("unknown or unsafe result data retained")
		}
	}
	if r.SchemaVersion != "1" || r.Result.AuthenticityProven || r.Result.Probability != nil || r.Result.Coverage.AIAudio != "not_tested" {
		t.Fatal("public guarantees not preserved")
	}
}
