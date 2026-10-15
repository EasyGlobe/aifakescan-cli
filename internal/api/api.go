// Package api implements the public AIFakeScan protocol. It contains no detector.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultEndpoint = "https://api.aifakescan.com"

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }

type Error struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return fmt.Sprintf("service error: %s (HTTP %d)", e.Code, e.Status) }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	return "network_or_service_error"
}
func Exit(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case "guest_quota_exhausted", "login_required", "auth_required", "invalid_token", "session_expired", "invalid_grant", "access_denied", "expired_token", "verification_required", "refresh_already_used", "refresh_reuse_detected":
			return 3
		}
		if e.Code == "recovery_conflict" {
			return 6
		}
		if e.Status == 401 || e.Status == 403 {
			return 3
		}
		if e.Status == 429 || e.Code == "capacity_exceeded" {
			return 4
		}
		if e.Status >= 400 && e.Status < 500 {
			return 5
		}
	}
	return 6
}

type Client struct {
	Endpoint         string
	HTTP, UploadHTTP *http.Client
	TestMode         bool
}

func New(endpoint string, testing bool) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid API endpoint")
	}
	if endpoint != "" {
		endpoint = strings.TrimRight(endpoint, "/")
	}
	if !testing && endpoint != DefaultEndpoint {
		return nil, errors.New("production API endpoint must be https://api.aifakescan.com")
	}
	if testing && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return nil, errors.New("test endpoint must be loopback HTTP")
	}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{Endpoint: endpoint, TestMode: testing, HTTP: &http.Client{Timeout: 45 * time.Second, CheckRedirect: noRedirect}, UploadHTTP: &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noRedirect}}, nil
}
func (c *Client) Request(ctx context.Context, method, path, token, owner, key string, in, out any, retry bool) (int, error) {
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#") {
		return 0, errors.New("invalid API path")
	}
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return 0, err
		}
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, bytes.NewReader(body))
		if err != nil {
			return 0, errors.New("invalid request")
		}
		req.Header.Set("Accept", "application/vnd.aifakescan.cli.v1+json")
		req.Header.Set("User-Agent", "aifakescan-cli/0.1.0-beta.1")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if owner != "" {
			req.Header.Set("X-Scan-Token", owner)
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if retry && attempt < 2 {
				if err = Pause(ctx, time.Duration(attempt+1)*time.Second); err != nil {
					return 0, err
				}
				continue
			}
			return 0, errors.New("network request failed; resume the saved batch")
		}
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
		resp.Body.Close()
		if readErr != nil || len(b) > 4*1024*1024 {
			return resp.StatusCode, errors.New("invalid or oversized service response")
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(b) > 0 {
				if json.Unmarshal(b, out) != nil {
					return resp.StatusCode, errors.New("malformed service response")
				}
				if report, ok := out.(*Report); ok {
					if err = report.Normalize(); err != nil {
						return resp.StatusCode, err
					}
				}
			}
			return resp.StatusCode, nil
		}
		var p struct {
			Error  string `json:"error"`
			Code   string `json:"code"`
			Detail struct {
				Code string `json:"code"`
			} `json:"detail"`
		}
		_ = json.Unmarshal(b, &p)
		code := p.Detail.Code
		if code == "" {
			code = p.Code
		}
		if code == "" {
			code = p.Error
		}
		if !idPattern.MatchString(code) {
			code = "http_error"
		}
		delay := retryDelay(resp.Header.Get("Retry-After"), attempt)
		e := &Error{resp.StatusCode, code, delay}
		if retry && attempt < 2 && (resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) {
			if err = Pause(ctx, delay); err != nil {
				return resp.StatusCode, err
			}
			continue
		}
		return resp.StatusCode, e
	}
}
func retryDelay(s string, attempt int) time.Duration {
	if n, e := strconv.Atoi(s); e == nil && n >= 0 {
		if n > 60 {
			n = 60
		}
		return time.Duration(n) * time.Second
	}
	if t, e := http.ParseTime(s); e == nil {
		d := time.Until(t)
		if d > 60*time.Second {
			d = 60 * time.Second
		}
		if d > 0 {
			return d
		}
	}
	return time.Duration(1<<attempt)*time.Second + time.Duration(rand.IntN(300))*time.Millisecond
}
func Pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (c *Client) Upload(ctx context.Context, target, method, mime string, size int64, body io.Reader) error {
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Fragment != "" {
		return errors.New("rejected upload destination")
	}
	host := u.Hostname()
	allowed := u.Scheme == "https" && strings.HasSuffix(host, ".r2.cloudflarestorage.com") && host != "r2.cloudflarestorage.com" && (u.Port() == "" || u.Port() == "443")
	if c.TestMode {
		base, _ := url.Parse(c.Endpoint)
		allowed = u.Scheme == "http" && u.Host == base.Host
	}
	if !allowed || method != "PUT" {
		return errors.New("rejected upload destination or method")
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", target, io.LimitReader(body, size))
	if err != nil {
		return errors.New("invalid upload request")
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", mime)
	resp, err := c.UploadHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("upload interrupted; resume the saved batch")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Code: "upload_failed"}
	}
	return nil
}

type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	SessionID    string    `json:"session_id,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	ExpiresAt    time.Time `json:"local_expires_at"`
}

func (t *Token) Validate(account bool) error {
	prefix := "afs_guest_"
	if account {
		prefix = "afs_access_"
	}
	if !strings.HasPrefix(t.AccessToken, prefix) || t.TokenType != "Bearer" || t.ExpiresIn <= 0 || t.ExpiresIn > 31536000 {
		return errors.New("invalid token response")
	}
	if account && t.RefreshToken == "" {
		return errors.New("missing refresh token")
	}
	t.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return nil
}

type Device struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}
type Quota struct {
	Enabled          *bool  `json:"enabled,omitempty"`
	NetworkRemaining *int   `json:"network_remaining,omitempty"`
	PrincipalType    string `json:"kind"`
	DailyLimit       int    `json:"limit"`
	Used             int    `json:"used"`
	Remaining        int    `json:"remaining"`
	Reserved         int    `json:"reserved"`
	InFlight         int    `json:"in_flight"`
	VideoLimit       int    `json:"video_limit"`
	VideoUsed        int    `json:"video_used"`
	VideoReserved    int    `json:"video_reserved"`
	MaxInFlight      int    `json:"max_in_flight"`
	MaxVideoInFlight int    `json:"max_video_in_flight"`
	ResetAt          string `json:"reset_at"`
}
type Created struct {
	ScanID       string `json:"scan_id"`
	OwnerToken   string `json:"owner_token,omitempty"`
	UploadURL    string `json:"upload_url,omitempty"`
	UploadMethod string `json:"upload_method,omitempty"`
	ExpiresAt    string `json:"expires_at"`
}
type Coverage struct {
	Provenance       string `json:"provenance"`
	VisibleWatermark string `json:"visible_watermark"`
	Generated        string `json:"generated"`
	Manipulated      string `json:"manipulated"`
	AIAudio          string `json:"ai_audio"`
}
type Evidence struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	Strength string `json:"strength"`
	Status   string `json:"status"`
}
type Result struct {
	AuthenticityProven bool       `json:"authenticity_proven"`
	Probability        *float64   `json:"probability"`
	Verdict            string     `json:"verdict"`
	Coverage           Coverage   `json:"coverage"`
	Limitations        []string   `json:"limitations,omitempty"`
	DecisionReasons    []string   `json:"decision_reasons,omitempty"`
	ScanDepth          string     `json:"scan_depth,omitempty"`
	Evidence           []Evidence `json:"evidence,omitempty"`
}
type Report struct {
	SchemaVersion string  `json:"schema_version"`
	ID            string  `json:"id"`
	Status        string  `json:"status"`
	ExpiresAt     string  `json:"expires_at,omitempty"`
	Result        *Result `json:"result,omitempty"`
	ErrorCode     string  `json:"error_code,omitempty"`
	ErrorMessage  string  `json:"-"`
}

func (r Report) Terminal() bool {
	switch r.Status {
	case "complete", "failed", "expired", "deleted":
		return true
	}
	return false
}

// Normalize keeps schema and result guarantees independent of unknown response
// fields. Even a malformed service confidence value cannot become proof.
func (r *Report) Normalize() error {
	if r.SchemaVersion != "" && r.SchemaVersion != "1" {
		return errors.New("unsupported report schema")
	}
	r.SchemaVersion = "1"
	if r.Result != nil {
		r.Result.AuthenticityProven = false
		r.Result.Probability = nil
		for _, field := range []*string{&r.Result.Coverage.Provenance, &r.Result.Coverage.VisibleWatermark, &r.Result.Coverage.Generated, &r.Result.Coverage.Manipulated, &r.Result.Coverage.AIAudio} {
			switch *field {
			case "complete", "partial", "not_tested", "not_applicable", "failed":
			default:
				*field = "not_tested"
			}
		}
	}
	return nil
}
