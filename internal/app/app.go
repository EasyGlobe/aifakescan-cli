package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EasyGlobe/aifakescan-cli/internal/api"
	"github.com/EasyGlobe/aifakescan-cli/internal/batch"
	"github.com/EasyGlobe/aifakescan-cli/internal/output"
	"github.com/EasyGlobe/aifakescan-cli/internal/store"
)

const Version = "0.1.0-beta.2"
const Policy = "2026-10-15"

type App struct {
	Client   *api.Client
	Vault    store.Vault
	Dir      string
	Out, Err io.Writer
	In       io.Reader
	mu       sync.Mutex
	authMu   sync.Mutex
}
type options struct {
	endpoint, state, credential, format, output   string
	test, recursive, dry, accept, overwrite, wait bool
	limit, concurrency                            int
	timeout                                       time.Duration
}

func Run(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, help)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(out, Version)
		return 0
	}
	o, rest, e := parse(args, stderr)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	if len(rest) == 0 {
		fmt.Fprint(stderr, help)
		return 2
	}
	if rest[0] == "scan" && o.dry {
		items, e := batch.Discover(rest[1:], o.recursive, o.limit)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		b := batch.New(o.endpoint, items)
		w, e := destination(o, out)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		defer w.Close()
		if e = output.Write(w, b, o.format); e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		fmt.Fprintln(stderr, "Local enumeration only; no network requests or uploads.")
		return 0
	}
	c, e := api.New(o.endpoint, o.test)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	if o.state == "" {
		base, e := os.UserConfigDir()
		if e != nil {
			fmt.Fprintln(stderr, "cannot resolve state directory")
			return 2
		}
		o.state = filepath.Join(base, "aifakescan")
	}
	dir := filepath.Join(o.state, store.Service(c.Endpoint))
	if e = store.SecureDir(dir); e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	unlock, e := store.Lock(dir)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	defer unlock()
	var v store.Vault = store.Keyring{Service: store.Service(c.Endpoint)}
	var credentialUnlock func()
	if o.credential != "" {
		credentialPath := o.credential + "." + store.Service(c.Endpoint)
		v, e = store.NewFileVault(credentialPath)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		credentialUnlock, e = store.LockFile(credentialPath + ".lock")
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		fmt.Fprintln(stderr, "Using explicitly selected local credential file (0600); keep this private.")
	} else {
		configDir, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(stderr, "cannot resolve credential lock directory")
			return 2
		}
		credentialLockDir := filepath.Join(configDir, "aifakescan-credential-locks", store.Service(c.Endpoint))
		if e = store.SecureDir(credentialLockDir); e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		credentialUnlock, e = store.Lock(credentialLockDir)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
	}
	defer credentialUnlock()
	a := &App{Client: c, Vault: v, Dir: dir, Out: out, Err: stderr, In: in}
	code, e := a.command(ctx, rest, o)
	if e != nil {
		fmt.Fprintln(stderr, output.Safe(e.Error()))
	}
	return code
}
func parse(args []string, errOut io.Writer) (options, []string, error) {
	var o options
	fs := flag.NewFlagSet("aifakescan", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.endpoint, "endpoint", api.DefaultEndpoint, "API endpoint; test mode accepts loopback only")
	fs.BoolVar(&o.test, "test-mode", false, "allow loopback mock server with isolated credentials")
	fs.StringVar(&o.state, "state-dir", "", "private state directory")
	fs.StringVar(&o.credential, "credential-file", "", "explicit Unix credential file base path (0600)")
	fs.StringVar(&o.format, "format", "table", "table, json, jsonl, csv")
	fs.StringVar(&o.output, "output", "", "output path")
	fs.BoolVar(&o.overwrite, "overwrite", false, "replace output file")
	fs.BoolVar(&o.recursive, "recursive", false, "recurse into directories")
	fs.BoolVar(&o.dry, "dry-run", false, "local file enumeration only")
	fs.BoolVar(&o.accept, "accept-upload-policy", false, "acknowledge cloud upload and retention")
	fs.BoolVar(&o.wait, "wait", false, "wait for confirmed cloud deletion")
	fs.IntVar(&o.limit, "limit", 0, "maximum selected files")
	fs.IntVar(&o.concurrency, "concurrency", 2, "in-flight work (1-2, further limited by server)")
	fs.DurationVar(&o.timeout, "timeout", 20*time.Minute, "total command wait timeout")
	// Go flags stop at the first positional argument; reorder known flags so examples
	// can place options after media paths. A literal -- protects dash-prefixed paths.
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		s := args[i]
		if s == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(s, "-") {
			flags = append(flags, s)
			n := strings.TrimLeft(strings.SplitN(s, "=", 2)[0], "-")
			f := fs.Lookup(n)
			if f == nil {
				return o, nil, errors.New("unknown option")
			}
			if !strings.Contains(s, "=") {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
					i++
					if i >= len(args) {
						return o, nil, errors.New("option requires a value")
					}
					flags = append(flags, args[i])
				}
			}
		} else {
			pos = append(pos, s)
		}
	}
	if e := fs.Parse(flags); e != nil {
		return o, nil, e
	}
	if o.limit < 0 || o.concurrency < 1 || o.concurrency > 2 || o.timeout <= 0 {
		return o, nil, errors.New("invalid limit, concurrency, or timeout")
	}
	switch o.format {
	case "table", "json", "jsonl", "csv":
	default:
		return o, nil, errors.New("unsupported output format")
	}
	return o, pos, nil
}
func destination(o options, w io.Writer) (io.WriteCloser, error) {
	if o.output == "" || o.output == "-" {
		return writeCloser{w}, nil
	}
	return output.Destination(o.output, o.overwrite)
}

type writeCloser struct{ io.Writer }

func (writeCloser) Close() error { return nil }
func (a *App) command(ctx context.Context, args []string, o options) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	switch args[0] {
	case "capabilities":
		var data map[string]any
		_, e := a.Client.Request(ctx, "GET", "/v1/capabilities", "", "", "", nil, &data, true)
		if e != nil {
			return api.Exit(e), e
		}
		return 0, json.NewEncoder(a.Out).Encode(data)
	case "auth":
		return a.authCommand(ctx, args[1:])
	case "quota":
		t, _, e := a.identity(ctx, true)
		if e != nil {
			return api.Exit(e), e
		}
		var q api.Quota
		_, e = a.Client.Request(ctx, "GET", "/v1/quota", t.AccessToken, "", "", nil, &q, true)
		if e != nil {
			return api.Exit(e), e
		}
		return 0, json.NewEncoder(a.Out).Encode(q)
	case "scan":
		items, e := batch.Discover(args[1:], o.recursive, o.limit)
		if e != nil {
			return 2, e
		}
		b := batch.New(a.Client.Endpoint, items)
		if e = a.policy(o.accept); e != nil {
			return 2, e
		}
		b.Policy = Policy
		return a.runBatch(ctx, b, o)
	case "batch":
		if len(args) != 3 {
			return 2, errors.New("use batch status|resume|export BATCH_ID")
		}
		b, e := batch.Load(a.Dir, args[2])
		if e != nil {
			return 2, e
		}
		if b.Endpoint != a.Client.Endpoint {
			return 2, errors.New("batch endpoint mismatch")
		}
		switch args[1] {
		case "status", "export":
			w, e := destination(o, a.Out)
			if e != nil {
				return 2, e
			}
			defer w.Close()
			return 0, output.Write(w, b, o.format)
		case "resume":
			if b.Policy != Policy {
				if e = a.policy(o.accept); e != nil {
					return 2, e
				}
				b.Policy = Policy
			}
			return a.runBatch(ctx, b, o)
		}
		return 2, errors.New("unknown batch command")
	case "report", "claim", "delete":
		if len(args) != 2 || !api.ValidID(args[1]) {
			return 2, errors.New("provide a valid scan ID")
		}
		return a.scanCommand(ctx, args[0], args[1], o)
	}
	return 2, errors.New("unknown command; run aifakescan help")
}
func (a *App) policy(accept bool) error {
	if accept {
		return nil
	}
	fmt.Fprintln(a.Err, "Files are uploaded unchanged for cloud analysis. Originals and analysis records remain until explicit deletion. Reports expire after 45 minutes; that does not delete media. Service privacy policy applies: https://aifakescan.com/en/privacy")
	f, ok := a.In.(*os.File)
	if !ok {
		return errors.New("use --accept-upload-policy to acknowledge uploads")
	}
	info, e := f.Stat()
	if e != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("non-interactive uploads require --accept-upload-policy")
	}
	fmt.Fprint(a.Err, "Type upload to accept: ")
	line, e := bufio.NewReader(a.In).ReadString('\n')
	if e != nil || strings.TrimSpace(line) != "upload" {
		return errors.New("upload policy was not accepted")
	}
	return nil
}
func (a *App) loadToken(key string) (*api.Token, error) {
	s, e := a.Vault.Get(key)
	if e != nil {
		return nil, e
	}
	var t api.Token
	if json.Unmarshal([]byte(s), &t) != nil {
		return nil, errors.New("invalid stored credential; sign in again")
	}
	return &t, nil
}
func (a *App) saveToken(key string, t *api.Token) error {
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	return a.Vault.Set(key, string(b))
}
func (a *App) identity(ctx context.Context, createGuest bool) (*api.Token, string, error) {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	t, e := a.loadToken("account")
	if e == nil {
		if time.Until(t.ExpiresAt) < 30*time.Second {
			var refreshed api.Token
			_, e = a.Client.Request(ctx, "POST", "/v1/cli/token", "", "", "", map[string]string{"grant_type": "refresh_token", "refresh_token": t.RefreshToken}, &refreshed, false)
			if e != nil {
				return nil, "", e
			}
			if e = refreshed.Validate(true); e != nil {
				return nil, "", e
			}
			if e = a.saveToken("account", &refreshed); e != nil {
				return nil, "", e
			}
			t = &refreshed
		}
		return t, "account", nil
	}
	if !errors.Is(e, store.ErrNotFound) {
		return nil, "", e
	}
	t, e = a.loadToken("guest")
	if e == nil {
		if time.Now().After(t.ExpiresAt) {
			return nil, "", &api.Error{Status: 401, Code: "session_expired"}
		}
		return t, "guest", nil
	}
	if !errors.Is(e, store.ErrNotFound) {
		return nil, "", e
	}
	if !createGuest {
		return nil, "", &api.Error{Status: 401, Code: "auth_required"}
	}
	var g api.Token
	_, e = a.Client.Request(ctx, "POST", "/v1/guest-sessions", "", "", "", map[string]any{}, &g, false)
	if e != nil {
		return nil, "", e
	}
	if e = g.Validate(false); e != nil {
		return nil, "", e
	}
	if e = a.saveToken("guest", &g); e != nil {
		return nil, "", e
	}
	return &g, "guest", nil
}
func (a *App) authCommand(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("use auth login|status|logout|sessions|revoke")
	}
	switch args[0] {
	case "login":
		if len(args) != 1 {
			return 2, errors.New("login does not accept credentials or passwords")
		}
		var d api.Device
		_, e := a.Client.Request(ctx, "POST", "/v1/cli/device-authorizations", "", "", "", map[string]string{"device_name": "AIFakeScan CLI"}, &d, false)
		if e != nil {
			return api.Exit(e), e
		}
		u, e := url.Parse(d.VerificationURI)
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" || (u.Host != "aifakescan.com" && u.Host != "www.aifakescan.com") || d.DeviceCode == "" || d.ExpiresIn <= 0 || d.ExpiresIn > 1800 || d.Interval < 1 || d.Interval > 60 {
			return 6, errors.New("invalid device authorization response")
		}
		fmt.Fprintf(a.Err, "Open %s\nEnter code: %s\nApprove only the device you requested. This CLI does not open a browser.\n", d.VerificationURI, output.Safe(d.UserCode))
		deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
		interval := time.Duration(d.Interval) * time.Second
		for time.Now().Before(deadline) {
			if e = api.Pause(ctx, interval); e != nil {
				return api.Exit(e), e
			}
			var t api.Token
			_, e = a.Client.Request(ctx, "POST", "/v1/cli/token", "", "", "", map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": d.DeviceCode}, &t, false)
			if e != nil {
				switch api.Code(e) {
				case "authorization_pending":
					continue
				case "slow_down":
					interval += 5 * time.Second
					continue
				}
				return api.Exit(e), e
			}
			if e = t.Validate(true); e != nil {
				return 6, e
			}
			if e = a.saveToken("account", &t); e != nil {
				return 6, e
			}
			fmt.Fprintln(a.Out, "Signed in. Standard scans remain free within server safety limits.")
			return 0, nil
		}
		return 3, &api.Error{Status: 401, Code: "expired_token"}
	case "status":
		t, e := a.loadToken("account")
		if errors.Is(e, store.ErrNotFound) {
			fmt.Fprintln(a.Out, "Not signed in. Guests have up to 3 scans per UTC day, shared by network.")
			return 0, nil
		}
		if e != nil {
			return 3, e
		}
		t, _, e = a.identity(ctx, false)
		if e != nil {
			return api.Exit(e), e
		}
		var q api.Quota
		if _, e = a.Client.Request(ctx, "GET", "/v1/quota", t.AccessToken, "", "", nil, &q, true); e != nil {
			return api.Exit(e), e
		}
		fmt.Fprintf(a.Out, "Account session: %s\nAccess expires: %s\n", output.Safe(t.SessionID), t.ExpiresAt.Local().Format(time.RFC3339))
		return 0, nil
	case "logout":
		return a.logout(ctx)
	case "sessions", "revoke":
		t, kind, e := a.identity(ctx, false)
		if e != nil {
			return api.Exit(e), e
		}
		if kind != "account" {
			return 3, errors.New("sign in to manage account sessions")
		}
		if args[0] == "revoke" {
			if len(args) != 2 || !api.ValidID(args[1]) {
				return 2, errors.New("provide a valid session ID")
			}
			_, e = a.Client.Request(ctx, "DELETE", "/v1/cli/sessions/"+args[1], t.AccessToken, "", "", nil, nil, true)
			if e == nil && args[1] == t.SessionID {
				e = a.Vault.Delete("account")
			}
			return api.Exit(e), e
		}
		var sessions struct {
			Sessions []struct {
				ID         string  `json:"id"`
				DeviceName string  `json:"device_name"`
				CreatedAt  string  `json:"created_at"`
				ExpiresAt  string  `json:"expires_at"`
				RevokedAt  *string `json:"revoked_at"`
			} `json:"sessions"`
		}
		_, e = a.Client.Request(ctx, "GET", "/v1/cli/sessions", t.AccessToken, "", "", nil, &sessions, true)
		if e != nil {
			return api.Exit(e), e
		}
		return 0, json.NewEncoder(a.Out).Encode(sessions)
	}
	return 2, errors.New("unknown auth command")
}

const help = `AIFakeScan CLI — cloud checks for AI-generation and provenance evidence

Usage:
  aifakescan scan FILE... [--recursive] [--dry-run] [--limit N]
    [--accept-upload-policy] [--concurrency 1|2] [--format table|jsonl|csv]
    [--output FILE] [--overwrite]
  aifakescan auth login|status|logout|sessions
  aifakescan auth revoke SESSION_ID
  aifakescan capabilities | quota
  aifakescan batch status|resume|export BATCH_ID
  aifakescan report SCAN_ID [--format json]
  aifakescan claim SCAN_ID
  aifakescan delete SCAN_ID [--wait]
  aifakescan version

Global: --state-dir DIR --credential-file PATH --timeout 20m
Development: --test-mode --endpoint http://127.0.0.1:PORT (isolated credentials)
Use -- before paths beginning with a dash. No credentials are accepted in arguments.
Guests: 3/day shared by network. Login: free with server abuse limits. No billing.
Cloud originals remain until explicit deletion. No result proves authenticity.
`

func (a *App) logout(ctx context.Context) (int, error) {
	_, err := a.loadToken("account")
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintln(a.Out, "Already signed out; guest credentials retained.")
		return 0, nil
	}
	if err != nil {
		return 6, err
	}
	token, kind, err := a.identity(ctx, false)
	if err == nil && kind == "account" {
		_, err = a.Client.Request(ctx, "POST", "/v1/cli/logout", token.AccessToken, "", "", map[string]any{}, nil, false)
	}
	invalid := false
	if err != nil {
		var serviceErr *api.Error
		if errors.As(err, &serviceErr) && (serviceErr.Status == 401 || serviceErr.Code == "invalid_grant" || serviceErr.Code == "invalid_token" || serviceErr.Code == "session_expired" || serviceErr.Code == "refresh_reuse_detected") {
			invalid = true
		} else {
			return api.Exit(err), errors.New("remote logout was not confirmed; local credentials retained; retry logout when the service is available")
		}
	}
	if err = a.Vault.Delete("account"); err != nil {
		return 6, err
	}
	if invalid {
		fmt.Fprintln(a.Out, "Removed invalid local account credentials; the server rejected this session. Guest scan credentials retained for deletion.")
	} else {
		fmt.Fprintln(a.Out, "Signed out; guest scan credentials retained for deletion.")
	}
	return 0, nil
}
