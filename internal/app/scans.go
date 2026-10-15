package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/EasyGlobe/aifakescan-cli/internal/api"
	"github.com/EasyGlobe/aifakescan-cli/internal/batch"
	"github.com/EasyGlobe/aifakescan-cli/internal/output"
	"github.com/EasyGlobe/aifakescan-cli/internal/store"
)

func (a *App) runBatch(ctx context.Context, b *batch.Batch, o options) (int, error) {
	// Reserve output before any network/upload, so a bad path never wastes a scan.
	w, e := destination(o, a.Out)
	if e != nil {
		return 2, e
	}
	defer w.Close()
	t, kind, e := a.identity(ctx, true)
	if e != nil {
		return api.Exit(e), e
	}
	var q api.Quota
	_, e = a.Client.Request(ctx, "GET", "/v1/quota", t.AccessToken, "", "", nil, &q, true)
	if e != nil {
		return api.Exit(e), e
	}
	if q.Enabled != nil && !*q.Enabled {
		return 6, &api.Error{Status: 503, Code: "cli_unavailable"}
	}
	slots := o.concurrency
	if kind == "guest" {
		slots = 1
	}
	for _, it := range b.Items {
		if it.Identity == "guest" && it.State != "complete" && it.State != "failed" && it.State != "expired" {
			slots = 1
		}
	}
	if q.MaxInFlight > 0 && q.MaxInFlight < slots {
		slots = q.MaxInFlight
	}
	var total int64
	for _, it := range b.Items {
		total += it.Size
	}
	fmt.Fprintf(a.Err, "%s · %d remaining today · %d files · %d bytes\nCloud processing. Originals remain until explicit deletion.\n", kind, q.Remaining, len(b.Items), total)
	if e = b.Save(a.Dir); e != nil {
		return 6, e
	}
	fmt.Fprintf(a.Err, "Saved batch: %s\n", b.ID)
	var sched sync.Mutex
	var wg sync.WaitGroup
	next := 0
	var blocked error
	video := make(chan struct{}, 1)
	save := func(index int, it *batch.Item) error {
		a.mu.Lock()
		defer a.mu.Unlock()
		copy := *it
		b.Items[index] = &copy
		return b.Save(a.Dir)
	}
	for worker := 0; worker < slots; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				sched.Lock()
				if blocked != nil || next >= len(b.Items) || ctx.Err() != nil {
					sched.Unlock()
					return
				}
				i := next
				next++
				it := *b.Items[i]
				sched.Unlock()
				if it.State == "complete" || it.State == "failed" || it.State == "expired" {
					continue
				}
				if it.Media == "video" {
					select {
					case video <- struct{}{}:
					case <-ctx.Done():
						return
					}
				}
				err := a.process(ctx, &it, func() error { return save(i, &it) })
				if it.Media == "video" {
					<-video
				}
				if err != nil {
					code := api.Exit(err)
					if code == 3 || code == 4 || code == 6 || code == 130 {
						sched.Lock()
						if blocked == nil {
							blocked = err
						}
						sched.Unlock()
					} else {
						it.State = "failed"
						it.Error = api.Code(err)
						if se := save(i, &it); se != nil {
							sched.Lock()
							blocked = se
							sched.Unlock()
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	if e = output.Write(w, b, o.format); e != nil {
		return 6, errors.New("cannot write results; the local batch remains saved")
	}
	if ctx.Err() != nil {
		return api.Exit(ctx.Err()), ctx.Err()
	}
	if blocked != nil {
		if api.Exit(blocked) == 3 {
			fmt.Fprintf(a.Err, "To continue, run:\n  aifakescan auth login\n  aifakescan batch resume %s\n", b.ID)
		} else {
			fmt.Fprintf(a.Err, "After the limit resets or service recovers, run:\n  aifakescan batch resume %s\n", b.ID)
		}
		return api.Exit(blocked), blocked
	}
	_, s := output.Rows(b)
	if s.Failed > 0 {
		return 5, nil
	}
	return 0, nil
}
func (a *App) taskToken(ctx context.Context, it *batch.Item) (string, error) {
	if it.Identity == "guest" {
		t, e := a.loadToken("guest")
		if e != nil {
			return "", e
		}
		if time.Now().After(t.ExpiresAt) {
			return "", &api.Error{Status: 401, Code: "session_expired"}
		}
		return t.AccessToken, nil
	}
	t, kind, e := a.identity(ctx, false)
	if e != nil {
		return "", e
	}
	if it.Identity == "account" && kind != "account" {
		return "", &api.Error{Status: 401, Code: "auth_required"}
	}
	return t.AccessToken, nil
}
func (a *App) process(ctx context.Context, it *batch.Item, save func() error) error {
	var file *os.File
	var e error
	if it.ScanID != "" {
		if marker, err := a.Vault.Get("claimed:" + it.ScanID); err == nil && marker == "account" {
			it.Identity = "account"
			if err = save(); err != nil {
				return err
			}
		}
	}
	// Completed uploads can be queried even after the original local file moves.
	if it.State == "pending" || it.State == "creating" || it.State == "uploading" {
		file, e = batch.OpenVerified(it)
		if e != nil {
			it.State = "failed"
			it.Error = "input_changed_or_unreadable"
			return save()
		}
		defer file.Close()
	}
	if it.Identity == "" {
		_, it.Identity, e = a.identity(ctx, true)
		if e != nil {
			return e
		}
	}
	token := ""
	if it.Identity != "guest" || (it.State != "polling" && it.State != "uploaded") {
		token, e = a.taskToken(ctx, it)
		if e != nil {
			return e
		}
	}
	owner := ""
	if it.ScanID != "" && it.Identity == "guest" {
		owner, e = a.Vault.Get("scan:" + it.ScanID)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return e
		}
	}
	if it.State == "pending" || it.State == "creating" || it.State == "uploading" {
		originalState := it.State
		it.State = "creating"
		if e = save(); e != nil {
			return e
		}
		var created api.Created
		if originalState != "pending" {
			_, e = a.Client.Request(ctx, "POST", "/v1/scans/recover", token, "", "", map[string]string{"idempotency_key": it.Key}, &created, false)
		}
		var ae *api.Error
		if originalState == "pending" || (errors.As(e, &ae) && ae.Status == 404) {
			// Only a definitive original-principal 404 allows an uncreated
			// guest intent to move to the signed-in account. An uncertain
			// response or an existing guest task always keeps its original identity.
			if originalState != "pending" && it.Identity == "guest" {
				current, kind, identityErr := a.identity(ctx, false)
				if identityErr != nil {
					return identityErr
				}
				if kind == "account" {
					it.Identity = "account"
					token = current.AccessToken
					if e = save(); e != nil {
						return e
					}
				}
			}
			body := map[string]any{"filename": filepath.Base(it.Path), "size": it.Size, "content_type": it.MIME, "media_type": it.Media, "mode": "basic", "analysis_profile": "standard", "sha256": it.SHA256}
			_, e = a.Client.Request(ctx, "POST", "/v1/scans", token, "", it.Key, body, &created, false)
			if e != nil && api.Exit(e) == 6 {
				_, recoverErr := a.Client.Request(ctx, "POST", "/v1/scans/recover", token, "", "", map[string]string{"idempotency_key": it.Key}, &created, false)
				if recoverErr == nil {
					e = nil
				}
			}
		}
		if e != nil {
			return e
		}
		if !api.ValidID(created.ScanID) {
			return errors.New("invalid scan response; resume the saved batch")
		}
		if it.Identity == "guest" {
			if created.OwnerToken == "" {
				return errors.New("missing guest ownership credential")
			}
			if e = a.Vault.Set("scan:"+created.ScanID, created.OwnerToken); e != nil {
				return e
			}
			owner = created.OwnerToken
		}
		it.ScanID = created.ScanID
		it.State = "uploading"
		if e = save(); e != nil {
			return e
		}
		if created.UploadURL != "" {
			if e = a.Client.Upload(ctx, created.UploadURL, created.UploadMethod, it.MIME, it.Size, file); e != nil {
				return e
			}
			it.State = "uploaded"
			if e = save(); e != nil {
				return e
			}
		} else {
			it.State = "polling"
			if e = save(); e != nil {
				return e
			}
		}
	}
	if it.State == "uploaded" {
		if it.Identity == "account" {
			token, e = a.taskToken(ctx, it)
			if e != nil {
				return e
			}
		}
		_, e = a.Client.Request(ctx, "POST", "/v1/scans/"+it.ScanID+"/uploaded", token, owner, "", map[string]any{}, nil, true)
		if e != nil {
			return e
		}
		it.State = "polling"
		if e = save(); e != nil {
			return e
		}
	}
	for {
		var report api.Report
		readToken := token
		if it.Identity == "guest" {
			readToken = ""
		} else {
			readToken, e = a.taskToken(ctx, it)
			if e != nil {
				return e
			}
		}
		_, e = a.Client.Request(ctx, "GET", "/v1/scans/"+it.ScanID, readToken, owner, "", nil, &report, true)
		if e != nil {
			if api.Code(e) == "report_expired" {
				it.State = "expired"
				it.Error = "report_expired"
				return save()
			}
			return e
		}
		if report.ID != "" && report.ID != it.ScanID {
			return errors.New("scan response ID mismatch")
		}
		if report.Terminal() {
			if report.Status == "complete" && (report.Result == nil || (report.Result.Verdict != "likely_ai" && report.Result.Verdict != "inconclusive" && report.Result.Verdict != "no_strong_evidence")) {
				return errors.New("invalid completed report")
			}
			it.Report = &report
			it.State = report.Status
			it.Error = report.ErrorCode
			if it.State == "deleted" {
				it.State = "failed"
				it.Error = "scan_deleted"
			}
			return save()
		}
		if e = api.Pause(ctx, 2*time.Second); e != nil {
			return e
		}
	}
}
func (a *App) scanAccess(ctx context.Context, id string) (string, string, error) {
	if marker, err := a.Vault.Get("claimed:" + id); err == nil && marker == "account" {
		t, kind, err := a.identity(ctx, false)
		if err != nil {
			return "", "", err
		}
		if kind != "account" {
			return "", "", &api.Error{Status: 401, Code: "auth_required"}
		}
		return t.AccessToken, "", nil
	}
	owner, e := a.Vault.Get("scan:" + id)
	if e == nil {
		return "", owner, nil
	}
	if !errors.Is(e, store.ErrNotFound) {
		return "", "", e
	}
	t, kind, e := a.identity(ctx, false)
	if e != nil {
		return "", "", e
	}
	if kind != "account" {
		return "", "", &api.Error{Status: 401, Code: "auth_required"}
	}
	return t.AccessToken, "", nil
}
func (a *App) scanCommand(ctx context.Context, command, id string, o options) (int, error) {
	token, owner, e := a.scanAccess(ctx, id)
	if e != nil {
		return api.Exit(e), e
	}
	path := "/v1/scans/" + id
	switch command {
	case "report":
		var r api.Report
		_, e = a.Client.Request(ctx, "GET", path, token, owner, "", nil, &r, true)
		if e != nil {
			return api.Exit(e), e
		}
		b := batch.New(a.Client.Endpoint, []*batch.Item{{Name: id, ScanID: id, State: r.Status, Report: &r}})
		w, e := destination(o, a.Out)
		if e != nil {
			return 2, e
		}
		defer w.Close()
		return 0, output.Write(w, b, o.format)
	case "claim":
		t, kind, e := a.identity(ctx, false)
		if e != nil {
			return api.Exit(e), e
		}
		if kind != "account" || owner == "" {
			return 3, errors.New("claim requires account login and this scan's guest ownership credential")
		}
		_, e = a.Client.Request(ctx, "POST", path+"/claim", t.AccessToken, owner, "", map[string]any{}, nil, false)
		if e != nil {
			return api.Exit(e), e
		}
		if e = a.Vault.Set("claimed:"+id, "account"); e != nil {
			return 6, e
		}
		entries, e := os.ReadDir(a.Dir)
		if e != nil {
			return 6, e
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			batchID := entry.Name()[:len(entry.Name())-5]
			b, err := batch.Load(a.Dir, batchID)
			if err != nil {
				continue
			}
			changed := false
			for _, it := range b.Items {
				if it.ScanID == id {
					it.Identity = "account"
					changed = true
				}
			}
			if changed {
				if e = b.Save(a.Dir); e != nil {
					return 6, e
				}
			}
		}
		if e = a.Vault.Delete("scan:" + id); e != nil {
			return 6, e
		}
		fmt.Fprintln(a.Out, "Scan claimed by the signed-in account; quota is unchanged.")
		return 0, nil
	case "delete":
		for {
			status, e := a.Client.Request(ctx, "DELETE", path, token, owner, "", nil, nil, true)
			if e != nil {
				return api.Exit(e), e
			}
			if status == 204 {
				fmt.Fprintln(a.Out, "Cloud media and analysis deletion confirmed. Local reports remain on this computer.")
				return 0, nil
			}
			if status != 202 {
				return 6, errors.New("unexpected deletion response; deletion is not confirmed")
			}
			if !o.wait {
				fmt.Fprintln(a.Out, "Deletion pending. Credentials retained; use delete --wait to confirm completion.")
				return 0, nil
			}
			if e = api.Pause(ctx, 2*time.Second); e != nil {
				return api.Exit(e), errors.New("deletion remains pending; credentials retained")
			}
		}
	}
	return 2, errors.New("unknown scan command")
}
