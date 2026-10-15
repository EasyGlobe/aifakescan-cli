package output

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/EasyGlobe/aifakescan-cli/internal/batch"
)

type Row struct {
	SchemaVersion      string   `json:"schema_version"`
	Type               string   `json:"type"`
	File               string   `json:"file"`
	ScanID             string   `json:"scan_id,omitempty"`
	Status             string   `json:"status"`
	Verdict            string   `json:"verdict,omitempty"`
	AuthenticityProven bool     `json:"authenticity_proven"`
	Probability        any      `json:"probability"`
	Coverage           any      `json:"coverage,omitempty"`
	Limitations        []string `json:"limitations,omitempty"`
	Evidence           any      `json:"evidence,omitempty"`
	DecisionReasons    []string `json:"decision_reasons,omitempty"`
	ScanDepth          string   `json:"scan_depth,omitempty"`
	Error              string   `json:"error_code,omitempty"`
	ExpiresAt          string   `json:"report_expires_at,omitempty"`
	Retention          string   `json:"media_retention"`
}
type Summary struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	BatchID       string `json:"batch_id"`
	Completed     int    `json:"completed"`
	Failed        int    `json:"failed"`
	Waiting       int    `json:"waiting"`
}

func Safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func CSVCell(s string) string {
	s = Safe(s)
	t := strings.TrimLeft(s, " ")
	if t != "" && strings.ContainsRune("=+-@", rune(t[0])) {
		return "'" + s
	}
	return s
}
func Rows(b *batch.Batch) ([]Row, Summary) {
	s := Summary{SchemaVersion: "1", Type: "summary", BatchID: b.ID}
	rows := []Row{}
	for _, it := range b.Items {
		r := Row{SchemaVersion: "1", Type: "result", File: Safe(it.Name), ScanID: it.ScanID, Status: it.State, Error: it.Error, Retention: "until_explicit_deletion"}
		if it.Report != nil {
			r.ExpiresAt = it.Report.ExpiresAt
			if it.Report.Result != nil {
				r.Verdict = it.Report.Result.Verdict
				r.Coverage = it.Report.Result.Coverage
				r.Limitations = it.Report.Result.Limitations
				r.Evidence = it.Report.Result.Evidence
				r.DecisionReasons = it.Report.Result.DecisionReasons
				r.ScanDepth = it.Report.Result.ScanDepth
			}
		}
		switch it.State {
		case "complete":
			s.Completed++
		case "failed", "expired":
			s.Failed++
		default:
			s.Waiting++
		}
		rows = append(rows, r)
	}
	return rows, s
}
func Write(w io.Writer, b *batch.Batch, format string) error {
	rows, sum := Rows(b)
	switch format {
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, r := range rows {
			if e := enc.Encode(r); e != nil {
				return e
			}
		}
		return enc.Encode(sum)
	case "json":
		return json.NewEncoder(w).Encode(struct {
			Results []Row   `json:"results"`
			Summary Summary `json:"summary"`
		}{rows, sum})
	case "csv":
		c := csv.NewWriter(w)
		if e := c.Write([]string{"file", "scan_id", "status", "verdict", "authenticity_proven", "coverage", "limitations", "error_code", "report_expires_at", "media_retention"}); e != nil {
			return e
		}
		for _, r := range rows {
			cov, _ := json.Marshal(r.Coverage)
			lim, _ := json.Marshal(r.Limitations)
			cells := []string{r.File, r.ScanID, r.Status, r.Verdict, "false", string(cov), string(lim), r.Error, r.ExpiresAt, r.Retention}
			for i := range cells {
				cells[i] = CSVCell(cells[i])
			}
			if e := c.Write(cells); e != nil {
				return e
			}
		}
		c.Flush()
		return c.Error()
	case "table":
		for _, r := range rows {
			if _, e := fmt.Fprintf(w, "%s\t%s\t%s\n", r.File, Safe(r.Status), Safe(r.Verdict)); e != nil {
				return e
			}
			for _, l := range r.Limitations {
				fmt.Fprintf(w, "  %s\n", Safe(l))
			}
			if r.Coverage != nil {
				cov, _ := json.Marshal(r.Coverage)
				fmt.Fprintf(w, "  Coverage: %s\n", Safe(string(cov)))
			}
			if r.Error != "" {
				fmt.Fprintf(w, "  %s\n", Safe(r.Error))
			}
		}
		_, e := fmt.Fprintf(w, "%d completed · %d failed · %d waiting\nBatch: %s\n", sum.Completed, sum.Failed, sum.Waiting, sum.BatchID)
		return e
	}
	return errors.New("format must be table, json, jsonl, or csv")
}
func Destination(path string, overwrite bool) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopCloser{os.Stdout}, nil
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		if s, e := os.Lstat(path); e == nil && !s.Mode().IsRegular() {
			return nil, errors.New("output must be a regular file")
		}
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, e := os.OpenFile(path, flags, 0600)
	if e != nil {
		return nil, errors.New("cannot create output; use --overwrite to replace an existing file")
	}
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
