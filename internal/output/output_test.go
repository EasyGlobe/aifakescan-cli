package output

import (
	"bytes"
	"encoding/json"
	"github.com/EasyGlobe/aifakescan-cli/internal/api"
	"github.com/EasyGlobe/aifakescan-cli/internal/batch"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeOutputsPreserveUncertainty(t *testing.T) {
	b := batch.New("", []*batch.Item{{Name: "=SUM(A1)\x1b.png", Path: "/private/secret/photo.png", Key: "private_idempotency", State: "complete", Report: &api.Report{Status: "complete", Result: &api.Result{Verdict: "inconclusive", Limitations: []string{"not calibrated"}, Coverage: api.Coverage{AIAudio: "not_tested"}}}}})
	for _, format := range []string{"jsonl", "csv", "table"} {
		var out bytes.Buffer
		if e := Write(&out, b, format); e != nil {
			t.Fatal(e)
		}
		s := out.String()
		for _, private := range []string{"/private/secret", "private_idempotency", "\x1b"} {
			if strings.Contains(s, private) {
				t.Fatal("private or terminal data leaked")
			}
		}
		if !strings.Contains(s, "not calibrated") || !strings.Contains(s, "not_tested") {
			t.Fatal("limits lost")
		}
		if format == "jsonl" {
			lines := strings.Split(strings.TrimSpace(s), "\n")
			if len(lines) != 2 || !json.Valid([]byte(lines[1])) {
				t.Fatal("invalid jsonl")
			}
		}
		if CSVCell("  =2+2")[0] != '\'' {
			t.Fatal("formula not escaped")
		}
	}
}
func TestNoImplicitOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.csv")
	os.WriteFile(p, []byte("original"), 0600)
	if _, e := Destination(p, false); e == nil {
		t.Fatal("overwrote output")
	}
	s, _ := os.ReadFile(p)
	if string(s) != "original" {
		t.Fatal("output changed")
	}
}
