// local.go — a ResultSink that writes the Report and its projections to a local
// directory. This is the portable, host-agnostic sink the dogfood CLI uses.
package resultsink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Default artifact filenames written by Local. They are stable so downstream
// tooling (and the operator) can find them by name.
const (
	// FileReportJSON is the canonical Report serialized as JSON.
	FileReportJSON = "report.json"
	// FileOpenVEX is the OpenVEX document.
	FileOpenVEX = "openvex.json"
	// FileSARIF is the SARIF 2.1.0 log.
	FileSARIF = "report.sarif.json"
	// FileReportHTML is the self-contained, file://-safe HTML report.
	FileReportHTML = "report.html"
)

// Local is a ResultSink that writes the Report (as JSON) and every non-empty
// projection into Dir. It is deterministic and offline — no network, no platform
// dependency — which makes it the dogfood/CLI sink and the test sink.
type Local struct {
	// Dir is the output directory. It is created (with parents) on Publish if absent.
	Dir string
	// Perm is the file mode for written artifacts. Zero defaults to 0o644.
	Perm os.FileMode
}

// NewLocal returns a Local sink writing to dir.
func NewLocal(dir string) *Local { return &Local{Dir: dir} }

// Publish writes report.json plus each present projection into l.Dir, creating the
// directory if needed. It returns the first write error encountered.
func (l *Local) Publish(_ context.Context, res Result) error {
	if l.Dir == "" {
		return fmt.Errorf("resultsink/local: Dir is empty")
	}
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		return fmt.Errorf("resultsink/local: create dir: %w", err)
	}

	reportJSON, err := json.MarshalIndent(res.Report, "", "  ")
	if err != nil {
		return fmt.Errorf("resultsink/local: marshal report: %w", err)
	}
	if err := l.write(FileReportJSON, reportJSON); err != nil {
		return err
	}

	for name, data := range map[string][]byte{
		FileOpenVEX:    res.Projections.OpenVEX,
		FileSARIF:      res.Projections.SARIF,
		FileReportHTML: res.Projections.HTML,
	} {
		if len(data) == 0 {
			continue
		}
		if err := l.write(name, data); err != nil {
			return err
		}
	}
	return nil
}

func (l *Local) write(name string, data []byte) error {
	perm := l.Perm
	if perm == 0 {
		perm = 0o644
	}
	path := filepath.Join(l.Dir, name)
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("resultsink/local: write %s: %w", name, err)
	}
	return nil
}
