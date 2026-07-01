package exporter

import (
	"bytes"
	"dirfuzz/pkg/report"
	"fmt"
)

type MarkdownExporter struct{}

func (e *MarkdownExporter) Export(artifact report.ReportArtifact) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("# %s\n", artifact.Title))
	buf.WriteString(fmt.Sprintf("**Severity**: %s\n", artifact.Severity))
	buf.WriteString(fmt.Sprintf("**Target**: %s\n", artifact.Target))
	buf.WriteString(fmt.Sprintf("**Finding ID**: %s\n\n", artifact.FindingID))
	buf.WriteString(fmt.Sprintf("## Summary\n%s\n\n", artifact.Summary))
	buf.WriteString(fmt.Sprintf("## Impact\n%s\n\n", artifact.Impact))
	buf.WriteString("## Evidence\n")
	for _, ev := range artifact.Evidence {
		buf.WriteString(fmt.Sprintf("- %s (Hash: %s)\n", ev.Summary, ev.Hash))
	}
	return buf.Bytes(), nil
}
