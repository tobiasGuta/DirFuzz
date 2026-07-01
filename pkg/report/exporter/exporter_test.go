package exporter

import (
	"dirfuzz/pkg/report"
	"dirfuzz/pkg/ui/viewmodel"
	"strings"
	"testing"
)

func TestExporterParity(t *testing.T) {
	finding := viewmodel.FindingDetailView{
		FindingID:  "idor-123",
		Title:      "IDOR User Details",
		Severity:   viewmodel.StyleHigh,
		Readiness:  viewmodel.ReportReadiness{Ready: true},
		Evidence: viewmodel.EvidenceView{
			Timeline: []viewmodel.EvidenceTimelineItem{
				{Title: "Tested endpoint", Source: "/api/users/1"},
			},
		},
	}

	builder := &report.DefaultBuilder{}
	artifact, _ := builder.Build(finding)

	markdownExporter := &MarkdownExporter{}
	jsonExporter := &JSONExporter{}
	sarifExporter := &SARIFExporter{}

	mdBytes, _ := markdownExporter.Export(artifact)
	jsonBytes, _ := jsonExporter.Export(artifact)
	sarifBytes, _ := sarifExporter.Export(artifact)

	mdStr := string(mdBytes)
	jsonStr := string(jsonBytes)
	sarifStr := string(sarifBytes)

	// Verify all exports maintain the FindingID
	if !strings.Contains(mdStr, "idor-123") {
		t.Fatalf("Markdown missing FindingID")
	}
	if !strings.Contains(jsonStr, "idor-123") {
		t.Fatalf("JSON missing FindingID")
	}
	if !strings.Contains(sarifStr, "idor-123") {
		t.Fatalf("SARIF missing FindingID")
	}

	// Verify all exports maintain Evidence Sources
	if !strings.Contains(mdStr, "Tested endpoint") {
		t.Fatalf("Markdown missing Evidence title")
	}
	if !strings.Contains(jsonStr, "Tested endpoint") {
		t.Fatalf("JSON missing Evidence title")
	}
	if !strings.Contains(sarifStr, "/api/users/1") {
		t.Fatalf("SARIF missing Evidence source URI")
	}
}
