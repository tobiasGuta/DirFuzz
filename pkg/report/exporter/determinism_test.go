package exporter

import (
	"crypto/sha256"
	"dirfuzz/pkg/report"
	"fmt"
	"testing"
)

func TestExportDeterminism(t *testing.T) {
	artifact := report.ReportArtifact{
		ID:        "rep-123",
		FindingID: "f-456",
		Title:     "Critical IDOR",
		Severity:  "HIGH",
		Summary:   "Found an IDOR vulnerability.",
		Impact:    "Data leak.",
		Target:    "api.example.com",
		Hash:      "abc",
		Reproduction: []report.Step{
			{Order: 1, Description: "Login", Action: "POST /login"},
			{Order: 2, Description: "Access user 2", Action: "GET /user/2"},
		},
		Evidence: []report.EvidenceItem{
			{ID: "ev-1", Summary: "Request", Hash: "req-hash", SourceID: "src-1"},
			{ID: "ev-2", Summary: "Response", Hash: "res-hash", SourceID: "src-2"},
		},
	}

	jsonExp := &JSONExporter{}
	mdExp := &MarkdownExporter{}

	// JSON
	b1, err := jsonExp.Export(artifact)
	if err != nil {
		t.Fatalf("JSON export failed: %v", err)
	}
	b2, _ := jsonExp.Export(artifact)
	
	hash1 := fmt.Sprintf("%x", sha256.Sum256(b1))
	hash2 := fmt.Sprintf("%x", sha256.Sum256(b2))
	if hash1 != hash2 {
		t.Errorf("JSON Exporter is not deterministic: %s != %s", hash1, hash2)
	}

	// Markdown
	b3, err := mdExp.Export(artifact)
	if err != nil {
		t.Fatalf("Markdown export failed: %v", err)
	}
	b4, _ := mdExp.Export(artifact)

	hash3 := fmt.Sprintf("%x", sha256.Sum256(b3))
	hash4 := fmt.Sprintf("%x", sha256.Sum256(b4))
	if hash3 != hash4 {
		t.Errorf("Markdown Exporter is not deterministic: %s != %s", hash3, hash4)
	}
}
