package exporter

import (
	"dirfuzz/pkg/report"
	"encoding/json"
)

type JSONExporter struct{}

func (e *JSONExporter) Export(artifact report.ReportArtifact) ([]byte, error) {
	return json.MarshalIndent(artifact, "", "  ")
}
