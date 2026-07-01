package exporter

import (
	"dirfuzz/pkg/report"
	"dirfuzz/pkg/report/mapper"
	"encoding/json"
)

type SARIFExporter struct{}

func (e *SARIFExporter) Export(artifact report.ReportArtifact) ([]byte, error) {
	doc := mapper.MapToSARIF(artifact)
	return json.MarshalIndent(doc, "", "  ")
}
