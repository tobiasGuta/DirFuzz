package exporter

import "dirfuzz/pkg/report"

type Exporter interface {
	Export(artifact report.ReportArtifact) ([]byte, error)
}
