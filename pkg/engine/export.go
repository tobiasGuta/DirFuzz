package engine

// ReportExporter defines standardized data emission contracts for enterprise tooling.
type ReportExporter interface {
	ExportFindingsJSON(findings []Finding) error
	ExportSARIF(findings []Finding) error
	ExportMarkdownReport(findings []Finding) error
}
