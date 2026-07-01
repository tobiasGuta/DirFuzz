package viewmodel

type EvidenceType int

const (
	EvidenceSource EvidenceType = iota
	EvidenceDiscovery
	EvidenceRequest
	EvidenceResponse
	EvidenceValidation
)

type EvidenceTimelineItem struct {
	Timestamp  string
	Type       EvidenceType
	Title      string
	Detail     string
	Source     string
	Confidence int
}

type EvidenceView struct {
	FindingID   string
	Timeline    []EvidenceTimelineItem
	OriginChain []string
	Summary     string
}

type FindingDetailView struct {
	FindingID  string
	Title      string
	Severity   SeverityStyle
	Score      int
	Confidence string
	Evidence   EvidenceView
	Readiness  ReportReadiness
}
