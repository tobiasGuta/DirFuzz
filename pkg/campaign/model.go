package campaign

type EvidenceProjection struct {
	Path        string
	StatusCode  int
	ContentType string
	Size        int64
	Confidence  int
	RiskScore   int
	Tags        []string
	Hash        string
}

type ChangeReasonType string

const (
	StatusChanged ChangeReasonType = "STATUS_CHANGED"
	AuthChanged   ChangeReasonType = "AUTH_CHANGED"
	SizeChanged   ChangeReasonType = "SIZE_CHANGED"
	NewFinding    ChangeReasonType = "NEW_FINDING"
)

type ChangeReason struct {
	Type   ChangeReasonType
	Before string
	After  string
}

type DiffCategory string

const (
	DiffNew     DiffCategory = "NEW"
	DiffChanged DiffCategory = "CHANGED"
	DiffRemoved DiffCategory = "REMOVED"
)

type DiffSeverity string

const (
	DiffInfo        DiffSeverity = "INFO"
	DiffInteresting DiffSeverity = "INTERESTING"
	DiffCritical    DiffSeverity = "CRITICAL"
)

type DiffFingerprint struct {
	TargetID  string
	ScopeHash string
	OldHash   string
	NewHash   string
	DiffHash  string
}


type EndpointDiff struct {
	NodeID      string
	Path        string
	Category    DiffCategory
	Severity    DiffSeverity
	Fingerprint DiffFingerprint
	Reasons     []ChangeReason
	Previous    EvidenceProjection
	Current     EvidenceProjection
}
