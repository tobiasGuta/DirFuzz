package campaign

import (
	"dirfuzz/pkg/engine"
	"time"
)

type CampaignDiffEvent struct {
	OldSnapshot string
	NewSnapshot string
	DiffID      string
	CreatedAt   time.Time
}

type RegressionType string

const (
	RegressionAuth     RegressionType = "AUTH"
	RegressionExposure RegressionType = "EXPOSURE"
	RegressionBehavior RegressionType = "BEHAVIOR"
)

type RegressionEvent struct {
	ID             string
	FindingID      string
	Type           RegressionType
	PreviousStatus engine.FindingStatus
	CurrentStatus  engine.FindingStatus
	EvidenceRefs   []string
	Confidence     int
	Reason         string
}

type SubmissionStatus string
type SubmissionReason string

const (
	StatusAccepted      SubmissionStatus = "ACCEPTED"
	StatusDuplicate     SubmissionStatus = "DUPLICATE"
	StatusInformative   SubmissionStatus = "INFORMATIVE"
	StatusNotApplicable SubmissionStatus = "NOT_APPLICABLE"
)

const (
	ReasonVulnerable    SubmissionReason = "VULNERABLE"
	ReasonFalsePositive SubmissionReason = "FALSE_POSITIVE"
	ReasonOutOfScope    SubmissionReason = "OUT_OF_SCOPE"
	ReasonDuplicate     SubmissionReason = "DUPLICATE_KNOWN"
	ReasonPolicy        SubmissionReason = "POLICY"
)

type SubmissionCreatedEvent struct {
	SubmissionID string
	FindingID    string
	Platform     string
	SubmittedAt  time.Time
}

type SubmissionResolvedEvent struct {
	SubmissionID string
	FindingID    string
	Status       SubmissionStatus
	Reason       SubmissionReason
	Confidence   int
	ResolvedAt   time.Time
}
