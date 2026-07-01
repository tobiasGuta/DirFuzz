package engine

import (
	"fmt"
	"time"
)
type FindingStatus string

const (
	FindingNew       FindingStatus = "new"
	FindingReview    FindingStatus = "review"
	FindingConfirmed FindingStatus = "confirmed"
	FindingRejected  FindingStatus = "rejected"
	FindingDuplicate FindingStatus = "duplicate"
	FindingFixed     FindingStatus = "fixed"
)

type FindingTag string

const (
	TagAuth     FindingTag = "auth"
	TagIDOR     FindingTag = "idor"
	TagExposure FindingTag = "exposure"
	TagConfig   FindingTag = "config"
	TagAPI      FindingTag = "api"
)

type AnalystNote struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"created_at"`
	Text      string    `json:"text"`
}

type FindingSnapshot struct {
	CreatedAt time.Time     `json:"created_at"`
	Score     FindingScore  `json:"score"`
	Evidence  EvidenceChain `json:"evidence"`
}

type ScoreReason struct {
	Factor string `json:"factor"`
	Points int    `json:"points"`
	Reason string `json:"reason"`
}

type FindingScore struct {
	Confidence  int           `json:"confidence"`
	Impact      int           `json:"impact"`
	Reliability int           `json:"reliability"`
	FinalScore  int           `json:"final_score"`
	Reasons     []ScoreReason `json:"reasons"`
}

type EvidenceStep struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Data      string    `json:"data"`
}

type EvidenceEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	DataHash  string    `json:"data_hash"`
}

type EvidenceChain struct {
	ID           string          `json:"id"`
	SourceNodeID string          `json:"source_node_id"`
	Steps        []EvidenceStep  `json:"steps"`
	Entries      []EvidenceEntry `json:"entries"` // append-only hashed logs
}

type FindingFingerprint struct {
	Host              string `json:"host"`
	PathPattern       string `json:"path_pattern"`
	VulnerabilityType string `json:"vulnerability_type"`
	Parameter         string `json:"parameter"`
}

type AnalystAction interface {
	AddNote(findingID, text string) error
	UpdateStatus(findingID string, next FindingStatus) error
	AddTag(findingID string, tag FindingTag) error
}

type Finding struct {
	ID          string             `json:"id"`
	NodeID      string             `json:"node_id"`
	DedupKey    string             `json:"dedup_key"`
	Fingerprint FindingFingerprint `json:"fingerprint"`
	Title       string             `json:"title"`
	Severity    string             `json:"severity"`
	Score       FindingScore       `json:"score"`
	Status      FindingStatus      `json:"status"`
	Tags        []FindingTag       `json:"tags"`
	Chain       EvidenceChain      `json:"chain"`
	Notes       []AnalystNote      `json:"notes"`
	Snapshots   []FindingSnapshot  `json:"snapshots"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
}

func (f *Finding) Transition(next FindingStatus) error {
	switch f.Status {
	case FindingNew, FindingReview:
		if next != FindingConfirmed && next != FindingRejected {
			return fmt.Errorf("invalid transition from %s to %s", f.Status, next)
		}
	case FindingConfirmed:
		if next != FindingFixed && next != FindingDuplicate {
			return fmt.Errorf("invalid transition from %s to %s", f.Status, next)
		}
	case FindingDuplicate:
		if next != FindingReview {
			return fmt.Errorf("invalid transition from %s to %s", f.Status, next)
		}
	case FindingFixed, FindingRejected:
		return fmt.Errorf("terminal state %s cannot transition to %s", f.Status, next)
	}

	f.Status = next
	return nil
}

// GenerateDedupKey explicitly calculates a deterministic identifier to merge related endpoints.
func GenerateDedupKey(target, endpoint, vulnType, parameter string) string {
	// e.g. target="api.ex.com" endpoint="/users/{id}" vuln="Possible IDOR"
	raw := target + "|" + endpoint + "|" + vulnType + "|" + parameter
	return raw // Simplified for Phase 5.6 demonstration; could be SHA256(raw)
}
