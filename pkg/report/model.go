package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

type Step struct {
	Order       int
	Description string
	Action      string
}

type EvidenceItem struct {
	ID       string
	Summary  string
	Hash     string
	SourceID string
}

type ArtifactStatus int

const (
	ArtifactDraft ArtifactStatus = iota
	ArtifactReady
	ArtifactFrozen
	ArtifactExported
)

type ReportArtifact struct {
	ID           string
	FindingID    string
	Title        string
	Severity     string
	Summary      string
	Impact       string
	Reproduction []Step
	Evidence     []EvidenceItem
	Target       string
	CreatedAt    time.Time
	Status       ArtifactStatus
	Hash         string
	Version      uint64
}

func (a *ReportArtifact) Transition(next ArtifactStatus) error {
	// Simple forward-only logic for this state machine
	if next <= a.Status {
		return fmt.Errorf("invalid transition from %v to %v", a.Status, next)
	}
	a.Status = next
	return nil
}

// ComputeHash computes a stable deterministic SHA-256 hash
func (a *ReportArtifact) ComputeHash() string {
	// Create a stable copy without the Hash, Version, and CreatedAt for computation
	stable := *a
	stable.Hash = ""
	stable.Version = 0
	stable.CreatedAt = time.Time{}
	
	bytes, _ := json.Marshal(stable)
	return fmt.Sprintf("%x", sha256.Sum256(bytes))
}
