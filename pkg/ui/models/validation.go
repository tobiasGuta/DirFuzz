package models

import "time"

type ValidationType string
type ValidationPhase string
type ValidationStatus string

const (
	ValidateAuthBoundary ValidationType = "AUTH_BOUNDARY"
	ValidateParameter    ValidationType = "PARAMETER"
	ValidateMethod       ValidationType = "METHOD"
	ValidateExposure     ValidationType = "EXPOSURE"
)

const (
	ValidationRequested ValidationPhase = "REQUESTED"
	ValidationStarted   ValidationPhase = "STARTED"
	ValidationObserved  ValidationPhase = "OBSERVED"
	ValidationCompleted ValidationPhase = "COMPLETED"
)

const (
	StatusPending   ValidationStatus = "PENDING"
	StatusRunning   ValidationStatus = "RUNNING"
	StatusCompleted ValidationStatus = "COMPLETED"
	StatusFailed    ValidationStatus = "FAILED"
)

type ValidationEvent struct {
	ID            string
	RequestID     string
	FindingID     string
	Type          ValidationType
	Phase         ValidationPhase
	Timestamp     time.Time
	ResultSummary string
	EvidenceHash  string
}

type ValidationRequest struct {
	ID        string
	FindingID string
	NodeID    string
	Type      ValidationType
	Reason    string
	CreatedAt time.Time
	Status    ValidationStatus
	DedupKey  string
}
