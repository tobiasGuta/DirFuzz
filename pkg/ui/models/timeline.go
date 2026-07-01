package models

import "time"

type EventCategory string

const (
	CategoryDiscovery  EventCategory = "DISCOVERY"
	CategoryTarget     EventCategory = "TARGET"
	CategoryFinding    EventCategory = "FINDING"
	CategoryValidation EventCategory = "VALIDATION"
)

type TimelineEvent struct {
	ID        string
	Timestamp time.Time
	Category  EventCategory
	Title     string
	Detail    string
	NodeID    string
	FindingID string
	Actor     string
	Source    string
	Sequence  uint64
}

type TimelineGroup struct {
	StartSequence uint64
	EndSequence   uint64
	Count         int
	Summary       string
}
