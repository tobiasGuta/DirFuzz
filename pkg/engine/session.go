package engine

import "time"

type SessionState string

const (
	SessionCreated SessionState = "created"
	SessionRunning SessionState = "running"
	SessionPaused  SessionState = "paused"
	SessionStopped SessionState = "stopped"
	SessionFailed  SessionState = "failed"
)

type ScanMode string

const (
	Active  ScanMode = "active"
	Passive ScanMode = "passive"
	DryRun  ScanMode = "dryrun"
)

type ScanSession struct {
	ID        string
	State     SessionState
	Mode      ScanMode
	Targets   []Target
	Graph     *DiscoveryGraph
	Findings  []Finding
	StartedAt time.Time
	UpdatedAt time.Time
}
