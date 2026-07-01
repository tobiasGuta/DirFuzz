package engine

import "time"

// EngineMetricsSnap holds a frozen point-in-time state of the engine metrics for UI rendering.
type EngineMetricsSnap struct {
	RequestsSent    int64 `json:"requests_sent"`
	NodesDiscovered int64 `json:"nodes_discovered"`
	NodesConfirmed  int64 `json:"nodes_confirmed"`
	FindingsCreated int64 `json:"findings_created"`
	QueueDepth      int64 `json:"queue_depth"`
	WorkerCount     int64 `json:"worker_count"`
	GraphSize       int64 `json:"graph_size"`
}

// AnalystView represents the read-only contract the Engine exposes to the UI layer.
type AnalystView struct {
	Findings   []Finding         `json:"findings"`
	TopTargets []Target          `json:"top_targets"`
	Timeline   []GraphEvent      `json:"timeline"`
	Metrics    EngineMetricsSnap `json:"metrics"`
}

// AnalystSnapshot is an immutable, point-in-time snapshot of the scan state to prevent graph locks during TUI renders.
type AnalystSnapshot struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Version     uint64            `json:"version"`
	Targets     []Target          `json:"targets"`
	Findings    []Finding         `json:"findings"`
	Metrics     EngineMetricsSnap `json:"metrics"`
}

// FindingFilter provides flexible criteria for querying findings.
type FindingFilter struct {
	Status   []FindingStatus
	Tags     []FindingTag
	Severity []string
	TargetID string
}

// AnalystStore defines the strict read-only query boundaries for the UI.
// The UI layer MUST NOT query DiscoveryGraph.Nodes directly.
type AnalystStore interface {
	GetFindings(filter FindingFilter) ([]Finding, error)
	GetTopRiskNodes(limit int) ([]DiscoveryNode, error)
	GetTimeline(start, end time.Time) ([]GraphEvent, error)
	GetAttackSurface(targetID string) (*AnalystView, error)
}
