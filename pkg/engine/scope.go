package engine

import "time"

type ScopeDecision struct {
	Allowed   bool
	Reason    string
	Rule      string
	CheckedAt time.Time
}

type ScopeEvent struct {
	TargetID string
	Host     string
	Path     string
	Decision string
	Reason   string
}

type ScopeAuditLog struct {
	Events []ScopeEvent
}

// Log records a rejected scope evaluation.
func (l *ScopeAuditLog) Log(target, host, path, decision, reason string) {
	l.Events = append(l.Events, ScopeEvent{
		TargetID: target,
		Host:     host,
		Path:     path,
		Decision: decision,
		Reason:   reason,
	})
}
