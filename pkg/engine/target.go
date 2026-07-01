package engine

import "time"

type Target struct {
	ID        string
	Host      string
	Scheme    string
	Scope     ScopeDecision
	CreatedAt time.Time
}
