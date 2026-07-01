package playbook

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
)

type TriggerRule struct {
	Event     engine.GraphEventType
	Condition map[string]string // e.g. {"status": "403"}
}

type PlaybookAction struct {
	Suggest models.ValidationType
}

type Playbook struct {
	ID          string
	Version     int
	Name        string
	Description string
	Triggers    []TriggerRule
	Actions     []PlaybookAction
	Enabled     bool
}
