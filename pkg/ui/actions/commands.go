package actions

import "time"

type AnalystAction int

const (
	ActionConfirm AnalystAction = iota
	ActionReject
	ActionDuplicate
	ActionAddNote
	ActionExport
)

type AnalystCommand struct {
	ID        string
	Action    AnalystAction
	CreatedAt time.Time
	Actor     string
	Reason    string
	Payload   string
}

type ExportFormat string

const (
	FormatMarkdown ExportFormat = "markdown"
	FormatJSON     ExportFormat = "json"
	FormatSARIF    ExportFormat = "sarif"
)

type ExportCommand struct {
	FindingID string
	Format    ExportFormat
}

type ValidationCommand struct {
	NodeID     string
	Validation string // Maps to models.ValidationType
	Priority   int
}
