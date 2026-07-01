package viewmodel

type ReportQueueItem struct {
	FindingID string
	Title     string
	Status    string // Draft, Ready, Frozen, Exported
	Evidence  int    // Number of steps
	Export    string // SARIF, Markdown, JSON
}

type ReportQueueView struct {
	Items []ReportQueueItem
}
