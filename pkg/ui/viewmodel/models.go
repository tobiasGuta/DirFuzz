package viewmodel

type SeverityStyle int

const (
	StyleCritical SeverityStyle = iota
	StyleHigh
	StyleMedium
	StyleLow
	StyleInfo
)

type FindingView struct {
	ID          string
	Title       string
	Severity    string
	Score       int
	Style       SeverityStyle
	ShortReason string
	Tags        []string
}

type MetricsWidget struct {
	Workers       int
	Requests      int
	TotalFindings int
	Confirmed     int
}

type QueueWidget struct {
	Validation int
	ParamFuzz  int
	Discovery  int
}

type TimelineEntry struct {
	Time    string
	Message string
}

type TimelineWidget struct {
	Entries []TimelineEntry
}

type DashboardView struct {
	Target   string
	Metrics  MetricsWidget
	Queue    QueueWidget
	Timeline TimelineWidget
	TopRisk  []FindingView
}

// FindingsPage handles paginated display of findings
type FindingsPage struct {
	Total  int
	Offset int
	Limit  int
	Items  []FindingView
}
