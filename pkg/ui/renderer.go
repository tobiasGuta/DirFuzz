package ui

import "dirfuzz/pkg/ui/viewmodel"

// Renderer explicitly defines how a viewmodel is drawn.
// This interface allows both the TUI (Bubble Tea) and a future Web API to render the exact same intelligence.
type Renderer interface {
	RenderDashboard(view viewmodel.DashboardView) string
	RenderFindings(page viewmodel.FindingsPage) string
}
