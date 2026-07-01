package tui

import (
	"dirfuzz/pkg/ui"
	"dirfuzz/pkg/ui/adapter"
	tea "github.com/charmbracelet/bubbletea"
	"time"
)

type TickMsg time.Time
type DirtyMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*250, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// EngineEventReceiver is a mock hook. Real EventBus would send DirtyMsg to the BubbleTea program.
func EngineEventReceiver(p *tea.Program) {
	p.Send(DirtyMsg{})
}

// ProcessTick handles backpressure logic
func (m Model) ProcessTick(provider ui.SnapshotProvider, snapAdapter *adapter.SnapshotAdapter) (Model, tea.Cmd) {
	if m.ui.Dirty {
		// Fetch the latest explicitly
		result := provider.Latest()

		// Diff version check
		if result.Version > m.dashboardVersion {
			m.dashboardVersion = result.Version
			presModel := snapAdapter.Convert(result.Snapshot)
			
			// Build views
			m.dashboard = m.presenter.Dashboard.Dashboard(presModel, m.presenterCtx)
			m.ui.Dirty = false
		}
	}

	return m, tickCmd()
}
