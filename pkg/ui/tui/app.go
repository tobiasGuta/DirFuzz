package tui

import (
	"dirfuzz/pkg/ui"
	"dirfuzz/pkg/ui/adapter"
	"dirfuzz/pkg/ui/presenter"
	"dirfuzz/pkg/ui/viewmodel"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ExplorerState struct {
	SelectedFindingID string
	ActivePanel       int
	EvidenceCursor    int
	SearchQuery       string
}

type UIState struct {
	CurrentTab        int
	Explorer          ExplorerState
	Scroll            int
	Caps              TerminalCapabilities
	Layout            LayoutMode
	Dirty             bool
}

type Model struct {
	dashboard        viewmodel.DashboardView
	ui               UIState
	presenter        *presenter.PresentationService
	keyMap           KeyMap
	dashboardVersion uint64
	presenterCtx     presenter.PresenterContext
	
	// Providers
	provider    ui.SnapshotProvider
	snapAdapter *adapter.SnapshotAdapter
}

func NewModel(p *presenter.PresentationService, prov ui.SnapshotProvider, adapt *adapter.SnapshotAdapter, ctx presenter.PresenterContext) Model {
	return Model{
		presenter:    p,
		keyMap:       DefaultKeyMap,
		provider:     prov,
		snapAdapter:  adapt,
		presenterCtx: ctx,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keyMap.Quit):
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.ui.Caps = TerminalCapabilities{
			Width:  msg.Width,
			Height: msg.Height,
		}
		m.ui.Layout = DetectLayoutMode(m.ui.Caps)
	case DirtyMsg:
		m.ui.Dirty = true
	case TickMsg:
		if m.provider != nil {
			var cmd tea.Cmd
			m, cmd = m.ProcessTick(m.provider, m.snapAdapter)
			return m, cmd
		}
		return m, tickCmd()
	}
	return m, nil
}

func (m Model) View() string {
	if m.ui.Caps.Width == 0 {
		return "Initializing layout..."
	}

	wMetrics := &MetricsWidget{Data: m.dashboard.Metrics}
	wQueue := &QueueWidget{Data: m.dashboard.Queue}
	wTimeline := &TimelineWidget{Data: m.dashboard.Timeline}

	// Calculate sizes based on LayoutMode
	var content string
	switch m.ui.Layout {
	case LayoutFull:
		leftColWidth := m.ui.Caps.Width / 3
		rightColWidth := m.ui.Caps.Width - leftColWidth
		
		leftCol := lipgloss.JoinVertical(
			lipgloss.Left,
			wMetrics.Render(leftColWidth, m.ui.Caps.Height/2),
			wQueue.Render(leftColWidth, m.ui.Caps.Height/2),
		)
		rightCol := wTimeline.Render(rightColWidth, m.ui.Caps.Height)
		content = lipgloss.JoinHorizontal(lipgloss.Top, leftCol, rightCol)

	case LayoutCompact:
		// Stack them vertically
		h := m.ui.Caps.Height / 3
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			wMetrics.Render(m.ui.Caps.Width, h),
			wQueue.Render(m.ui.Caps.Width, h),
			wTimeline.Render(m.ui.Caps.Width, m.ui.Caps.Height - (2*h)),
		)
	default:
		content = wMetrics.Render(m.ui.Caps.Width, m.ui.Caps.Height)
	}

	return content
}
