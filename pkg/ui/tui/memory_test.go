package tui

import (
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/presenter"
	"dirfuzz/pkg/ui/viewmodel"
	tea "github.com/charmbracelet/bubbletea"
	"testing"
	"runtime"
)

type mockDashboardPresenter struct{}

func (m *mockDashboardPresenter) Metrics(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.MetricsWidget {
	return viewmodel.MetricsWidget{}
}
func (m *mockDashboardPresenter) Queue(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.QueueWidget {
	return viewmodel.QueueWidget{}
}
func (m *mockDashboardPresenter) Timeline(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.TimelineWidget {
	return viewmodel.TimelineWidget{}
}
func (m *mockDashboardPresenter) Dashboard(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.DashboardView {
	return viewmodel.DashboardView{
		Metrics: m.Metrics(model, ctx),
		Queue:   m.Queue(model, ctx),
		Timeline: m.Timeline(model, ctx),
	}
}

func TestDashboardLongRunningSession(t *testing.T) {
	presService := presenter.NewPresentationService(&mockDashboardPresenter{}, nil, nil)
	model := NewModel(presService, nil, nil, presenter.PresenterContext{})

	// Simulate rendering the dashboard many times
	// Initialize layout
	m, _ := model.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	model = m.(Model)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	initialAllocs := memStats.TotalAlloc

	// Simulate 100k fast refreshes
	for i := 0; i < 100000; i++ {
		// Mock receiving a new snapshot update (handled later in Update)
		model.dashboard = viewmodel.DashboardView{
			Metrics: viewmodel.MetricsWidget{Requests: i},
		}
		_ = model.View()
	}

	runtime.ReadMemStats(&memStats)
	finalAllocs := memStats.TotalAlloc

	allocsPerRender := (finalAllocs - initialAllocs) / 100000

	// We expect the render loop to be relatively garbage-free, though strings allocate some memory.
	// We ensure it doesn't exponentially leak or allocate massively.
	if allocsPerRender > 100000 {
		t.Fatalf("Excessive allocations per render tick: %d bytes", allocsPerRender)
	}
}
