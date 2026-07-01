package tui

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui"
	"dirfuzz/pkg/ui/adapter"
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/presenter"
	"dirfuzz/pkg/ui/viewmodel"
	"sync/atomic"
	"testing"
	"time"
)

type mockProvider struct {
	counter uint64
}

func (m *mockProvider) Latest() ui.SnapshotResult {
	val := atomic.LoadUint64(&m.counter)
	return ui.SnapshotResult{
		Version: val,
		Snapshot: engine.AnalystSnapshot{
			Version: val,
		},
	}
}

type slowMockDashboardPresenter struct{}

func (m *slowMockDashboardPresenter) Metrics(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.MetricsWidget { return viewmodel.MetricsWidget{} }
func (m *slowMockDashboardPresenter) Queue(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.QueueWidget { return viewmodel.QueueWidget{} }
func (m *slowMockDashboardPresenter) Timeline(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.TimelineWidget { return viewmodel.TimelineWidget{} }

// Slow render
func (m *slowMockDashboardPresenter) Dashboard(model models.PresentationModel, ctx presenter.PresenterContext) viewmodel.DashboardView {
	time.Sleep(400 * time.Millisecond)
	return viewmodel.DashboardView{}
}

func TestTUIRefreshStorm(t *testing.T) {
	prov := &mockProvider{}
	adapt := adapter.NewSnapshotAdapter()
	pres := presenter.NewPresentationService(&slowMockDashboardPresenter{}, nil, nil)
	
	model := NewModel(pres, prov, adapt, presenter.PresenterContext{})

	// Simulate 10000 events/sec hitting the dirty flag
	go func() {
		for i := 0; i < 10000; i++ {
			atomic.AddUint64(&prov.counter, 1)
			
			// We manually invoke the DirtyMsg behavior since we aren't running
			// the full BubbleTea runtime loop here.
			model.ui.Dirty = true
		}
	}()

	// The tick loop
	ticks := 0
	start := time.Now()
	
	for time.Since(start) < 2*time.Second {
		// Simulate a 250ms tick interval
		time.Sleep(250 * time.Millisecond)
		
		// Run tick processing
		newModel, _ := model.ProcessTick(prov, adapt)
		model = newModel
		ticks++
	}

	// 10,000 engine events fired.
	// We ran the loop for 2 seconds -> approx 8 ticks.
	// But the renderer sleeps for 400ms. So each loop cycle (250ms tick + 400ms render) = 650ms.
	// In 2 seconds, we expect ~3 renders.

	// Ensure the background engine easily reached 10k while UI was slow.
	finalCount := atomic.LoadUint64(&prov.counter)
	if finalCount < 9000 {
		t.Fatalf("Engine was throttled by the UI! Only reached %d events", finalCount)
	}

	if ticks > 10 {
		t.Fatalf("UI thrashed and ticked too many times: %d", ticks)
	}
}
