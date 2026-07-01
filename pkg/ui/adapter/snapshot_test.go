package adapter

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/presenter"
	"testing"
	"time"
)

type dummyClock struct{}

func (d dummyClock) Now() string { return "12:00:00" }

func TestDashboardBuildMillionNodeSnapshot(t *testing.T) {
	// 1. Construct Mock AnalystSnapshot with 1M nodes and 100k findings
	snap := engine.AnalystSnapshot{
		Version: 1,
		Targets: []engine.Target{{Host: "example.com"}},
		Metrics: engine.EngineMetricsSnap{
			GraphSize:       1000000,
			FindingsCreated: 100000,
		},
	}
	
	// Pre-populate 100k findings (in real life, findings are large arrays, but we just want to ensure
	// our mapping doesn't blow up memory quadratically).
	for i := 0; i < 100000; i++ {
		snap.Findings = append(snap.Findings, engine.Finding{
			ID:       "f1",
			Title:    "Test finding",
			Severity: "High",
			Score:    engine.FindingScore{FinalScore: 80},
		})
	}

	start := time.Now()

	// 2. Adapter conversion
	adapter := NewSnapshotAdapter()
	presModel := adapter.Convert(snap)

	// 3. Presenter Build DashboardView
	dashPresenter := presenter.NewDashboardPresenter()
	ctx := presenter.PresenterContext{
		Clock:      dummyClock{},
		PageSize:   50,
		TimeFormat: "15:04:05",
	}

	view := dashPresenter.Dashboard(presModel, ctx)

	duration := time.Since(start)

	// 4. Verify O(1)/Bounded properties
	if view.Metrics.TotalFindings != 100000 {
		t.Fatalf("Failed to correctly map 100k findings metrics")
	}

	// We only take the top 10 findings for the dashboard, checking that it correctly bounded it
	if len(view.TopRisk) != 10 {
		t.Fatalf("Dashboard TopRisk widget should be bounded to 10 items, got %d", len(view.TopRisk))
	}

	if duration > 100*time.Millisecond {
		t.Fatalf("Presentation transformation of 1M-Node / 100k-Finding snapshot took too long: %v. Expected <100ms", duration)
	}
}
