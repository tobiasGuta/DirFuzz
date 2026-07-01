package diff

import "dirfuzz/pkg/engine"

type DashboardDelta struct {
	NewFindings     int
	NewNodes        int
	QueueChanged    bool
}

func CalculateDelta(old, new engine.AnalystSnapshot) DashboardDelta {
	return DashboardDelta{
		NewFindings: int(new.Metrics.FindingsCreated - old.Metrics.FindingsCreated),
		NewNodes:    int(new.Metrics.GraphSize - old.Metrics.GraphSize),
		QueueChanged: new.Metrics.QueueDepth != old.Metrics.QueueDepth,
	}
}
