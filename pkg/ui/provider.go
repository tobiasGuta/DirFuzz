package ui

import "dirfuzz/pkg/engine"

type SnapshotResult struct {
	Snapshot engine.AnalystSnapshot
	Version  uint64
}

type SnapshotProvider interface {
	Latest() SnapshotResult
}
