package engine

type GraphTransaction interface {
	Commit() error
	Rollback() error
}

type GraphStore interface {
	SaveSnapshot(graph *DiscoveryGraph) error
	LoadSnapshot() (*DiscoveryGraph, error)

	AppendEvent(event GraphEvent) error
	GetEvents(after string) ([]GraphEvent, error)

	Begin() (GraphTransaction, error)
}
