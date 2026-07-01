package models

type SurfaceKind int

const (
	SurfaceTarget SurfaceKind = iota
	SurfaceAsset
	SurfaceEndpoint
	SurfaceParameter
	SurfaceFinding
)

type RiskSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

type SurfaceNode struct {
	ID           string
	Name         string
	Kind         SurfaceKind
	ChildIDs     []string
	RiskSummary  RiskSummary
	FindingCount int
	Confidence   int
	Sources      []string
}

type SurfaceIndex struct {
	Nodes       map[string]*SurfaceNode
	SearchIndex map[string][]string
}
