package models

import "time"

type MetricsData struct {
	RequestsSent    int64
	NodesDiscovered int64
	NodesConfirmed  int64
	FindingsCreated int64
	QueueDepth      int64
	WorkerCount     int64
	GraphSize       int64
}

type QueueData struct {
	Validation int
	ParamFuzz  int
	Discovery  int
}

type TimelineData struct {
	Time    time.Time
	Message string
}

type FindingData struct {
	ID       string
	Title    string
	Severity string
	Score    int
}

type TargetData struct {
	Host string
}

// PresentationModel is purely owned by the UI. It never imports `engine`.
type PresentationModel struct {
	Version  uint64
	Targets  []TargetData
	Metrics  MetricsData
	Queue    QueueData
	Timeline []TimelineData
	Findings []FindingData
}
