package campaign

import "time"
type EndpointHistory struct {
	EndpointID     string
	Path           string
	ChangeCount    int
	LatestOldScore int
	LatestNewScore int
}

type PlaybookEffectiveness struct {
	PlaybookID    string
	Version       string
	Window        time.Duration
	Runs          int
	Confirmed     int
	FalsePositive int
	SuccessRate   float64
}

type AnalystSignalQuality struct {
	AnalystID           string
	AcceptedSuggestions int
	RejectedSuggestions int
	ConfirmedFindings   int
}

type GraphQuery interface {
	GetEndpointsWithRepeatedAuthChanges(targetID string) []EndpointHistory
	GetHighRiskUntestedSurface(targetID string) []IntelligenceNode
	GetEndpointsRejectedByAnalysts(reason string) []IntelligenceNode
	GetMostChangedEndpoints(targetID string) []EndpointHistory
	GetDecayedKnowledge(targetID string) []IntelligenceNode
	GetCampaignRiskTrend(targetID string) []CampaignRisk
	GetPlaybookMetrics() []PlaybookEffectiveness
	GetAnalystSignalQuality() []AnalystSignalQuality
}
