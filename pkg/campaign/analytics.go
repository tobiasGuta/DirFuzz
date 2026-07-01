package campaign

type RiskSignal struct {
	Name     string
	Value    float64
	Evidence []string
}

type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

type CampaignRisk struct {
	Level   RiskLevel
	Signals []RiskSignal
}

// CalculateRisk evaluates a set of CampaignBaselines (historical chronological snapshots)
// to yield an aggregate risk score tracking overall target regression and surface expansion.
func CalculateRisk(baselines []CampaignBaseline) CampaignRisk {
	risk := CampaignRisk{
		Level:   RiskLow,
		Signals: make([]RiskSignal, 0),
	}

	if len(baselines) < 2 {
		return risk // Cannot calculate risk without at least two baselines
	}

	first := baselines[0]
	last := baselines[len(baselines)-1]

	var totalSignalValue float64

	// 1. Attack Surface Growth
	if first.KnownEndpoints > 0 {
		growth := float64(last.KnownEndpoints-first.KnownEndpoints) / float64(first.KnownEndpoints)

		if growth > 0.5 { // >50% growth
			w := growth * 10
			if w > 25.0 {
				w = 25.0 // Cap to prevent wildcard explosion fatigue
			}
			totalSignalValue += w
			risk.Signals = append(risk.Signals, RiskSignal{
				Name:     "Attack Surface Expansion",
				Value:    w,
				Evidence: []string{"Surface grew by >50%"},
			})
		}
	}

	// 2. Auth Boundary Changes
	if last.KnownAuthBoundaries > first.KnownAuthBoundaries {
		diff := last.KnownAuthBoundaries - first.KnownAuthBoundaries
		w := float64(diff) * 2.0
		totalSignalValue += w
		risk.Signals = append(risk.Signals, RiskSignal{
			Name:     "Auth Boundary Instability",
			Value:    w,
			Evidence: []string{"New authentication boundary changes detected"},
		})
	}

	if totalSignalValue > 50 {
		risk.Level = RiskCritical
	} else if totalSignalValue > 20 {
		risk.Level = RiskHigh
	} else if totalSignalValue > 5 {
		risk.Level = RiskMedium
	}

	return risk
}
