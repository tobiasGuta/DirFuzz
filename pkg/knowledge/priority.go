package knowledge

import "fmt"

type KnowledgePolicy struct {
	MaxInfluencePerPattern int
	MinSamplesForBoost     int
}

type PriorityReason struct {
	Source    string
	Value     int
	Reference string
}

type PriorityCalculator interface {
	Calculate(basePriority int, kResult KnowledgeResult, policy KnowledgePolicy) (int, []PriorityReason)
}

type DefaultPriorityCalculator struct{}

func (c *DefaultPriorityCalculator) Calculate(basePriority int, kResult KnowledgeResult, policy KnowledgePolicy) (int, []PriorityReason) {
	var reasons []PriorityReason

	reasons = append(reasons, PriorityReason{
		Source:    "Base Priority",
		Value:     basePriority,
		Reference: "Evidence + RiskScore",
	})

	netBoost := kResult.ConfidenceBoost - kResult.ConfidencePenalty
	
	// Apply protection limit
	// MinSamplesForBoost is a bit tricky if we just use raw Boost score from store,
	// but let's assume each sample is roughly +5.
	samples := (kResult.ConfidenceBoost + kResult.ConfidencePenalty) / 5
	if samples < policy.MinSamplesForBoost {
		if samples > 0 {
			reasons = append(reasons, PriorityReason{
				Source:    "Analyst Knowledge",
				Value:     0,
				Reference: fmt.Sprintf("Ignored knowledge: Below boost threshold (%d < %d)", samples, policy.MinSamplesForBoost),
			})
		}
		netBoost = 0
	} else {
		if netBoost > policy.MaxInfluencePerPattern {
			netBoost = policy.MaxInfluencePerPattern
		} else if netBoost < -policy.MaxInfluencePerPattern {
			netBoost = -policy.MaxInfluencePerPattern
		}

		if netBoost != 0 {
			reasons = append(reasons, PriorityReason{
				Source:    "Analyst Knowledge",
				Value:     netBoost,
				Reference: fmt.Sprintf("Calculated from %d feedback samples", samples),
			})
		}
	}

	return basePriority + netBoost, reasons
}
