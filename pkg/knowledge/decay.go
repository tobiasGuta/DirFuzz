package knowledge

import (
	"math"
	"time"
)

// CalculateDecayedWeight applies the exponential decay formula based on age
// Weight = OriginalWeight * e^(-ageDays / HalfLifeDays)
func CalculateDecayedWeight(decay KnowledgeDecay, now time.Time, originalWeight float64) float64 {
	// If the half life is zero or negative, do not decay (infinite)
	if decay.HalfLifeDays <= 0 {
		return originalWeight
	}

	// Age is calculated from the LastConfirmed timestamp
	ageDuration := now.Sub(decay.LastConfirmed)
	ageDays := ageDuration.Hours() / 24.0

	// If it's negative age (time traveling, tests, or just now), age is 0
	if ageDays < 0 {
		ageDays = 0
	}

	// Calculate decay multiplier
	multiplier := math.Exp(-ageDays / float64(decay.HalfLifeDays))
	
	newWeight := originalWeight * multiplier

	// Adjust based on LastObserved. If it was recently observed but not confirmed,
	// maybe it doesn't drop below the MinWeight.
	if newWeight < decay.MinWeight {
		return decay.MinWeight
	}

	return newWeight
}
