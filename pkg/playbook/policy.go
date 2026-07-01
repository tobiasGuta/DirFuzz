package playbook

import "time"

type PlaybookPolicy struct {
	MaxSuggestionsPerFinding int
	Cooldown                 time.Duration
}

// Check enforces the playbook safety constraints.
func (p *PlaybookPolicy) Check(suggestion PlaybookSuggestion, history []PlaybookSuggestion) bool {
	count := 0
	for _, h := range history {
		if h.FindingID == suggestion.FindingID && h.PlaybookID == suggestion.PlaybookID {
			count++
		}
	}

	if count >= p.MaxSuggestionsPerFinding {
		return false
	}
	return true
}
