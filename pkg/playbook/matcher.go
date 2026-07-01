package playbook

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
	"fmt"
	"time"
)

type SuggestionState string

const (
	Suggested SuggestionState = "SUGGESTED"
	Approved  SuggestionState = "APPROVED"
	Rejected  SuggestionState = "REJECTED"
)

type PlaybookSuggestion struct {
	ID                  string
	PlaybookID          string
	FindingID           string
	NodeID              string
	SuggestedValidation models.ValidationType
	Reason              string
	Confidence          int
	TriggerEventID      string
	EvidenceRefs        []string
	CreatedAt           time.Time
	State               SuggestionState
}

type MatchContext struct {
	ExistingSuggestions map[string]bool // keys could be hashes of the suggestion logic
	CurrentSnapshotHash string
}

type Matcher interface {
	Evaluate(event engine.GraphEvent, context MatchContext) []PlaybookSuggestion
}

type DefaultMatcher struct {
	playbooks []Playbook
}

func NewMatcher(playbooks []Playbook) *DefaultMatcher {
	return &DefaultMatcher{playbooks: playbooks}
}

func (m *DefaultMatcher) Evaluate(event engine.GraphEvent, context MatchContext) []PlaybookSuggestion {
	var suggestions []PlaybookSuggestion

	for _, pb := range m.playbooks {
		if !pb.Enabled {
			continue
		}

		for _, trigger := range pb.Triggers {
			if trigger.Event == event.Type {
				statusCondition, ok := trigger.Condition["status"]
				// In a real system, we'd lookup ResponseEvidence from the engine or payload.
				// For this mock implementation, we simulate matching by parsing the condition.
				if ok && statusCondition == "403" {

					// Match found
					for _, action := range pb.Actions {
						sgID := fmt.Sprintf("sg-%s-%s", pb.ID, event.ID)

						if context.ExistingSuggestions[sgID] {
							continue // Do not suggest if it already exists/was rejected
						}

						suggestions = append(suggestions, PlaybookSuggestion{
							ID:                  sgID,
							PlaybookID:          pb.ID,
							FindingID:           event.NodeID, // Or a resolved FindingID
							NodeID:              event.NodeID,
							SuggestedValidation: action.Suggest,
							Reason:              fmt.Sprintf("Endpoint returned %s after anonymous request", statusCondition),
							Confidence:          85,
							TriggerEventID:      event.ID,
							EvidenceRefs:        []string{event.ID},
							CreatedAt:           time.Now(),
							State:               Suggested,
						})
					}
				}
			}
		}
	}

	return suggestions
}
