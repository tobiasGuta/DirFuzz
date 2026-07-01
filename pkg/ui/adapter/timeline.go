package adapter

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
	"fmt"
)

type TimelineAdapter struct{}

func NewTimelineAdapter() *TimelineAdapter {
	return &TimelineAdapter{}
}

func (a *TimelineAdapter) Project(events []engine.GraphEvent) []models.TimelineGroup {
	var groups []models.TimelineGroup
	
	// Example logic: cluster events into groups of Discovery
	currentGroup := models.TimelineGroup{}
	
	for i, e := range events {
		seq := uint64(i)
		
		if currentGroup.Count == 0 {
			currentGroup.StartSequence = seq
		}
		currentGroup.EndSequence = seq
		currentGroup.Count++
		
		// In a real system, we'd inspect e.Payload to determine when to break the group
		// For now, let's group every 3 events or on finding triggers.
		if currentGroup.Count >= 3 || e.Type == "FINDING" {
			currentGroup.Summary = fmt.Sprintf("Processed %d events ending at %s", currentGroup.Count, e.Type)
			groups = append(groups, currentGroup)
			currentGroup = models.TimelineGroup{}
		}
	}
	
	if currentGroup.Count > 0 {
		currentGroup.Summary = fmt.Sprintf("Processed %d events", currentGroup.Count)
		groups = append(groups, currentGroup)
	}

	return groups
}
