package replay

import "dirfuzz/pkg/ui/models"

type CausalChain struct {
	FindingID string
	Trigger   models.TimelineEvent
	Path      []models.TimelineEvent
}
