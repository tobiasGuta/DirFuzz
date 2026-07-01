package viewmodel

import (
	"dirfuzz/pkg/ui/models"
	"time"
)

type ValidationQueueItem struct {
	Request models.ValidationRequest
	Score   int
	Age     time.Duration
	Origin  string
}

type ValidationQueueView struct {
	Pending   int
	Running   int
	Completed int
	Items     []ValidationQueueItem
}
