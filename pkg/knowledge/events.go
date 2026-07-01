package knowledge

import "time"

type KnowledgeEvent struct {
	PatternHash string
	DecisionID  string
	Influence   int
	Timestamp   time.Time
}
