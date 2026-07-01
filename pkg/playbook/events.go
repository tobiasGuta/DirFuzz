package playbook

import "time"

type PlaybookEvent struct {
	PlaybookID string
	EventID    string
	Timestamp  time.Time
	Decision   string
}
