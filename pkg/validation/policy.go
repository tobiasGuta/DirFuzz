package validation

import "dirfuzz/pkg/ui/models"

type ValidationPolicy interface {
	Allow(req models.ValidationRequest) error
}

type DefaultPolicy struct {
	dedup map[string]bool
}

func NewDefaultPolicy() *DefaultPolicy {
	return &DefaultPolicy{
		dedup: make(map[string]bool),
	}
}

func (p *DefaultPolicy) Allow(req models.ValidationRequest) error {
	// Example policy: don't repeat identical validations
	if p.dedup[req.DedupKey] {
		return nil // Or return an error depending on strictness. In a real engine, we drop silently.
	}
	p.dedup[req.DedupKey] = true
	return nil
}
