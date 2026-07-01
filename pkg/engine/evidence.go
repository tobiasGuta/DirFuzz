package engine

// EvidenceExtractor defines the contract for adapting execution Results
// into Graph intelligence ResponseEvidence without leaking graph models
// into the worker fuzzing loop.
type EvidenceExtractor interface {
	Extract(result Result) ResponseEvidence
}

// DefaultEvidenceExtractor provides a standard mapping from Result to ResponseEvidence.
type DefaultEvidenceExtractor struct{}

// Extract converts a fuzzing Result into a ResponseEvidence.
func (d DefaultEvidenceExtractor) Extract(result Result) ResponseEvidence {
	interesting := false
	if result.IsEagleAlert || result.MarkedInteresting {
		interesting = true
	}

	return ResponseEvidence{
		StatusCode:  result.StatusCode,
		ContentType: result.ContentType,
		Length:      result.Size,
		Headers:     result.Headers,
		Interesting: interesting,
		Reason:      result.Note,
	}
}
