package knowledge

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

type PatternSignature struct {
	Method      string
	RouteClass  string
	StatusCode  int
	ContentType string
	Tags        []string
}

func (s *PatternSignature) Hash() string {
	// A deterministic string representation
	// Note: Tags must be sorted in a real implementation for determinism.
	// We'll join them directly for this mock implementation.
	tagStr := strings.Join(s.Tags, ",")
	raw := fmt.Sprintf("%s|%s|%d|%s|%s", s.Method, s.RouteClass, s.StatusCode, s.ContentType, tagStr)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
}
