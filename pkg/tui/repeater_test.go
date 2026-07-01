package tui

import (
	"testing"
)

func TestNewRepeaterTextarea(t *testing.T) {
	// Should not panic due to infinite recursion
	ta := newRepeaterTextarea()
	if ta.Placeholder != "GET / HTTP/1.1..." {
		t.Errorf("Expected placeholder 'GET / HTTP/1.1...', got %q", ta.Placeholder)
	}
}
