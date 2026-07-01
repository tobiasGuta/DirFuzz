package campaign

import (
	"context"
	"strings"
	"testing"
	"time"
)

type MockEvent struct {
	ID        string
	Type      string
	Time      time.Time
	Headers   map[string]string
	RawBody   string
}

func (m *MockEvent) EventID() string { return m.ID }
func (m *MockEvent) EventType() string { return m.Type }
func (m *MockEvent) Timestamp() time.Time { return m.Time }

type MockStore struct {
	LastEvent Event
}

func (m *MockStore) Append(ctx context.Context, event Event) error {
	m.LastEvent = event
	return nil
}
func (m *MockStore) Read(ctx context.Context, from, to time.Time) ([]Event, error) { return nil, nil }
func (m *MockStore) Snapshot(ctx context.Context) ([]byte, error) { return nil, nil }
func (m *MockStore) Replay(ctx context.Context) ([]Event, error) { return nil, nil }


func TestLedgerCannotStoreSecrets(t *testing.T) {
	mock := &MockStore{}
	sanitizer := NewEvidenceSanitizer(mock)

	secretToken := "abc123supersecret"
	secretCookie := "xyz_session_cookie_999"

	ev := &MockEvent{
		ID:   "evt-1",
		Type: "HTTP_REQ",
		Time: time.Now(),
		Headers: map[string]string{
			"Authorization": "Bearer " + secretToken,
			"Cookie":        "session=" + secretCookie,
			"Content-Type":  "application/json",
		},
		RawBody: "{\"jwt\": \"eyXXX.eyYYY.ZZZ\"}",
	}

	err := sanitizer.Append(context.Background(), ev)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	appended := mock.LastEvent.(*MockEvent)

	// Assert the secrets do not exist
	if strings.Contains(appended.Headers["Authorization"], secretToken) {
		t.Errorf("Authorization token was not redacted! Found %s", appended.Headers["Authorization"])
	}
	if strings.Contains(appended.Headers["Cookie"], secretCookie) {
		t.Errorf("Cookie was not redacted! Found %s", appended.Headers["Cookie"])
	}
	if strings.Contains(appended.RawBody, "eyXXX.eyYYY.ZZZ") {
		t.Errorf("JWT in body was not redacted! Found %s", appended.RawBody)
	}

	// Assert it was replaced with redaction
	if !strings.Contains(appended.Headers["Authorization"], "[REDACTED") {
		t.Errorf("Authorization header missing REDACTED tag")
	}
	if appended.Headers["Content-Type"] != "application/json" {
		t.Errorf("Safe headers were modified!")
	}
}
