package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// EvidenceSanitizer wraps an EventStore and redacts sensitive credentials
// from events before they are committed to the immutable ledger.
type EvidenceSanitizer struct {
	Store EventStore
}

func NewEvidenceSanitizer(store EventStore) *EvidenceSanitizer {
	return &EvidenceSanitizer{Store: store}
}

func (s *EvidenceSanitizer) Append(ctx context.Context, event Event) error {
	// Redact the event deeply
	redactedEvent := redactEvent(event)
	return s.Store.Append(ctx, redactedEvent)
}

func (s *EvidenceSanitizer) Read(ctx context.Context, from, to time.Time) ([]Event, error) {
	return s.Store.Read(ctx, from, to)
}

func (s *EvidenceSanitizer) Snapshot(ctx context.Context) ([]byte, error) {
	return s.Store.Snapshot(ctx)
}

func (s *EvidenceSanitizer) Replay(ctx context.Context) ([]Event, error) {
	return s.Store.Replay(ctx)
}

var sensitiveHeaders = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"set-cookie":    true,
	"x-api-key":     true,
	"x-amz-security-token": true,
}

var bearerRegex = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)`)
var jwtRegex = regexp.MustCompile(`(?i)(ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`)

func redactString(val string) string {
	// First redact known token formats if they exist inside the string
	val = bearerRegex.ReplaceAllStringFunc(val, func(m string) string {
		parts := bearerRegex.FindStringSubmatch(m)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(parts[2])))
		return fmt.Sprintf("%s[REDACTED sha256:%s]", parts[1], hash)
	})

	val = jwtRegex.ReplaceAllStringFunc(val, func(m string) string {
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(m)))
		return fmt.Sprintf("[REDACTED sha256:%s]", hash)
	})
	return val
}

func hashValue(val string) string {
	return fmt.Sprintf("[REDACTED sha256:%x]", sha256.Sum256([]byte(val)))
}

func redactEvent(event Event) Event {
	// We serialize to JSON and back to generic map, redact, then re-marshal.
	// Since Event is an interface, it's the safest way to deeply redact 
	// without dealing with unexported fields and reflection panics.
	
	bytes, err := json.Marshal(event)
	if err != nil {
		return event
	}
	
	var data interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		return event
	}

	redactedData := walkAndRedact(data)
	
	// We need to return an Event. However, turning map[string]interface{} back 
	// into the concrete Event type requires reflection.
	
	// Fast-path: reflect the pointer and mutate its fields if it's a struct pointer.
	// For simplicity, we create a new instance of the original type.
	val := reflect.ValueOf(event)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	
	newObj := reflect.New(val.Type()).Interface()
	redactedBytes, _ := json.Marshal(redactedData)
	json.Unmarshal(redactedBytes, newObj)
	
	if ev, ok := newObj.(Event); ok {
		return ev
	}
	
	return event
}

func walkAndRedact(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		return redactString(v)
	case map[string]interface{}:
		redacted := make(map[string]interface{})
		for key, val := range v {
			if sensitiveHeaders[strings.ToLower(key)] {
				// If it's a known sensitive key (like in a Headers map)
				if strVal, ok := val.(string); ok {
					redacted[key] = hashValue(strVal)
				} else if strSlice, ok := val.([]interface{}); ok {
					var rs []interface{}
					for _, item := range strSlice {
						if s, ok := item.(string); ok {
							rs = append(rs, hashValue(s))
						} else {
							rs = append(rs, item)
						}
					}
					redacted[key] = rs
				} else {
					redacted[key] = walkAndRedact(val)
				}
			} else {
				redacted[key] = walkAndRedact(val)
			}
		}
		return redacted
	case []interface{}:
		var redacted []interface{}
		for _, val := range v {
			redacted = append(redacted, walkAndRedact(val))
		}
		return redacted
	}
	return data
}
