package fingerprint

import (
	"reflect"
	"testing"
)

func TestFingerprinter_Detect(t *testing.T) {
	fp := NewFingerprinter()

	tests := []struct {
		name         string
		headers      map[string]string
		cookies      map[string]string
		body         []byte
		expectedTech []string
	}{
		{
			name:         "Detect PHP via Header",
			headers:      map[string]string{"X-Powered-By": "PHP/8.1.2"},
			expectedTech: []string{"PHP"},
		},
		{
			name:         "Detect IIS via Server Header",
			headers:      map[string]string{"Server": "Microsoft-IIS/10.0"},
			expectedTech: []string{"IIS"},
		},
		{
			name:         "Detect Spring via Cookie",
			cookies:      map[string]string{"JSESSIONID": "123456789"},
			expectedTech: []string{"Spring"},
		},
		{
			name:         "Detect Spring Boot via Body",
			body:         []byte(`<html><body><h1>Whitelabel Error Page</h1></body></html>`),
			expectedTech: []string{"Spring Boot"},
		},
		{
			name:    "Multiple Technologies Returns Sorted Output",
			headers: map[string]string{"X-Powered-By": "Express", "Server": "nginx/1.18.0"},
			cookies: map[string]string{"PHPSESSID": "abcdef"},
			// Must be sorted alphabetically to guarantee determinism
			expectedTech: []string{"Express", "PHP", "nginx"},
		},
		{
			name:         "No Detection Returns Nil",
			headers:      map[string]string{"Server": "Unknown-Custom-Server"},
			body:         []byte(`Just a standard body with no signatures`),
			expectedTech: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := fp.Detect(tt.headers, tt.cookies, tt.body)
			if len(results) == 0 && len(tt.expectedTech) == 0 {
				return
			}
			if !reflect.DeepEqual(results, tt.expectedTech) {
				t.Errorf("Detect() = %v, want %v", results, tt.expectedTech)
			}
		})
	}
}
