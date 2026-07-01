package fingerprint

import (
	"regexp"
	"sort"
	"strings"
)

type MatchLocation string

const (
	HeaderMatch MatchLocation = "header"
	CookieMatch MatchLocation = "cookie"
	BodyMatch   MatchLocation = "body"
)

type Signature struct {
	Tech     string
	Location MatchLocation
	Key      string
	Pattern  *regexp.Regexp
}

type Fingerprinter struct {
	signatures []Signature
}

func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		signatures: defaultSignatures(),
	}
}

// Detect is completely decoupled from net/http.
// headers: map of response header names to values (use resp.HeaderMap directly)
// cookies: map of cookie names parsed from raw Set-Cookie headers
// body: raw response body bytes
// Returns a sorted, deduplicated slice of detected technology names.
// Sorted to guarantee determinism for Event Ledger hashing and replay.
func (f *Fingerprinter) Detect(headers map[string]string, cookies map[string]string, body []byte) []string {
	detected := make(map[string]bool)

	for _, sig := range f.signatures {
		switch sig.Location {
		case HeaderMatch:
			for k, v := range headers {
				if strings.EqualFold(k, sig.Key) {
					if sig.Pattern == nil || sig.Pattern.MatchString(v) {
						detected[sig.Tech] = true
					}
				}
			}
		case CookieMatch:
			for k := range cookies {
				if strings.EqualFold(k, sig.Key) {
					detected[sig.Tech] = true
				}
			}
		case BodyMatch:
			if sig.Pattern != nil && sig.Pattern.Match(body) {
				detected[sig.Tech] = true
			}
		}
	}

	var results []string
	for tech := range detected {
		results = append(results, tech)
	}

	sort.Strings(results) // Mandatory: enforces determinism for ledger hashing
	return results
}
