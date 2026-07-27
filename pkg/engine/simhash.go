package engine

import (
	"hash"
	"hash/fnv"
	"math/bits"
	"sync"
	"unicode"
	"unicode/utf8"
)

// simhashBody computes a 64-bit SimHash fingerprint for a response body without allocating.
func simhashBody(body []byte) uint64 {
	if len(body) == 0 {
		return 0
	}

	var vector [64]int
	hasTokens := false

	inToken := false
	tokenStart := 0

	hasher := fnv.New64a()

	for i := 0; i < len(body); {
		r, size := utf8.DecodeRune(body[i:])
		isBoundary := unicode.IsSpace(r) || unicode.IsPunct(r)

		if isBoundary {
			if inToken {
				token := body[tokenStart:i]
				if len(token) > 0 {
					hasher.Reset()
					hashToken(token, &vector, hasher)
					hasTokens = true
				}
				inToken = false
			}
		} else {
			if !inToken {
				tokenStart = i
				inToken = true
			}
		}
		i += size
	}

	if inToken {
		token := body[tokenStart:]
		if len(token) > 0 {
			hasher.Reset()
			hashToken(token, &vector, hasher)
			hasTokens = true
		}
	}

	if !hasTokens {
		return 0
	}

	var fingerprint uint64
	for bit, weight := range vector {
		if weight > 0 {
			fingerprint |= uint64(1) << bit
		}
	}
	return fingerprint
}

func hashToken(token []byte, vector *[64]int, hasher hash.Hash64) {
	_, _ = hasher.Write(token)
	h := hasher.Sum64()

	for bit := 0; bit < 64; bit++ {
		if h&(uint64(1)<<bit) != 0 {
			vector[bit]++
		} else {
			vector[bit]--
		}
	}
}

func hammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

type simhashCluster struct {
	centroid uint64
	count    int
}

// SimhashTracker manages SimHash-based soft-404 clustering.
type SimhashTracker struct {
	clusters     []simhashCluster
	clusterLock  sync.Mutex
	threshold    int
	clusterLimit int
}

// NewSimhashTracker creates a new SimhashTracker.
func NewSimhashTracker(threshold, limit int) *SimhashTracker {
	return &SimhashTracker{
		clusters:     make([]simhashCluster, 0, 100),
		threshold:    threshold,
		clusterLimit: limit,
	}
}

// Configure updates clustering parameters under the same lock used by request
// workers, preventing snapshot refreshes from racing with live scans.
func (s *SimhashTracker) Configure(threshold, limit int) {
	s.clusterLock.Lock()
	s.threshold = threshold
	s.clusterLimit = limit
	s.clusterLock.Unlock()
}

// Clear resets the cluster map.
func (s *SimhashTracker) Clear() {
	s.clusterLock.Lock()
	s.clusters = s.clusters[:0]
	s.clusterLock.Unlock()
}

// IsSoftFour tracks a SimHash cluster and returns true once the cluster
// exceeds the configured limit.
func (s *SimhashTracker) IsSoftFour(bodyHash uint64) bool {
	s.clusterLock.Lock()
	defer s.clusterLock.Unlock()

	threshold := s.threshold
	if threshold < 0 {
		threshold = 0
	}
	limit := s.clusterLimit
	if limit <= 0 {
		return false
	}

	for i := 0; i < len(s.clusters); i++ {
		if hammingDistance(s.clusters[i].centroid, bodyHash) <= threshold {
			s.clusters[i].count++

			// Bubble up to keep sorted descending by count
			curr := i
			for curr > 0 && s.clusters[curr].count > s.clusters[curr-1].count {
				s.clusters[curr], s.clusters[curr-1] = s.clusters[curr-1], s.clusters[curr]
				curr--
			}

			return s.clusters[curr].count >= limit
		}
	}

	const maxSimhashCentroids = 5000
	if len(s.clusters) >= maxSimhashCentroids {
		// Replace the last element (lowest count)
		s.clusters[len(s.clusters)-1] = simhashCluster{centroid: bodyHash, count: 1}
	} else {
		s.clusters = append(s.clusters, simhashCluster{centroid: bodyHash, count: 1})
	}

	return false
}

// SeedBaseline registers a baseline SimHash fingerprint as pre-suppressed.
func (s *SimhashTracker) SeedBaseline(bodyHash uint64) {
	s.clusterLock.Lock()
	defer s.clusterLock.Unlock()
	c := simhashCluster{centroid: bodyHash, count: s.clusterLimit}
	s.clusters = append([]simhashCluster{c}, s.clusters...)
}
