package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// GraphVersion tracks the schema version of the discovery graph for persistence compatibility.
type GraphVersion int

const (
	GraphV1 GraphVersion = 1
)

// NodeKind identifies whether a discovery node is a root source or an extracted path.
type NodeKind string

const (
	NodeSource NodeKind = "source"
	NodePath   NodeKind = "path"
)

// DiscoveryEvidence provides structured details on how an endpoint was discovered.
type DiscoveryEvidence struct {
	Type             string `json:"type,omitempty"`
	Source           string `json:"source,omitempty"`
	Line             int    `json:"line,omitempty"`
	ExtractionMethod string `json:"extraction_method,omitempty"`
	Confidence       int    `json:"confidence,omitempty"` // 0-100 scale
	Quality          int    `json:"quality,omitempty"`
}

type NodeState int

const (
	StateDiscovered NodeState = iota
	StateQueued
	StateTested
	StateConfirmed
	StateRejected
	StateStale
	StateBlocked
	StateRetesting
)

type NodeLifecycle struct {
	State        NodeState     `json:"state"`
	LastSeen     time.Time     `json:"last_seen"`
	LastTested   time.Time     `json:"last_tested"`
	HitCount     int           `json:"hit_count"`
	ArchiveAfter time.Duration `json:"archive_after,omitempty"`
	IsArchived   bool          `json:"is_archived,omitempty"`
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitHalfOpen
	CircuitOpen
)

type CircuitBreaker struct {
	State            CircuitState  `json:"state"`
	Consecutive5xx   int           `json:"consecutive_5xx"`
	ConsecutiveTO    int           `json:"consecutive_to"`
	ConsecutiveConnE int           `json:"consecutive_conn_e"`
	OpenedAt         time.Time     `json:"opened_at"`
	Cooldown         time.Duration `json:"cooldown"`
}

type ScanBudget struct {
	RequestsUsed int           `json:"requests_used"`
	BytesUsed    int64         `json:"bytes_used"`
	TimeUsed     time.Duration `json:"time_used"`
	MaxRequests  int           `json:"max_requests"`
	MaxBytes     int64         `json:"max_bytes"`
	MaxTime      time.Duration `json:"max_time"`
}

type NegativeEvidence struct {
	Method    string        `json:"method"`
	Status    int           `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	TTL       time.Duration `json:"ttl"`
}

type GraphConfig struct {
	MaxEvents int `json:"max_events"`
	MaxNodes  int `json:"max_nodes"`
}

// ActionStatus tracks the state of a generated follow-up task.
type ActionStatus string

const (
	ActionPending   ActionStatus = "pending"
	ActionQueued    ActionStatus = "queued"
	ActionCompleted ActionStatus = "completed"
	ActionFailed    ActionStatus = "failed"
)

// DiscoveryAction represents an intelligence-driven follow-up task.
type DiscoveryAction struct {
	ID        string       `json:"id"`
	Type      string       `json:"type"`      // Corresponds to JobType (e.g. "paramfuzz", "validation")
	NodeID    string       `json:"node_id"`   // The graph node this action is attached to
	Reason    string       `json:"reason"`    // Human-readable rationale for this action
	Priority  int            `json:"priority"`  // The priority score bonus this action holds
	Status    ActionStatus   `json:"status"`    // Execution status
	CreatedAt time.Time      `json:"created_at"`
	Origin    GraphEventType `json:"origin,omitempty"`
}

// ActionKey uniquely identifies an action to prevent duplicates.
// We use a string key ("NodeID|ActionType") for json.Marshal compatibility.
func makeActionKey(nodeID, actionType string) string {
	return nodeID + "|" + actionType
}

// ActionExecution tracks the runtime lifecycle of a generated action.
type ActionExecution struct {
	Status      ActionStatus `json:"status"`
	JobID       string       `json:"job_id,omitempty"`
	StartedAt   time.Time    `json:"started_at,omitempty"`
	CompletedAt time.Time    `json:"completed_at,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// GraphEventType describes a state transition in the intelligence model.
type GraphEventType string

const (
	GraphEventNodeAdded        GraphEventType = "node_added"
	GraphEventEvidenceUpdated  GraphEventType = "evidence_updated"
	GraphEventResponseObserved GraphEventType = "response_observed"
	GraphEventActionCreated    GraphEventType = "action_created"
)

// GraphEvent represents a chronological intelligence update.
type GraphEvent struct {
	ID        string            `json:"id"`
	Type      GraphEventType    `json:"type"`
	NodeID    string            `json:"node_id"`
	Evidence  DiscoveryEvidence `json:"evidence,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// ResponseEvidence captures relevant runtime signals without storing raw payload bodies.
type ResponseEvidence struct {
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Length      int               `json:"length"`
	Headers     map[string]string `json:"headers,omitempty"`
	Interesting bool              `json:"interesting"`
	Reason      string            `json:"reason,omitempty"`
}

// DiscoveryNode represents a single point in the discovery topology.
type DiscoveryNode struct {
	ID                        string              `json:"id"`
	TargetID                  string              `json:"target_id,omitempty"`
	Kind                      NodeKind            `json:"kind"`
	CanonicalPath             string              `json:"canonical_path,omitempty"`
	Label                     string              `json:"label"`
	ParentID                  string              `json:"parent_id,omitempty"`
	SourceType                string              `json:"source_type,omitempty"`
	Evidence                  DiscoveryEvidence   `json:"evidence,omitempty"`
	Lifecycle                 NodeLifecycle       `json:"lifecycle"`
	CircuitBreaker            CircuitBreaker      `json:"circuit_breaker"`
	Budget                    ScanBudget          `json:"budget"`
	FirstSeen                 time.Time           `json:"first_seen"`
	FirstDiscoveredByNodeID   string              `json:"first_discovered_by_node_id,omitempty"`
	Confidence                int                 `json:"confidence"`
	PriorityScore             int                 `json:"priority_score"`
	RiskScore                 int                 `json:"risk_score"`
	Tags                      []string            `json:"tags,omitempty"`
	DerivedJobsCount          int                 `json:"derived_jobs_count,omitempty"`
	FeedbackJobsCount         int                 `json:"feedback_jobs_count,omitempty"`
	LastEvaluatedEvidenceHash string              `json:"last_evaluated_evidence_hash,omitempty"`
	Children                  map[string]struct{} `json:"children,omitempty"`
}

// DiscoveryGraph manages the topology of discoveries.
type DiscoveryGraph struct {
	sync.RWMutex     `json:"-"`
	Version          GraphVersion               `json:"version"`
	Config           GraphConfig                `json:"config"`
	Nodes            map[string]*DiscoveryNode  `json:"nodes"`
	BySignature      map[string]string          `json:"by_signature"`
	ByPath           map[string][]string        `json:"by_path"`
	ActionHistory    map[string]struct{}        `json:"action_history"`
	ActionExecutions map[string]ActionExecution `json:"action_executions"`
	Events           []GraphEvent               `json:"events"`
	NegativeCache    map[string][]NegativeEvidence `json:"negative_cache"`
}

const MaxDerivedJobsPerNode = 5
const DefaultMaxEventHistory = 100000

// NewDiscoveryGraph creates a new empty graph.
func NewDiscoveryGraph() *DiscoveryGraph {
	return &DiscoveryGraph{
		Version:          GraphV1,
		Config:           GraphConfig{MaxEvents: DefaultMaxEventHistory, MaxNodes: 100000},
		Nodes:            make(map[string]*DiscoveryNode),
		BySignature:      make(map[string]string),
		ByPath:           make(map[string][]string),
		ActionHistory:    make(map[string]struct{}),
		ActionExecutions: make(map[string]ActionExecution),
		Events:           make([]GraphEvent, 0),
		NegativeCache:    make(map[string][]NegativeEvidence),
	}
}

// AddEvent securely appends a GraphEvent to the ledger, enforcing deduplication and pruning.
// The caller MUST hold g.Lock().
func (g *DiscoveryGraph) AddEvent(event GraphEvent) {
	// Deduplicate by ID
	if event.ID != "" {
		// Optimization: check from newest to oldest since resubmits happen recently
		for i := len(g.Events) - 1; i >= 0; i-- {
			if g.Events[i].ID == event.ID {
				return // Ignore duplicate
			}
		}
	} else {
		event.ID = uuid.New().String()
	}

	g.Events = append(g.Events, event)
	if g.Config.MaxEvents > 0 && len(g.Events) > g.Config.MaxEvents {
		// Prune oldest
		pruneCount := len(g.Events) - g.Config.MaxEvents
		// In-place slide or re-slice
		newEvents := make([]GraphEvent, g.Config.MaxEvents)
		copy(newEvents, g.Events[pruneCount:])
		g.Events = newEvents
	}
}

// GetEvidenceQuality returns the quality score for a given extraction source.
func GetEvidenceQuality(sourceType string) int {
	switch sourceType {
	case "openapi":
		return 95
	case "javascript":
		return 70
	case "wordlist":
		return 20
	default:
		return 10
	}
}

// CalculatePriority determines the priority score of a node based on heuristics.
func CalculatePriority(node *DiscoveryNode) int {
	score := 0
	
	// Medium Priority: Extraction methods
	switch node.SourceType {
	case "javascript", "openapi", "graphql", "sourcemap":
		score += 30
	}

	// Adjust based on EvidenceQuality and Confidence
	if node.Evidence.Quality > 0 {
		score += (node.Evidence.Quality / 2) // Up to +50
	}
	
	if node.Evidence.Confidence > 0 {
		score += (node.Evidence.Confidence / 5) // up to +20
	}

	// Path-based heuristics
	pathLower := strings.ToLower(node.CanonicalPath)
	
	// High Priority: Sensitive endpoints
	sensitiveKeywords := []string{"admin", "internal", "debug", "config", "secret", ".env", ".git", "api"}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(pathLower, kw) {
			score += 50
			break // don't stack multiple sensitive keywords excessively
		}
	}

	// Low Priority: Static assets
	staticExts := []string{".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range staticExts {
		if strings.HasSuffix(pathLower, ext) {
			score -= 50
			break
		}
	}

	// Clamp the score to a reasonable range
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	
	return score
}

// generateSignature creates a deterministic signature for deduplication.
func (g *DiscoveryGraph) generateSignature(parentID, path, sourceType string) string {
	raw := fmt.Sprintf("%s|%s|%s", parentID, path, sourceType)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// contains helper for slices
func containsStr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// EvaluateNode analyzes a DiscoveryNode and generates relevant follow-up actions.
// It automatically deduplicates actions against the ActionHistory and enforces MaxDerivedJobsPerNode.
// The caller MUST hold g.Lock().
func (g *DiscoveryGraph) EvaluateNode(node *DiscoveryNode) []DiscoveryAction {
	var actions []DiscoveryAction

	if node.DerivedJobsCount >= MaxDerivedJobsPerNode {
		return actions // Cap reached
	}

	pathLower := strings.ToLower(node.CanonicalPath)

	// 1. ParamFuzz from OpenAPI paths with parameters
	if node.SourceType == "openapi" && (strings.Contains(pathLower, "{id}") || strings.Contains(pathLower, "{uuid}")) {
		actions = append(actions, DiscoveryAction{
			ID:        uuid.New().String(),
			Type:      "paramfuzz",
			NodeID:    node.ID,
			Reason:    "OpenAPI path parameter detected",
			Priority:  50,
			Status:    ActionPending,
			CreatedAt: time.Now().UTC(),
			Origin:    GraphEventNodeAdded,
		})
	}

	// 2. Auth boundary validation for sensitive JS endpoints
	if node.SourceType == "javascript" && (strings.Contains(pathLower, "/admin") || strings.Contains(pathLower, "/debug") || strings.Contains(pathLower, "/internal")) {
		actions = append(actions, DiscoveryAction{
			ID:        uuid.New().String(),
			Type:      "validation",
			NodeID:    node.ID,
			Reason:    "Sensitive path extracted from JS",
			Priority:  80,
			Status:    ActionPending,
			CreatedAt: time.Now().UTC(),
			Origin:    GraphEventNodeAdded,
		})
	}

	// 3. GraphQL method testing
	if node.SourceType == "graphql" && strings.Contains(pathLower, "mutation") {
		actions = append(actions, DiscoveryAction{
			ID:        uuid.New().String(),
			Type:      "validation",
			NodeID:    node.ID,
			Reason:    "GraphQL mutation endpoint detected",
			Priority:  70,
			Status:    ActionPending,
			CreatedAt: time.Now().UTC(),
			Origin:    GraphEventNodeAdded,
		})
	}

	// Deduplicate against history
	var newActions []DiscoveryAction
	for _, a := range actions {
		key := makeActionKey(node.ID, a.Type)
		if _, exists := g.ActionHistory[key]; !exists {
			g.ActionHistory[key] = struct{}{}
			node.DerivedJobsCount++
			newActions = append(newActions, a)
			
			// Also add to ActionExecutions to track lifecycle
			g.ActionExecutions[a.ID] = ActionExecution{
				Status:    ActionPending,
				StartedAt: time.Now().UTC(),
			}

			// Record event
			g.AddEvent(GraphEvent{
				Type:      GraphEventActionCreated,
				NodeID:    node.ID,
				Timestamp: time.Now().UTC(),
			})

			if node.DerivedJobsCount >= MaxDerivedJobsPerNode {
				break
			}
		}
	}

	return newActions
}

// RecordNegativeEvidence adds an expiring dead-end to the negative cache.
func (g *DiscoveryGraph) RecordNegativeEvidence(path, method string, status int, ttl time.Duration) {
	g.Lock()
	defer g.Unlock()

	g.NegativeCache[path] = append(g.NegativeCache[path], NegativeEvidence{
		Method:    method,
		Status:    status,
		CreatedAt: time.Now().UTC(),
		TTL:       ttl,
	})
}

// IsNegativeCached returns true if the exact path/method is currently un-testable.
func (g *DiscoveryGraph) IsNegativeCached(path, method string) bool {
	g.RLock()
	defer g.RUnlock()

	evs := g.NegativeCache[path]
	if len(evs) == 0 {
		return false
	}

	now := time.Now().UTC()
	for _, ev := range evs {
		if ev.Method == method {
			if now.Sub(ev.CreatedAt) < ev.TTL {
				return true
			}
		}
	}
	return false
}

// IsNodeBlocked checks if a node is currently paused due to CircuitBreaker or Budget.
func (g *DiscoveryGraph) IsNodeBlocked(nodeID string) bool {
	g.RLock()
	defer g.RUnlock()

	node, ok := g.Nodes[nodeID]
	if !ok {
		return false
	}

	// 1. Budget Exceeded
	if node.Budget.MaxRequests > 0 && node.Budget.RequestsUsed >= node.Budget.MaxRequests {
		return true
	}

	// 2. Circuit Breaker
	if node.CircuitBreaker.State == CircuitOpen {
		if time.Now().UTC().Sub(node.CircuitBreaker.OpenedAt) < node.CircuitBreaker.Cooldown {
			return true
		}
		// Transition to HalfOpen is possible on next try, so allow it
	}

	return false
}

// UpdateCircuitBreaker records error telemetry and trips breakers if needed.
func (g *DiscoveryGraph) UpdateCircuitBreaker(nodeID string, errClass string) {
	g.Lock()
	defer g.Unlock()

	node, ok := g.Nodes[nodeID]
	if !ok {
		return
	}

	// If we successfully recorded a hit (not an error), we close the breaker if HalfOpen
	if errClass == "success" {
		node.CircuitBreaker.Consecutive5xx = 0
		node.CircuitBreaker.ConsecutiveTO = 0
		node.CircuitBreaker.ConsecutiveConnE = 0
		if node.CircuitBreaker.State == CircuitHalfOpen {
			node.CircuitBreaker.State = CircuitClosed
		}
		return
	}

	// Record the failure
	switch errClass {
	case "5xx":
		node.CircuitBreaker.Consecutive5xx++
	case "timeout":
		node.CircuitBreaker.ConsecutiveTO++
	case "connection":
		node.CircuitBreaker.ConsecutiveConnE++
	}

	// Trip logic: 3 of same kind
	if node.CircuitBreaker.Consecutive5xx >= 3 || node.CircuitBreaker.ConsecutiveTO >= 3 || node.CircuitBreaker.ConsecutiveConnE >= 3 {
		node.CircuitBreaker.State = CircuitOpen
		node.CircuitBreaker.OpenedAt = time.Now().UTC()
		node.Lifecycle.State = StateBlocked
	}
}

const MaxFeedbackActionsPerNode = 3

// UpdateEvidence acts as the primary feedback loop entrypoint. It mutates the node's scoring,
// logs events, and emits new feedback-driven actions safely.
func (g *DiscoveryGraph) UpdateEvidence(nodeID string, resp ResponseEvidence) []DiscoveryAction {
	g.Lock()
	defer g.Unlock()

	node, exists := g.Nodes[nodeID]
	if !exists {
		return nil
	}

	hashStr := fmt.Sprintf("%d|%s|%d|%v|%s", resp.StatusCode, resp.ContentType, resp.Length, resp.Interesting, resp.Reason)
	if node.LastEvaluatedEvidenceHash == hashStr {
		return nil // Already evaluated this exact evidence signature
	}
	node.LastEvaluatedEvidenceHash = hashStr

	g.AddEvent(GraphEvent{
		Type:      GraphEventResponseObserved,
		NodeID:    node.ID,
		Timestamp: time.Now().UTC(),
	})

	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		node.Confidence -= 20
	} else if resp.StatusCode == 403 || resp.StatusCode == 401 {
		node.Confidence += 20
		node.RiskScore += 40
		node.PriorityScore += 40
	} else if resp.StatusCode == 500 {
		node.RiskScore += 10
	} else if resp.StatusCode == 200 {
		node.Confidence += 10
		node.PriorityScore += 20
		if resp.Interesting {
			node.RiskScore += 30
		}
	} else if resp.StatusCode == 0 {
		node.Confidence -= 5
	}
	
	// Enforce bounds
	if node.Confidence < 0 { node.Confidence = 0 }
	if node.Confidence > 100 { node.Confidence = 100 }
	if node.PriorityScore < 0 { node.PriorityScore = 0 }
	if node.RiskScore < 0 { node.RiskScore = 0 }
	if node.RiskScore > 100 { node.RiskScore = 100 }

	if node.FeedbackJobsCount >= MaxFeedbackActionsPerNode {
		return nil
	}

	var actions []DiscoveryAction
	
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		actions = append(actions, DiscoveryAction{
			ID:        uuid.New().String(),
			Type:      "validation",
			NodeID:    node.ID,
			Reason:    "403 Forbidden response during feedback",
			Priority:  85,
			Status:    ActionPending,
			CreatedAt: time.Now().UTC(),
			Origin:    GraphEventResponseObserved,
		})
	}
	
	var newActions []DiscoveryAction
	for _, a := range actions {
		// Differentiate origin types in history deduplication
		key := makeActionKey(node.ID, a.Type+"_feedback")
		if _, exists := g.ActionHistory[key]; !exists {
			g.ActionHistory[key] = struct{}{}
			node.FeedbackJobsCount++
			newActions = append(newActions, a)
			
			g.ActionExecutions[a.ID] = ActionExecution{
				Status:    ActionPending,
				StartedAt: time.Now().UTC(),
			}

			g.AddEvent(GraphEvent{
				Type:      GraphEventActionCreated,
				NodeID:    node.ID,
				Timestamp: time.Now().UTC(),
			})

			if node.FeedbackJobsCount >= MaxFeedbackActionsPerNode {
				break
			}
		}
	}

	return newActions
}

// AddSourceNode explicitly registers a root discovery source.
func (g *DiscoveryGraph) AddSourceNode(label, sourceType string) (string, []DiscoveryAction) {
	g.Lock()
	defer g.Unlock()

	if g.Nodes == nil {
		g.Nodes = make(map[string]*DiscoveryNode)
		g.BySignature = make(map[string]string)
		g.ByPath = make(map[string][]string)
		g.ActionHistory = make(map[string]struct{})
		g.ActionExecutions = make(map[string]ActionExecution)
		g.Events = make([]GraphEvent, 0)
	}

	sig := g.generateSignature("", "", sourceType)
	if existingID, ok := g.BySignature[sig]; ok {
		return existingID, nil
	}

	id := uuid.New().String()
	node := &DiscoveryNode{
		ID:         id,
		Kind:       NodeSource,
		Label:      label,
		SourceType: sourceType,
		FirstSeen:  time.Now().UTC(),
		Children:   make(map[string]struct{}),
		Lifecycle: NodeLifecycle{
			State:      StateDiscovered,
			LastSeen:   time.Now().UTC(),
			ArchiveAfter: 30 * 24 * time.Hour, // default 30 days
		},
		CircuitBreaker: CircuitBreaker{
			Cooldown: 10 * time.Minute,
		},
		Budget: ScanBudget{
			MaxRequests: 50000, // default max requests
			MaxBytes:    500 * 1024 * 1024,
			MaxTime:     24 * time.Hour,
		},
	}
	node.Evidence.Quality = GetEvidenceQuality(sourceType)
	node.PriorityScore = CalculatePriority(node)
	g.Nodes[id] = node
	g.BySignature[sig] = id

	g.AddEvent(GraphEvent{
		Type:      GraphEventNodeAdded,
		NodeID:    id,
		Timestamp: time.Now().UTC(),
	})

	actions := g.EvaluateNode(node)
	return id, actions
}

// AddPathNode adds a discovered endpoint, linked to an explicit parent.
func (g *DiscoveryGraph) AddPathNode(parentID, path, label, sourceType string, evidence DiscoveryEvidence) (string, []DiscoveryAction) {
	g.Lock()
	defer g.Unlock()

	if g.Nodes == nil {
		g.Nodes = make(map[string]*DiscoveryNode)
		g.BySignature = make(map[string]string)
		g.ByPath = make(map[string][]string)
		g.ActionHistory = make(map[string]struct{})
		g.ActionExecutions = make(map[string]ActionExecution)
		g.Events = make([]GraphEvent, 0)
	}

	sig := g.generateSignature(parentID, path, sourceType)
	if existingID, ok := g.BySignature[sig]; ok {
		// Existing node: maybe re-evaluate if we want, but usually we just return.
		// To be safe on re-discoveries, we could evaluate again (dedup prevents dups).
		actions := g.EvaluateNode(g.Nodes[existingID])
		return existingID, actions
	}

	id := uuid.New().String()
	node := &DiscoveryNode{
		ID:                      id,
		Kind:                    NodePath,
		CanonicalPath:           path,
		Label:                   label,
		ParentID:                parentID,
		SourceType:              sourceType,
		Evidence:                evidence,
		FirstSeen:               time.Now().UTC(),
		FirstDiscoveredByNodeID: parentID,
		Children:                make(map[string]struct{}),
		Lifecycle: NodeLifecycle{
			State:      StateDiscovered,
			LastSeen:   time.Now().UTC(),
			ArchiveAfter: 30 * 24 * time.Hour,
		},
		CircuitBreaker: CircuitBreaker{
			Cooldown: 10 * time.Minute,
		},
		Budget: ScanBudget{
			MaxRequests: 50000,
			MaxBytes:    500 * 1024 * 1024,
			MaxTime:     24 * time.Hour,
		},
	}
	
	if node.Evidence.Quality == 0 {
		node.Evidence.Quality = GetEvidenceQuality(sourceType)
	}
	
	node.PriorityScore = CalculatePriority(node)
	g.Nodes[id] = node

	g.BySignature[sig] = id
	g.ByPath[path] = append(g.ByPath[path], id)

	if parentID != "" {
		if parentNode, ok := g.Nodes[parentID]; ok {
			if parentNode.Children == nil {
				parentNode.Children = make(map[string]struct{})
			}
			parentNode.Children[id] = struct{}{}
		}
	}

	g.AddEvent(GraphEvent{
		Type:      GraphEventNodeAdded,
		NodeID:    id,
		Timestamp: time.Now().UTC(),
	})

	actions := g.EvaluateNode(node)
	return id, actions
}

// GetSnapshot returns a safe, read-only deep-ish copy of the graph for rendering.
func (g *DiscoveryGraph) GetSnapshot() *DiscoveryGraph {
	g.RLock()
	defer g.RUnlock()

	snap := &DiscoveryGraph{
		Version:     g.Version,
		Nodes:       make(map[string]*DiscoveryNode, len(g.Nodes)),
		BySignature: make(map[string]string, len(g.BySignature)),
		ByPath:      make(map[string][]string, len(g.ByPath)),
	}

	for k, v := range g.BySignature {
		snap.BySignature[k] = v
	}
	for k, v := range g.ByPath {
		c := make([]string, len(v))
		copy(c, v)
		snap.ByPath[k] = c
	}
	for k, n := range g.Nodes {
		nodeCopy := *n
		if n.Tags != nil {
			nodeCopy.Tags = make([]string, len(n.Tags))
			copy(nodeCopy.Tags, n.Tags)
		}
		if n.Children != nil {
			nodeCopy.Children = make(map[string]struct{}, len(n.Children))
			for c := range n.Children {
				nodeCopy.Children[c] = struct{}{}
			}
		}
		snap.Nodes[k] = &nodeCopy
	}
	return snap
}

// ─── Query Helpers ────────────────────────────────────────────────────────────

// FindPathsBySource returns all nodes that originated from a given sourceType (e.g., "javascript").
func (g *DiscoveryGraph) FindPathsBySource(sourceType string) []*DiscoveryNode {
	g.RLock()
	defer g.RUnlock()

	var results []*DiscoveryNode
	for _, n := range g.Nodes {
		if n.SourceType == sourceType {
			results = append(results, n)
		}
	}
	return results
}

// FindOrphanNodes returns nodes that have no children, indicating terminal points
// or nodes that haven't been further explored.
func (g *DiscoveryGraph) FindOrphanNodes() []*DiscoveryNode {
	g.RLock()
	defer g.RUnlock()

	var results []*DiscoveryNode
	for _, n := range g.Nodes {
		if len(n.Children) == 0 {
			results = append(results, n)
		}
	}
	return results
}

// GetHighPriorityNodes returns all nodes with a priority score >= minScore.
func (g *DiscoveryGraph) GetHighPriorityNodes(minScore int) []*DiscoveryNode {
	g.RLock()
	defer g.RUnlock()

	var results []*DiscoveryNode
	for _, n := range g.Nodes {
		if n.PriorityScore >= minScore {
			results = append(results, n)
		}
	}
	return results
}

// GraphSummary provides a high-level overview of the discovery graph.
type GraphSummary struct {
	TotalNodes     int            `json:"total_nodes"`
	NodesByKind    map[string]int `json:"nodes_by_kind"`
	NodesBySource  map[string]int `json:"nodes_by_source"`
	OrphanCount    int            `json:"orphan_count"`
	HighValueCount int            `json:"high_value_count"`
}

// ExportSummary generates a structural breakdown of the current attack surface graph.
func (g *DiscoveryGraph) ExportSummary() GraphSummary {
	g.RLock()
	defer g.RUnlock()

	summary := GraphSummary{
		TotalNodes:    len(g.Nodes),
		NodesByKind:   make(map[string]int),
		NodesBySource: make(map[string]int),
	}

	for _, n := range g.Nodes {
		summary.NodesByKind[string(n.Kind)]++
		
		if n.SourceType != "" {
			summary.NodesBySource[n.SourceType]++
		} else {
			summary.NodesBySource["unknown"]++
		}

		if len(n.Children) == 0 {
			summary.OrphanCount++
		}
		
		if n.PriorityScore >= 50 {
			summary.HighValueCount++
		}
	}

	return summary
}
