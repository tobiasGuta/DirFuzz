package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ValidateGraph checks the consistency of the discovery topology to prevent logic errors.
func (g *DiscoveryGraph) ValidateGraph() error {
	g.RLock()
	defer g.RUnlock()

	for id, node := range g.Nodes {
		if node.ID != id {
			return fmt.Errorf("node ID mismatch: key=%s, node.ID=%s", id, node.ID)
		}

		if node.Confidence < 0 || node.Confidence > 100 {
			return fmt.Errorf("node %s has invalid confidence %d", id, node.Confidence)
		}
		if node.RiskScore < 0 || node.RiskScore > 100 {
			return fmt.Errorf("node %s has invalid risk score %d", id, node.RiskScore)
		}
		if node.PriorityScore < 0 {
			return fmt.Errorf("node %s has invalid priority score %d", id, node.PriorityScore)
		}

		// Check parent edge
		if node.ParentID != "" {
			if _, exists := g.Nodes[node.ParentID]; !exists {
				return fmt.Errorf("node %s has orphan ParentID %s", id, node.ParentID)
			}
		}

		// Check child edges
		for childID := range node.Children {
			if _, exists := g.Nodes[childID]; !exists {
				return fmt.Errorf("node %s has orphan child %s", id, childID)
			}
		}
	}

	if err := g.DetectCycles(); err != nil {
		return err
	}

	return nil
}

// DetectCycles explicitly prevents topological loops (e.g., A -> B -> C -> A).
func (g *DiscoveryGraph) DetectCycles() error {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var detect func(nodeID string) error
	detect = func(nodeID string) error {
		if recStack[nodeID] {
			return fmt.Errorf("graph cycle detected at node %s", nodeID)
		}
		if visited[nodeID] {
			return nil
		}
		
		visited[nodeID] = true
		recStack[nodeID] = true
		defer func() { recStack[nodeID] = false }()

		node, exists := g.Nodes[nodeID]
		if !exists {
			return nil
		}

		for childID := range node.Children {
			if err := detect(childID); err != nil {
				return err
			}
		}
		return nil
	}

	for id := range g.Nodes {
		if !visited[id] {
			if err := detect(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExportDOT generates a Graphviz (.dot) visualization of the discovery topology.
func (g *DiscoveryGraph) ExportDOT() string {
	g.RLock()
	defer g.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph Discovery {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled, fontname=\"Helvetica\"];\n")

	for id, node := range g.Nodes {
		label := node.CanonicalPath
		if label == "" {
			label = node.Label
		}
		
		color := "lightgrey"
		if node.RiskScore > 50 {
			color = "lightpink"
		} else if node.Confidence > 50 {
			color = "lightblue"
		}

		escapedLabel := strings.ReplaceAll(label, "\"", "\\\"")
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\", fillcolor=\"%s\"];\n", id, escapedLabel, color))

		for childID := range node.Children {
			sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\";\n", id, childID))
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ExportJSON generates a flattened, automation-friendly JSON payload.
func (g *DiscoveryGraph) ExportJSON() ([]byte, error) {
	g.RLock()
	defer g.RUnlock()

	type ExportNode struct {
		ID            string `json:"id"`
		Path          string `json:"path"`
		ParentID      string `json:"parent_id,omitempty"`
		Priority      int    `json:"priority"`
		Risk          int    `json:"risk"`
		Confidence    int    `json:"confidence"`
		SourceType    string `json:"source_type"`
		Quality       int    `json:"quality"`
		State         int    `json:"state"`
	}

	var output struct {
		Nodes []ExportNode `json:"nodes"`
	}

	for _, node := range g.Nodes {
		output.Nodes = append(output.Nodes, ExportNode{
			ID:         node.ID,
			Path:       node.CanonicalPath,
			ParentID:   node.ParentID,
			Priority:   node.PriorityScore,
			Risk:       node.RiskScore,
			Confidence: node.Confidence,
			SourceType: node.SourceType,
			Quality:    node.Evidence.Quality,
			State:      int(node.Lifecycle.State),
		})
	}

	return json.MarshalIndent(output, "", "  ")
}
