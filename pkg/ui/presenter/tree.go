package presenter

import "dirfuzz/pkg/ui/models"

type SurfaceIdentity struct {
	NodeID   string
	PathHash string
}

type TreeState struct {
	Expanded map[string]bool
	CursorID string
}

type TreePresenter interface {
	RenderBranch(idx *models.SurfaceIndex, state TreeState, rootID string) []string
}

type DefaultTreePresenter struct{}

func (p *DefaultTreePresenter) RenderBranch(idx *models.SurfaceIndex, state TreeState, rootID string) []string {
	var lines []string
	p.renderNode(idx, state, rootID, 0, &lines)
	return lines
}

func (p *DefaultTreePresenter) renderNode(idx *models.SurfaceIndex, state TreeState, nodeID string, depth int, lines *[]string) {
	node, ok := idx.Nodes[nodeID]
	if !ok {
		return
	}

	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	prefix := "+ "
	if state.Expanded[nodeID] {
		prefix = "- "
	}
	if len(node.ChildIDs) == 0 {
		prefix = "  "
	}

	cursorMarker := " "
	if state.CursorID == nodeID {
		cursorMarker = ">"
	}

	// Just a simple representation for rendering
	line := indent + cursorMarker + prefix + node.Name
	*lines = append(*lines, line)

	if state.Expanded[nodeID] {
		for _, childID := range node.ChildIDs {
			p.renderNode(idx, state, childID, depth+1, lines)
		}
	}
}
