package validation

import (
	"crypto/sha256"
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
	"fmt"
	"time"
)

type Planner interface {
	Suggest(finding viewmodel.FindingDetailView) []models.ValidationRequest
}

type DefaultPlanner struct{}

func (p *DefaultPlanner) Suggest(finding viewmodel.FindingDetailView) []models.ValidationRequest {
	var reqs []models.ValidationRequest

	// If this is an IDOR or Auth issue, suggest Auth Boundary test
	if finding.Title == "IDOR" || finding.Title == "403 without authentication" {
		req := models.ValidationRequest{
			ID:        fmt.Sprintf("val-%s", finding.FindingID),
			FindingID: finding.FindingID,
			NodeID:    "node-" + finding.FindingID,
			Type:      models.ValidateAuthBoundary,
			Reason:    "Test ownership boundary across different roles",
			CreatedAt: time.Now(),
			Status:    models.StatusPending,
		}
		
		hashInput := fmt.Sprintf("%s|%s|%s", req.FindingID, req.NodeID, req.Type)
		req.DedupKey = fmt.Sprintf("%x", sha256.Sum256([]byte(hashInput)))
		
		reqs = append(reqs, req)
	}

	return reqs
}
