package campaign

import (
	"fmt"
	"sort"
)

type CampaignSnapshot struct {
	ID       string
	TargetID string
	Nodes    map[string]EvidenceProjection
}

type DiffEngine interface {
	Compare(snapOld CampaignSnapshot, snapNew CampaignSnapshot) CampaignDiff
}

type DefaultDiffEngine struct{}

func computeDiffHash(oldNode, newNode EvidenceProjection) string {
	return fmt.Sprintf("diff-%s-%d-%d", newNode.Path, oldNode.RiskScore, newNode.RiskScore)
}

func (e *DefaultDiffEngine) Compare(snapOld CampaignSnapshot, snapNew CampaignSnapshot) CampaignDiff {
	diff := CampaignDiff{
		Endpoints: make([]EndpointDiff, 0),
	}

	oldNodes := make(map[string]EvidenceProjection, len(snapOld.Nodes))
	for k, v := range snapOld.Nodes {
		oldNodes[k] = v
	}

	newKeys := make([]string, 0, len(snapNew.Nodes))
	for k := range snapNew.Nodes {
		newKeys = append(newKeys, k)
	}
	sort.Strings(newKeys)

	for _, nodeID := range newKeys {
		newNode := snapNew.Nodes[nodeID]
		oldNode, exists := oldNodes[nodeID]
		if !exists {
			diff.TotalNew++
			diff.Endpoints = append(diff.Endpoints, EndpointDiff{
				NodeID:   nodeID,
				Path:     newNode.Path,
				Category: DiffNew,
				Severity: DiffInteresting,
				Fingerprint: DiffFingerprint{
					TargetID: snapNew.TargetID,
					DiffHash: fmt.Sprintf("new-%s", newNode.Path),
				},
				Current:  newNode,
			})
		} else {
			reasons, sev := detectChanges(oldNode, newNode)
			if len(reasons) > 0 {
				diff.TotalChange++
				diff.Endpoints = append(diff.Endpoints, EndpointDiff{
					NodeID:   nodeID,
					Path:     newNode.Path,
					Category: DiffChanged,
					Severity: sev,
					Fingerprint: DiffFingerprint{
						TargetID: snapNew.TargetID,
						DiffHash: computeDiffHash(oldNode, newNode),
					},
					Reasons:  reasons,
					Previous: oldNode,
					Current:  newNode,
				})
			}
			delete(oldNodes, nodeID)
		}
	}

	oldKeys := make([]string, 0, len(oldNodes))
	for k := range oldNodes {
		oldKeys = append(oldKeys, k)
	}
	sort.Strings(oldKeys)

	for _, nodeID := range oldKeys {
		oldNode := oldNodes[nodeID]
		diff.TotalRemove++
		diff.Endpoints = append(diff.Endpoints, EndpointDiff{
			NodeID:   nodeID,
			Path:     oldNode.Path,
			Category: DiffRemoved,
			Severity: DiffInfo,
			Fingerprint: DiffFingerprint{
				TargetID: snapOld.TargetID,
				DiffHash: fmt.Sprintf("rem-%s", oldNode.Path),
			},
			Previous: oldNode,
		})
	}

	return diff
}

func detectChanges(oldNode, newNode EvidenceProjection) ([]ChangeReason, DiffSeverity) {
	var reasons []ChangeReason
	severity := DiffInfo

	if oldNode.RiskScore != newNode.RiskScore {
		reasons = append(reasons, ChangeReason{
			Type:   StatusChanged,
			Before: fmt.Sprintf("Score:%d", oldNode.RiskScore),
			After:  fmt.Sprintf("Score:%d", newNode.RiskScore),
		})
		
		diffAmt := newNode.RiskScore - oldNode.RiskScore
		if diffAmt < 0 {
			diffAmt = -diffAmt
		}
		
		if diffAmt > 50 {
			severity = DiffCritical
		} else {
			severity = DiffInteresting
		}
	}

	return reasons, severity
}
