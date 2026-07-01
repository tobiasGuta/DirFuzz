package report

import (
	"dirfuzz/pkg/ui/viewmodel"
	"testing"
	"time"
)

func TestReportBuilderScale(t *testing.T) {
	// Simulate memory overhead of having 100,000 findings loaded in UI state
	findings := make([]viewmodel.FindingDetailView, 100000)
	
	// Ensure the array doesn't get optimized away
	findings[99999] = viewmodel.FindingDetailView{
		FindingID: "complex-finding",
		Title:     "Complex Evidence Chain",
		Severity:  viewmodel.StyleCritical,
		Readiness: viewmodel.ReportReadiness{Ready: true},
		Evidence: viewmodel.EvidenceView{
			Timeline: make([]viewmodel.EvidenceTimelineItem, 50), // 50 evidence steps
		},
	}

	builder := &DefaultBuilder{}

	start := time.Now()
	// Build the specific finding
	_, err := builder.Build(findings[99999])
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Builder failed: %v", err)
	}

	// Sub 10ms execution requirement for building the report and hashing it
	if elapsed > 10 * time.Millisecond {
		t.Fatalf("ReportBuilder execution took too long: %v (budget 10ms)", elapsed)
	}
}
