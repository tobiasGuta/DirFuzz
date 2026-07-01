package presenter

import (
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
	"strings"
)

type defaultDashboardPresenter struct{}

func NewDashboardPresenter() DashboardPresenter {
	return &defaultDashboardPresenter{}
}

func (p *defaultDashboardPresenter) Metrics(model models.PresentationModel, ctx PresenterContext) viewmodel.MetricsWidget {
	return viewmodel.MetricsWidget{
		Workers:       int(model.Metrics.WorkerCount),
		Requests:      int(model.Metrics.RequestsSent),
		TotalFindings: int(model.Metrics.FindingsCreated),
		Confirmed:     int(model.Metrics.NodesConfirmed), // roughly mapping
	}
}

func (p *defaultDashboardPresenter) Queue(model models.PresentationModel, ctx PresenterContext) viewmodel.QueueWidget {
	return viewmodel.QueueWidget{
		Validation: model.Queue.Validation,
		ParamFuzz:  model.Queue.ParamFuzz,
		Discovery:  model.Queue.Discovery,
	}
}

func (p *defaultDashboardPresenter) Timeline(model models.PresentationModel, ctx PresenterContext) viewmodel.TimelineWidget {
	var entries []viewmodel.TimelineEntry
	for _, t := range model.Timeline {
		entries = append(entries, viewmodel.TimelineEntry{
			Time:    t.Time.Format(ctx.TimeFormat),
			Message: t.Message,
		})
	}
	return viewmodel.TimelineWidget{Entries: entries}
}

func (p *defaultDashboardPresenter) Dashboard(model models.PresentationModel, ctx PresenterContext) viewmodel.DashboardView {
	var topRisk []viewmodel.FindingView
	for _, f := range model.Findings {
		style := viewmodel.StyleMedium
		lsev := strings.ToLower(f.Severity)
		if strings.Contains(lsev, "crit") {
			style = viewmodel.StyleCritical
		} else if strings.Contains(lsev, "high") {
			style = viewmodel.StyleHigh
		} else if strings.Contains(lsev, "low") {
			style = viewmodel.StyleLow
		}

		topRisk = append(topRisk, viewmodel.FindingView{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Score:    f.Score,
			Style:    style,
		})
		if len(topRisk) >= 10 {
			break // Only top 10
		}
	}

	target := "Unknown"
	if len(model.Targets) > 0 {
		target = model.Targets[0].Host
	}

	return viewmodel.DashboardView{
		Target:   target,
		Metrics:  p.Metrics(model, ctx),
		Queue:    p.Queue(model, ctx),
		Timeline: p.Timeline(model, ctx),
		TopRisk:  topRisk,
	}
}
