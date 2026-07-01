package presenter

import (
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
)

// Clock abstracts time fetching
type Clock interface {
	Now() string
}

// PresenterContext holds abstract configurations for formatting UI elements.
type PresenterContext struct {
	Clock      Clock
	PageSize   int
	TimeFormat string
}

type DashboardPresenter interface {
	Metrics(model models.PresentationModel, ctx PresenterContext) viewmodel.MetricsWidget
	Queue(model models.PresentationModel, ctx PresenterContext) viewmodel.QueueWidget
	Timeline(model models.PresentationModel, ctx PresenterContext) viewmodel.TimelineWidget
	Dashboard(model models.PresentationModel, ctx PresenterContext) viewmodel.DashboardView
}

type FindingsPresenter interface {
	Page(model models.PresentationModel, ctx PresenterContext, offset int) viewmodel.FindingsPage
}

type PresentationService struct {
	Dashboard DashboardPresenter
	Findings  FindingsPresenter
	Explorer  FindingExplorerPresenter
}

func NewPresentationService(dash DashboardPresenter, find FindingsPresenter, explorer FindingExplorerPresenter) *PresentationService {
	return &PresentationService{
		Dashboard: dash,
		Findings:  find,
		Explorer:  explorer,
	}
}
