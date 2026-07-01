package tui

import (
	"dirfuzz/pkg/ui/viewmodel"
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#7D56F4")).Padding(0, 1)
	borderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#383838"))
	statLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Width(12)
	statValueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
)

type MetricsWidget struct {
	Data viewmodel.MetricsWidget
}

func (w *MetricsWidget) Render(width int, height int) string {
	b := borderStyle.Width(width - 2).Height(height - 2)

	content := fmt.Sprintf("%s %s\n", statLabelStyle.Render("Workers"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.Workers)))
	content += fmt.Sprintf("%s %s\n", statLabelStyle.Render("Requests"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.Requests)))
	content += fmt.Sprintf("%s %s\n", statLabelStyle.Render("Findings"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.TotalFindings)))
	content += fmt.Sprintf("%s %s", statLabelStyle.Render("Confirmed"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.Confirmed)))

	return b.Render(lipgloss.JoinVertical(lipgloss.Left, titleStyle.Render("Metrics"), "", content))
}

type QueueWidget struct {
	Data viewmodel.QueueWidget
}

func (w *QueueWidget) Render(width int, height int) string {
	b := borderStyle.Width(width - 2).Height(height - 2)

	content := fmt.Sprintf("%s %s\n", statLabelStyle.Render("Validation"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.Validation)))
	content += fmt.Sprintf("%s %s\n", statLabelStyle.Render("ParamFuzz"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.ParamFuzz)))
	content += fmt.Sprintf("%s %s", statLabelStyle.Render("Discovery"), statValueStyle.Render(fmt.Sprintf("%d", w.Data.Discovery)))

	return b.Render(lipgloss.JoinVertical(lipgloss.Left, titleStyle.Render("Queue"), "", content))
}

type TimelineWidget struct {
	Data viewmodel.TimelineWidget
}

func (w *TimelineWidget) Render(width int, height int) string {
	b := borderStyle.Width(width - 2).Height(height - 2)
	
	var lines []string
	lines = append(lines, titleStyle.Render("Recent Events"), "")
	
	maxLines := height - 4
	for i, e := range w.Data.Entries {
		if i >= maxLines {
			break
		}
		timeStr := lipgloss.NewStyle().Foreground(lipgloss.Color("#555555")).Render(e.Time)
		lines = append(lines, fmt.Sprintf("%s %s", timeStr, e.Message))
	}

	return b.Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
}
