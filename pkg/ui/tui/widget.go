package tui

type Widget interface {
	Render(width int, height int) string
}
