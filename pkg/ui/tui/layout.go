package tui

type LayoutMode int

const (
	LayoutFull LayoutMode = iota
	LayoutCompact
	LayoutMinimal
)

type TerminalCapabilities struct {
	Width   int
	Height  int
	Color   bool
	Unicode bool
}

func DetectLayoutMode(caps TerminalCapabilities) LayoutMode {
	if caps.Width >= 120 && caps.Height >= 30 {
		return LayoutFull
	} else if caps.Width >= 80 {
		return LayoutCompact
	}
	return LayoutMinimal
}
