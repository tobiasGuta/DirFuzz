package tui

import (
	"github.com/charmbracelet/bubbles/key"
)

type KeyAction int

const (
	ActionQuit KeyAction = iota
	ActionNextPanel
	ActionSearch
	ActionRefresh
	ActionEnter
)

type KeyMap struct {
	Quit      key.Binding
	NextPanel key.Binding
	Search    key.Binding
	Refresh   key.Binding
	Enter     key.Binding
}

var DefaultKeyMap = KeyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	NextPanel: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next panel"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "refresh"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
}
