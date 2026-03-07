package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/engine"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles for the TUI
var (
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#BD93F9"))                                           // Dracula Purple
	boxStyle       = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#6272A4")).Padding(0, 1) // Dracula Comment/Selection
	activeBoxStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#50FA7B")).Padding(0, 1) // Green Border for Focus

	// Dracula Palette
	draculaBg       = lipgloss.Color("#282A36")
	draculaCurrLine = lipgloss.Color("#44475A")
	draculaFg       = lipgloss.Color("#F8F8F2")
	draculaComment  = lipgloss.Color("#6272A4")
	draculaCyan     = lipgloss.Color("#8BE9FD")
	draculaGreen    = lipgloss.Color("#50FA7B")
	draculaOrange   = lipgloss.Color("#FFB86C")
	draculaPink     = lipgloss.Color("#FF79C6")
	draculaPurple   = lipgloss.Color("#BD93F9")
	draculaRed      = lipgloss.Color("#FF5555")
	draculaYellow   = lipgloss.Color("#F1FA8C")

	okStyle    = lipgloss.NewStyle().Foreground(draculaGreen)
	errStyle   = lipgloss.NewStyle().Foreground(draculaRed)
	warnStyle  = lipgloss.NewStyle().Foreground(draculaOrange)
	infoStyle  = lipgloss.NewStyle().Foreground(draculaCyan)
	pauseStyle = lipgloss.NewStyle().Bold(true).Foreground(draculaPink).Blink(true)
	cmdStyle   = lipgloss.NewStyle().Foreground(draculaFg).Background(draculaCurrLine)

	// Log Styles
	pathStyle = lipgloss.NewStyle().Foreground(draculaCyan).Bold(true)
	status200 = lipgloss.NewStyle().Foreground(draculaGreen)
	status300 = lipgloss.NewStyle().Foreground(draculaPurple)
	status400 = lipgloss.NewStyle().Foreground(draculaOrange)
	status500 = lipgloss.NewStyle().Foreground(draculaRed)
	sizeStyle = lipgloss.NewStyle().Foreground(draculaYellow)
)

// Messages for updating the TUI from the engine
type TickMsg time.Time
type LogMsg engine.Result
type StatusMsg string // For validation errors etc
type StatsMsg struct {
	RPS       int
	QueueSize int
	Err403    int
	Err429    int
	Err500    int

	// Progress
	ProgressCurrent int64
	ProgressTotal   int64
}

// Model holds the state of the TUI
type Model struct {
	// Telemetry
	RPS       int
	QueueSize int
	Err403    int
	Err429    int
	Err500    int
	ErrConn   int
	StatusStr string

	// Progress
	ProgressTotal   int64
	ProgressCurrent int64

	// State
	Paused    bool
	PrePaused bool // Tracks if user had manually paused before command mode
	Workers   int
	Engine    *engine.Engine

	// Command Mode
	CommandMode     bool
	TextInput       textinput.Model
	Suggestions     []CommandDef
	SuggestionIndex int

	// Viewport for Top Panel
	Viewport     viewport.Model
	HelpViewport viewport.Model
	TopFocused   bool

	// Logs
	Logs         []engine.Result
	MaxLogs      int
	ScrollOffset int // 0 means waiting at the bottom (auto-scroll), > 0 means scrolled up

	// Dimensions
	Width  int
	Height int
}

// CommandDef defines a CLI command with help text
type CommandDef struct {
	Name        string
	Description string
	Usage       string
}

// AvailableCommands is the static list of all commands
var AvailableCommands = []CommandDef{
	{Name: "worker", Description: "Set worker count", Usage: ":worker [int]"},
	{Name: "set-url", Description: "Set target URL", Usage: ":set-url [URL]"},
	{Name: "set-ua", Description: "Set User-Agent string", Usage: ":set-ua [AgentString]"},
	{Name: "set-delay", Description: "Set request delay", Usage: ":set-delay [10ms|1s]"},
	{Name: "add-header", Description: "Add custom HTTP header", Usage: ":add-header [Key]: [Value]"},
	{Name: "rm-header", Description: "Remove HTTP header", Usage: ":rm-header [Key]"},
	{Name: "filter-size", Description: "Filter response size", Usage: ":filter-size [bytes]"},
	{Name: "rm-filter-size", Description: "Remove size filter", Usage: ":rm-filter-size [bytes]"},
	{Name: "filter-code", Description: "Add Status Code to Match List", Usage: ":filter-code [200|403]"},
	{Name: "rm-filter-code", Description: "Remove Status Code from Match List", Usage: ":rm-filter-code [200|403]"},
	{Name: "add-ext", Description: "Add Extension to scanner", Usage: ":add-ext [php|txt]"},
	{Name: "rm-ext", Description: "Remove Extension from scanner", Usage: ":rm-ext [php]"},
	{Name: "set-mutate", Description: "Enable/Disable Smart Mutation", Usage: ":set-mutate [on|off]"},
	{Name: "wordlist", Description: "Hot-swap wordlist file", Usage: ":wordlist [path]"},
	{Name: "help", Description: "Show available commands", Usage: ":help"},
}

// NewModel initializes the TUI state
func NewModel(eng *engine.Engine, initialWorkers int) Model {
	ti := textinput.New()
	ti.Placeholder = "Type command..."
	ti.CharLimit = 156
	// ti.Width = 50 // Removed fixed width so it can be responsive

	// Initialize Help Viewport with default content
	hv := viewport.New(0, 0)
	helpText := lipgloss.NewStyle().Foreground(draculaPink).Render("AVAILABLE COMMANDS (Use arrow keys to scroll):") + "\n" +
		":run                  - Restart scan with current configs\n" +
		":set-ua [Agent]       - Set User-Agent\n" +
		":add-header [K]: [V]  - Set Header\n" +
		":rm-header [K]        - Remove Header\n" +
		":set-delay [dur]      - Set Delay (e.g., 50ms)\n" +
		":worker [int]         - Set Worker threads\n" +
		":filter-size [bytes]  - Filter by Size\n" +
		":rm-filter-size [s]   - Remove Size Filter\n" +
		":filter-code [code]   - Add Status Match\n" +
		":rm-filter-code [c]   - Remove Status Match\n" +
		":add-ext [ext]        - Add Extension\n" +
		":rm-ext [ext]         - Remove Extension\n" +
		":set-mutate [on|off]  - Toggle Mutation\n" +
		":wordlist [path]      - Hot-swap Wordlist\n" +
		":run                  - Resume Scanning"
	hv.SetContent(helpText)

	return Model{
		Workers:      initialWorkers,
		MaxLogs:      1000,
		Logs:         []engine.Result{},
		Engine:       eng,
		TextInput:    ti,
		Suggestions:  []CommandDef{},
		TopFocused:   false, // Bottom focused by default
		HelpViewport: hv,
	}
}

// Helper to generate telemetry string for the viewport
func (m Model) renderTelemetryContent() string {

	// --- Top Half: Telemetry ---
	status := okStyle.Render("RUNNING (v2)")

	// If in command mode, show PAUSED (CMD) unless manually paused
	if m.Paused {
		if m.CommandMode && !m.PrePaused {
			status = pauseStyle.Render("PAUSED (CMD)")
		} else {
			status = pauseStyle.Render("PAUSED")
		}
	}

	// Fetch current config for display
	ua, filters, headers, delay, extensions := m.Engine.ConfigSnapshot()
	sort.Ints(filters)
	filtersStr := "None"
	if len(filters) > 0 {
		strs := make([]string, len(filters))
		for i, v := range filters {
			strs[i] = strconv.Itoa(v)
		}
		filtersStr = strings.Join(strs, ",")
	}

	extentionsStr := "None"
	if len(extensions) > 0 {
		extentionsStr = strings.Join(extensions, ",")
	}

	headersBlock := "             [Headers: None]"
	if len(headers) > 0 {
		var hList []string
		for k, v := range headers {
			if k != "User-Agent" { // User-Agent is already shown elsewhere usually
				hList = append(hList, fmt.Sprintf("%s:%s", k, v))
			}
		}
		sort.Strings(hList)
		if len(hList) > 0 {
			var formattedHeaders []string
			for _, h := range hList {
				styledHeader := lipgloss.NewStyle().Foreground(draculaGreen).Render(h)
				formattedHeaders = append(formattedHeaders, fmt.Sprintf("             [Headers: %s]", styledHeader))
			}
			headersBlock = strings.Join(formattedHeaders, "\n")
		}
	}

	displayUA := ua

	// Left Side: Telemetry
	targetURL := m.Engine.BaseURL()
	telemetryLeft := fmt.Sprintf(
		"%s\n\n"+
			"Target URL:  %s\n"+
			"Status:      %s\n"+
			"Workers:     %s (Press L/R or :worker)\n"+
			"Progress:    %s\n"+
			"RPS:         %s\n"+
			"Params:      [Delay: %s]\n"+
			"Queue Size:  %s\n\n"+
			"Config:      [UA: %s]\n"+
			"             [Filter Sizes: %s]\n"+
			"             [Ext: %s]\n"+
			"%s\n\n"+
			"Errors:      [Conn: %s] [403: %s]  [429: %s]  [500: %s]\n\n"+
			"Controls:    [Tab] Switch Focus  [p] Pause/Resume  [:] Command",
		titleStyle.Render("DirFuzz Telemetry"),
		lipgloss.NewStyle().Foreground(draculaPink).Render(targetURL),
		status,
		infoStyle.Render(fmt.Sprintf("%d", m.Workers)),
		lipgloss.NewStyle().Foreground(draculaCyan).Render(fmt.Sprintf("%d/%d", m.ProgressCurrent, m.ProgressTotal)),
		infoStyle.Render(fmt.Sprintf("%d", m.RPS)),
		lipgloss.NewStyle().Foreground(draculaPink).Render(delay.String()),
		infoStyle.Render(fmt.Sprintf("%d", m.QueueSize)),
		lipgloss.NewStyle().Foreground(draculaOrange).Render(displayUA),
		lipgloss.NewStyle().Foreground(draculaYellow).Render(filtersStr),
		lipgloss.NewStyle().Foreground(draculaPurple).Render(extentionsStr),
		headersBlock,
		errStyle.Render(fmt.Sprintf("%d", m.ErrConn)),
		warnStyle.Render(fmt.Sprintf("%d", m.Err403)),
		warnStyle.Render(fmt.Sprintf("%d", m.Err429)),
		errStyle.Render(fmt.Sprintf("%d", m.Err500)),
	)

	if m.StatusStr != "" {
		// Use green/cyan for success-like messages to differentiate from red errors
		style := lipgloss.NewStyle().Foreground(draculaGreen)
		if strings.HasPrefix(m.StatusStr, "Error:") {
			style = errStyle
		}
		telemetryLeft += "\n\n" + style.Render(m.StatusStr)
	}

	return telemetryLeft
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	// Start the tick timer for UI refreshes (if needed for animations/time)
	// Also focus input just in case, though we only need it in command mode
	// And start listening for engine results
	return tea.Batch(
		tickCmd(),
		textinput.Blink,
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var inputCmd tea.Cmd

	// Update Top Viewport Content on every relevant cycle (stats/logs/commands)
	// We do this preemptively or reactively. Let's do it reactively at end, but we need 'm' updated first.
	// Actually, viewport.SetContent() doesn't trigger a re-render unless View() is called.
	// But scrolling state is in Viewport.

	switch msg := msg.(type) {

	// Handle keyboard events
	case tea.KeyMsg:
		// Command Mode Logic
		if m.CommandMode {
			// Always allow scrolling Help Viewport with Page keys while in command mode
			if msg.String() == "pgup" {
				m.HelpViewport.LineUp(5)
				return m, nil
			} else if msg.String() == "pgdown" {
				m.HelpViewport.LineDown(5)
				return m, nil
			} else if msg.String() == "up" && len(m.Suggestions) == 0 {
				m.HelpViewport.LineUp(1)
				return m, nil
			} else if msg.String() == "down" && len(m.Suggestions) == 0 {
				m.HelpViewport.LineDown(1)
				return m, nil
			}

			// If not a scroll key, reset status string on typing
			if msg.Type != tea.KeyEnter {
				// m.StatusStr = "" // Optional: Clear status on new typing? Keeps errors visible until next enter.
			}

			switch msg.Type {
			case tea.KeyEnter:
				val := m.TextInput.Value()
				m.StatusStr = "" // Clear previous status

				// Empty command -> Restore Pause State / Exit Command Mode
				if strings.TrimSpace(val) == "" {
					m.CommandMode = false
					m.TextInput.Blur()
					m.TextInput.Reset()
					// Restore previous pause state
					m.Paused = m.PrePaused
					m.Engine.SetPaused(m.Paused)

					// Full width for viewport when leaving command mode
					m.Viewport.Width = m.Width - 4
					m.updateTelemetry()
					m.Viewport.GotoTop()
					return m, nil
				}

				// Execute the command
				if err := m.ExecuteCommand(val); err != nil {
					m.StatusStr = fmt.Sprintf("Error: %v", err)
				}

				isHelp := strings.TrimSpace(strings.TrimPrefix(val, ":")) == "help"
				isRun := strings.TrimSpace(strings.TrimPrefix(val, ":")) == "run"

				if isRun {
					// Resume Logic
					m.CommandMode = false
					m.TextInput.Blur()
					m.TextInput.Reset()
					m.Engine.SetPaused(false)
					m.Paused = false
					// Full width for viewport
					m.Viewport.Width = m.Width - 4
					m.updateTelemetry()
					m.Viewport.GotoTop()
				} else {
					// Stay in Command Mode for chaining
					m.TextInput.SetValue("") // Clear input for next command

					// Update view so user sees the change (e.g. added header)
					m.updateTelemetry()

					// If help was shown, scroll to bottom so they see it
					if isHelp {
						m.HelpViewport.GotoTop()
					} else {
						m.Viewport.GotoBottom()
					}
					// Keep suggestions cleared until typing starts again
					m.Suggestions = []CommandDef{}
				}

				return m, nil

			case tea.KeyEsc:
				m.CommandMode = false
				m.TextInput.Blur()
				m.TextInput.Reset()
				// Restore previous pause state
				m.Paused = m.PrePaused
				m.Engine.SetPaused(m.Paused)
				m.Suggestions = []CommandDef{}
				// Full width for viewport
				m.Viewport.Width = m.Width - 4
				m.updateTelemetry()

			case tea.KeyTab:
				// Autocomplete
				if len(m.Suggestions) > 0 {
					selected := m.Suggestions[m.SuggestionIndex]
					val := selected.Name
					if !strings.HasSuffix(val, string(os.PathSeparator)) {
						val += " "
					}
					m.TextInput.SetValue(val)
					m.TextInput.CursorEnd()
					m.Suggestions = []CommandDef{}
				}

			case tea.KeyUp:
				if len(m.Suggestions) > 0 {
					m.SuggestionIndex--
					if m.SuggestionIndex < 0 {
						m.SuggestionIndex = len(m.Suggestions) - 1
					}
				} else {
					// No suggestions -> Scroll Help Viewport Up
					m.HelpViewport.LineUp(1)
				}

			case tea.KeyDown:
				if len(m.Suggestions) > 0 {
					m.SuggestionIndex++
					if m.SuggestionIndex >= len(m.Suggestions) {
						m.SuggestionIndex = 0
					}
				} else {
					// No suggestions -> Scroll Help Viewport Down
					m.HelpViewport.LineDown(1)
				}
			}

			m.TextInput, inputCmd = m.TextInput.Update(msg)

			// Recalculate suggestions based on current input
			inputVal := strings.TrimSpace(m.TextInput.Value())
			m.Suggestions = []CommandDef{}

			// Check if we are typing a wordlist command to give file suggestions
			if strings.HasPrefix(inputVal, "wordlist ") {
				pathPart := strings.TrimSpace(strings.TrimPrefix(inputVal, "wordlist "))
				searchPattern := pathPart + "*"
				if pathPart == "" {
					searchPattern = "*"
				}
				// Expand ~
				if strings.HasPrefix(pathPart, "~") {
					home, err := os.UserHomeDir()
					if err == nil {
						expanded := strings.Replace(pathPart, "~", home, 1)
						searchPattern = expanded + "*"
					}
				}

				matches, err := filepath.Glob(searchPattern)
				if err == nil {
					sort.Strings(matches)
					// Special case for incomplete filename
					if len(matches) == 0 {
						dir, file := filepath.Split(pathPart)
						if dir == "" {
							dir = "."
						}
						searchDir := dir
						if strings.HasPrefix(searchDir, "~") {
							home, _ := os.UserHomeDir()
							searchDir = strings.Replace(searchDir, "~", home, 1)
						}
						globPattern := filepath.Join(searchDir, file+"*")
						matches, _ = filepath.Glob(globPattern)
					}

					m.Suggestions = []CommandDef{}
					for _, match := range matches {
						displayName := match
						if strings.HasPrefix(pathPart, "~") {
							home, _ := os.UserHomeDir()
							if strings.HasPrefix(match, home) {
								displayName = strings.Replace(match, home, "~", 1)
							}
						}

						info, err := os.Stat(match)
						if err == nil {
							desc := "File"
							if info.IsDir() {
								desc = "Directory"
								displayName += string(os.PathSeparator)
							}
							m.Suggestions = append(m.Suggestions, CommandDef{
								Name:        "wordlist " + displayName,
								Description: desc,
								Usage:       ":wordlist " + displayName,
							})
						}
					}
					// Sort dirs first
					sort.Slice(m.Suggestions, func(i, j int) bool {
						iDir := m.Suggestions[i].Description == "Directory"
						jDir := m.Suggestions[j].Description == "Directory"
						if iDir && !jDir {
							return true
						}
						return m.Suggestions[i].Name < m.Suggestions[j].Name
					})
				}
				if len(m.Suggestions) > 10 {
					m.Suggestions = m.Suggestions[:10]
				}

			} else if inputVal != "" {
				for _, cmdDef := range AvailableCommands {
					if strings.HasPrefix(cmdDef.Name, inputVal) {
						m.Suggestions = append(m.Suggestions, cmdDef)
					}
				}
			} else {
				for _, cmdDef := range AvailableCommands {
					m.Suggestions = append(m.Suggestions, cmdDef)
				}
			}

			// Reset index
			if m.SuggestionIndex >= len(m.Suggestions) {
				m.SuggestionIndex = 0
			}

			return m, inputCmd
		} else {
			// Normal Mode Logic
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case ":":
				m.PrePaused = m.Paused // Save user's pause state
				m.CommandMode = true

				// Resize Viewports for side-by-side view
				if m.Width > 0 {
					telemetryWidth := int(float64(m.Width-4) * 0.6)
					helpWidth := (m.Width - 4) - telemetryWidth - 3

					m.Viewport.Width = telemetryWidth
					m.updateTelemetry()

					m.HelpViewport.Width = helpWidth
					// Re-set help content to ensure proper wrapping if needed
					helpText := lipgloss.NewStyle().Foreground(draculaPink).Render("AVAILABLE COMMANDS:") + "\n" +
						":run                  - Restart scan with current configs\n" +
						":set-url [URL]        - Set Target URL\n" +
						":set-ua [Agent]       - Set User-Agent\n" +
						":add-header [K]: [V]  - Set Header\n" +
						":rm-header [K]        - Remove Header\n" +
						":set-delay [dur]      - Set Delay (e.g., 50ms)\n" +
						":worker [int]         - Set Worker threads\n" +
						":filter-size [bytes]  - Filter by Size\n" +
						":rm-filter-size [s]   - Remove Size Filter\n" +
						":filter-code [code]   - Add Status Match\n" +
						":rm-filter-code [c]   - Remove Status Match\n" +
						":add-ext [ext]        - Add Extension\n" +
						":rm-ext [ext]         - Remove Extension\n" +
						":set-mutate [on|off]  - Toggle Mutation\n" +
						":wordlist [path]      - Hot-swap Wordlist\n" +
						":run                  - Resume Scanning"
					m.HelpViewport.SetContent(helpText)
				}

				m.TextInput.Focus()
				m.Engine.SetPaused(true)
				m.Paused = true
				m.Suggestions = []CommandDef{}
				for _, cmdDef := range AvailableCommands {
					m.Suggestions = append(m.Suggestions, cmdDef)
				}
				return m, nil
			case "p":
				m.Paused = !m.Paused
				m.Engine.SetPaused(m.Paused)
				m.updateTelemetry()
			case "tab":
				m.TopFocused = !m.TopFocused
				return m, nil
			}

			if m.TopFocused {
				// Handle Scroll Keys for Viewport
				var vpCmd tea.Cmd
				m.Viewport, vpCmd = m.Viewport.Update(msg)
				return m, vpCmd
			} else {
				// Handle Scroll Keys for Logs (Legacy)
				switch msg.String() {
				// Worker Control
				case "Right", "l":
					m.Workers++
					m.Engine.SetWorkerCount(m.Workers)
				case "Left", "h":
					if m.Workers > 1 {
						m.Workers--
						m.Engine.SetWorkerCount(m.Workers)
					}
				// Scrolling
				case "pgup": // Page Up
					m.ScrollOffset += 10
					if m.ScrollOffset > len(m.Logs) {
						m.ScrollOffset = len(m.Logs)
					}
				case "pgdown": // Page Down
					m.ScrollOffset -= 10
					if m.ScrollOffset < 0 {
						m.ScrollOffset = 0
					}
				case "up", "k": // Scroll Up
					m.ScrollOffset++
					if m.ScrollOffset > len(m.Logs) {
						m.ScrollOffset = len(m.Logs)
					}
				case "down", "j": // Scroll Down
					m.ScrollOffset--
					if m.ScrollOffset < 0 {
						m.ScrollOffset = 0
					}
				}
			}
		}

		// Handle Mouse scrolling
	case tea.MouseMsg:
		var cmd tea.Cmd
		if msg.Type == tea.MouseWheelUp || msg.Type == tea.MouseWheelDown {
			if m.TopFocused {
				m.Viewport, cmd = m.Viewport.Update(msg)
			} else if m.CommandMode {
				m.HelpViewport, cmd = m.HelpViewport.Update(msg)
			}
			return m, cmd
		}

	// Handle window resizing
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

		// Initialize Viewport if needed
		headerHeight := lipgloss.Height(m.renderTelemetryContent())
		// Actually, we want a fixed or percentage size for top view?
		// The original logic was dynamic size based on content.
		// If content is huge, we should limit it.
		// Let's say top view is Max 50% of screen height, otherwise scrollable.
		// Wait, headerHeight is the *full* content height.

		maxTopHeight := msg.Height / 2
		if headerHeight > maxTopHeight {
			headerHeight = maxTopHeight
		}
		// Or maybe a minimum height?
		if headerHeight < 10 {
			headerHeight = 10
		}

		telemetryWidth := msg.Width - 4
		helpWidth := 0

		if m.CommandMode {
			// Split view: 60% / 40%
			telemetryWidth = int(float64(msg.Width-4) * 0.6)
			helpWidth = (msg.Width - 4) - telemetryWidth - 3 // -3 for gap
		}

		m.Viewport = viewport.New(telemetryWidth, headerHeight)
		m.Viewport.YPosition = 0
		m.Viewport.HighPerformanceRendering = false
		m.updateTelemetry()

		m.HelpViewport = viewport.New(helpWidth, headerHeight)
		m.HelpViewport.SetContent(m.HelpViewport.View()) // Keeps content, update size
		// Re-set help content to be safe
		helpText := lipgloss.NewStyle().Foreground(draculaPink).Render("AVAILABLE COMMANDS:") + "\n" +
			":run                  - Restart scan with current configs\n" +
			":set-ua [Agent]       - Set User-Agent\n" +
			":add-header [K]: [V]  - Set Header\n" +
			":rm-header [K]        - Remove Header\n" +
			":set-delay [dur]      - Set Delay (e.g., 50ms)\n" +
			":worker [int]         - Set Worker threads\n" +
			":filter-size [bytes]  - Filter by Size\n" +
			":rm-filter-size [s]   - Remove Size Filter\n" +
			":filter-code [code]   - Add Status Match\n" +
			":rm-filter-code [c]   - Remove Status Match\n" +
			":add-ext [ext]        - Add Extension\n" +
			":rm-ext [ext]         - Remove Extension\n" +
			":set-mutate [on|off]  - Toggle Mutation\n" +
			":wordlist [path]      - Hot-swap Wordlist\n" +
			":run                  - Resume Scanning"
		m.HelpViewport.SetContent(helpText)

	// Handle incoming telemetry stats
	case StatsMsg:
		m.RPS = msg.RPS
		m.QueueSize = msg.QueueSize
		m.Err403 = msg.Err403
		m.Err429 = msg.Err429
		m.Err500 = msg.Err500
		m.updateTelemetry()

	// Handle incoming successful logs
	case LogMsg:
		// Append new log
		m.Logs = append(m.Logs, engine.Result(msg))
		if len(m.Logs) > m.MaxLogs {
			m.Logs = m.Logs[1:] // Remove oldest log
		}
		// Continue waiting for more logs
		return m, nil

	// Handle periodic ticks
	case TickMsg:
		// Update stats from Engine on every tick
		// Access atomic variables directly from engine
		m.ProgressTotal = atomic.LoadInt64(&m.Engine.TotalLines)
		m.ProgressCurrent = atomic.LoadInt64(&m.Engine.ProcessedLines)

		// Update Telemetry
		m.QueueSize = m.Engine.QueueSize()
		m.Err403 = int(atomic.LoadInt64(&m.Engine.Count403))
		m.Err429 = int(atomic.LoadInt64(&m.Engine.Count429))
		m.Err500 = int(atomic.LoadInt64(&m.Engine.Count500))
		m.ErrConn = int(atomic.LoadInt64(&m.Engine.CountConnErr))

		m.updateTelemetry() // Should force viewport update
		return m, tickCmd()
	}

	return m, nil
}

func (m *Model) ExecuteCommand(raw string) error {
	raw = strings.TrimPrefix(raw, ":")
	parts := strings.SplitN(raw, " ", 2)
	command := parts[0]
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	switch command {
	case "run":
		err := m.Engine.Restart()
		if err != nil {
			return fmt.Errorf("failed to restart: %v", err)
		}
		// Clear viewport results from previous run
		m.Logs = []engine.Result{}
		m.ScrollOffset = 0
		m.StatusStr = "Scan restarted with updated configuration!"
	case "set-url":
		if args == "" {
			return fmt.Errorf("usage: :set-url [URL]")
		}
		if err := m.Engine.SetTarget(args); err != nil {
			return fmt.Errorf("invalid URL: %v", err)
		}
		m.StatusStr = fmt.Sprintf("URL updated to %s", args)
	case "set-ua":
		if args == "" {
			return fmt.Errorf("usage: :set-ua [value]")
		}
		m.Engine.UpdateUserAgent(args)
	case "add-header":
		// Expect Key: Value
		if !strings.Contains(args, ":") {
			return fmt.Errorf("usage: :add-header Key: Value")
		}
		headerParts := strings.SplitN(args, ":", 2)
		key := strings.TrimSpace(headerParts[0])
		val := strings.TrimSpace(headerParts[1])

		// Check for duplicate header
		if _, exists := m.Engine.Config.Headers[key]; exists {
			return fmt.Errorf("header %s already exists", key)
		}
		m.Engine.AddHeader(key, val)
	case "set-delay":
		d, err := time.ParseDuration(strings.TrimSpace(args))
		if err != nil {
			return fmt.Errorf("invalid duration format (e.g. 100ms, 1s)")
		}
		m.Engine.SetDelay(d)
	case "worker":
		n, err := strconv.Atoi(strings.TrimSpace(args))
		if err != nil || n < 1 {
			return fmt.Errorf("invalid worker count")
		}
		m.Workers = n // Update TUI view immediately
		m.Engine.SetWorkerCount(n)
	case "filter-size":
		size, err := strconv.Atoi(strings.TrimSpace(args))
		if err != nil {
			return fmt.Errorf("invalid size")
		}
		m.Engine.AddFilterSize(size)
	case "rm-filter-size":
		size, err := strconv.Atoi(strings.TrimSpace(args))
		if err != nil {
			return fmt.Errorf("invalid size")
		}
		m.Engine.RemoveFilterSize(size)
	case "rm-header":
		if args == "" {
			return fmt.Errorf("usage: :rm-header [Key]")
		}
		m.Engine.RemoveHeader(strings.TrimSpace(args))
	case "wordlist":
		if args == "" {
			return fmt.Errorf("usage: :wordlist path/to/file")
		}
		if err := m.Engine.ChangeWordlist(args); err != nil {
			return err
		}
	case "filter-code":
		code, err := strconv.Atoi(strings.TrimSpace(args))
		if err != nil {
			return fmt.Errorf("invalid status code")
		}
		m.Engine.AddMatchCode(code)
	case "rm-filter-code":
		code, err := strconv.Atoi(strings.TrimSpace(args))
		if err != nil {
			return fmt.Errorf("invalid status code")
		}
		m.Engine.RemoveMatchCode(code)
	case "add-ext":
		if args == "" {
			return fmt.Errorf("usage: :add-ext [ext]")
		}
		// Extensions usually start with .
		ext := strings.TrimSpace(args)
		m.Engine.AddExtension(ext)
	case "rm-ext":
		if args == "" {
			return fmt.Errorf("usage: :rm-ext [ext]")
		}
		ext := strings.TrimSpace(args)
		m.Engine.RemoveExtension(ext)
	case "set-mutate":
		val := strings.ToLower(strings.TrimSpace(args))
		if val == "on" || val == "true" || val == "1" {
			m.Engine.SetMutation(true)
		} else if val == "off" || val == "false" || val == "0" {
			m.Engine.SetMutation(false)
		} else {
			return fmt.Errorf("usage: :set-mutate [on|off]")
		}

	case "help":
		// Detailed help message
		m.StatusStr = "COMMAND LIST:\n" +
			":set-ua [Agent]       - Set User-Agent\n" +
			":add-header [K]: [V]  - Set Header\n" +
			":rm-header [K]        - Remove Header\n" +
			":set-delay [dur]      - Set Delay (e.g., 50ms)\n" +
			":worker [int]         - Set Worker threads\n" +
			":filter-size [bytes]  - Filter by Size\n" +
			":rm-filter-size [s]   - Remove Size Filter\n" +
			":filter-code [code]   - Add Status Match\n" +
			":rm-filter-code [c]   - Remove Status Match\n" +
			":add-ext [ext]        - Add Extension\n" +
			":rm-ext [ext]         - Remove Extension\n" +
			":set-mutate [on|off]  - Toggle Mutation\n" +
			":wordlist [path]      - Hot-swap Wordlist\n" +
			":run                  - Resume Scanning\n" +
			":help                 - Show this menu"
	default:
		return fmt.Errorf("unknown command")
	}
	return nil
}

func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "Initializing..."
	}

	// --- Top Half: Telemetry (Viewport) ---
	var topContent string
	if m.CommandMode {
		// Side-by-side view with separator
		left := m.Viewport.View()
		// Ensure separator style matches theme
		sep := lipgloss.NewStyle().Foreground(draculaComment).Render(" │ ")
		right := m.HelpViewport.View()
		topContent = lipgloss.JoinHorizontal(lipgloss.Top, left, sep, right)
	} else {
		topContent = m.Viewport.View()
	}

	var topBox string
	if m.TopFocused {
		topBox = activeBoxStyle.Width(m.Width - 2).Render(topContent) // Highlight focus
	} else {
		topBox = boxStyle.Width(m.Width - 2).Render(topContent)
	}

	// Measure the top box height immediately to calculate remaining space
	topHeight := lipgloss.Height(topBox)
	bottomHeight := m.Height - topHeight

	// --- Bottom Half: Logs or Command Input ---
	var bottomContent string
	var bottomBox string

	if m.CommandMode {
		// Render Suggestions
		var suggestionsView string
		if len(m.Suggestions) > 0 {
			var lines []string
			for i, s := range m.Suggestions {
				prefix := "  "
				lineStyle := lipgloss.NewStyle().Foreground(draculaComment)

				if i == m.SuggestionIndex {
					prefix = "> "
					lineStyle = lipgloss.NewStyle().Foreground(draculaPurple).Bold(true)
				}

				// Actually using simple string manipulation for layout
				left := fmt.Sprintf("%-20s", s.Name)
				right := s.Description

				renderedContent := fmt.Sprintf("%s%s %s", prefix, lineStyle.Render(left), lipgloss.NewStyle().Foreground(draculaComment).Italic(true).Render(right))
				lines = append(lines, renderedContent)
			}
			// Limit suggestions height
			if len(lines) > 10 {
				lines = lines[:10]
			}
			suggestionsView = strings.Join(lines, "\n") + "\n\n"
		}

		bottomContent = fmt.Sprintf(
			"COMMAND MODE (TAB to autocomplete)\n\n%s%s",
			suggestionsView,
			m.TextInput.View(),
		)
		// Active box for command mode? Or distinct style
		bottomBox = activeBoxStyle.
			Width(m.Width - 2).
			Height(bottomHeight - 2).
			Render(bottomContent)

	} else {
		// Render Logs
		// Calculate available lines for logs inside the bottom box
		// The bottom box has a border, so we subtract 2 from the height.
		logLinesAvailable := bottomHeight - 2
		if logLinesAvailable < 1 {
			logLinesAvailable = 1
		}

		// Total logs available
		totalLogs := len(m.Logs)

		// The index of the last log to show
		endIndex := totalLogs - m.ScrollOffset
		if endIndex > totalLogs {
			endIndex = totalLogs
		}

		// The index of the first log to show
		startIndex := endIndex - logLinesAvailable
		if startIndex < 0 {
			startIndex = 0
		}

		var viewLogs []string
		for i := startIndex; i < endIndex; i++ {
			if i >= len(m.Logs) {
				break
			}
			res := m.Logs[i]

			// Eagle Alert Handling
			prefix := lipgloss.NewStyle().Foreground(draculaPink).Render("[+]")
			changeInfo := ""

			if res.IsEagleAlert {
				prefix = lipgloss.NewStyle().Foreground(draculaRed).Bold(true).Blink(true).Render("[EAGLE]")
				changeInfo = lipgloss.NewStyle().Foreground(draculaRed).Bold(true).Render(fmt.Sprintf(" (CHANGE: %d -> %d)", res.OldStatusCode, res.StatusCode))
			} else if res.IsAutoFilter {
				prefix = lipgloss.NewStyle().Foreground(draculaOrange).Bold(true).Render("[AUTO-FILTER]")
				if val, ok := res.Headers["Msg"]; ok {
					changeInfo = lipgloss.NewStyle().Foreground(draculaOrange).Render(" " + val)
				}
			}

			// Format Status Code
			var statusStr string
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				statusStr = status200.Render(fmt.Sprintf("%d", res.StatusCode))
			} else if res.StatusCode >= 300 && res.StatusCode < 400 {
				statusStr = status300.Render(fmt.Sprintf("%d", res.StatusCode))
			} else if res.StatusCode >= 400 && res.StatusCode < 500 {
				statusStr = status400.Render(fmt.Sprintf("%d", res.StatusCode))
			} else {
				statusStr = status500.Render(fmt.Sprintf("%d", res.StatusCode))
			}

			// Format Line
			extras := ""
			if val, ok := res.Headers["Server"]; ok {
				extras += lipgloss.NewStyle().Foreground(draculaCyan).Render(fmt.Sprintf(" [Srv:%s]", val))
			}
			if val, ok := res.Headers["X-Powered-By"]; ok {
				extras += lipgloss.NewStyle().Foreground(draculaCyan).Render(fmt.Sprintf(" [XPB:%s]", val))
			}

			methodStr := res.Method
			if methodStr == "" {
				methodStr = "HEAD"
			}
			methodFmt := lipgloss.NewStyle().Foreground(draculaPurple).Render(fmt.Sprintf("[%s]", methodStr))

			redirectFmt := ""
			if res.Redirect != "" {
				redirectFmt = lipgloss.NewStyle().Foreground(draculaYellow).Render(fmt.Sprintf(" -> %s", res.Redirect))
			}

			line := fmt.Sprintf("%s %s %s%s %s %s%s %s%s",
				prefix,
				methodFmt,
				pathStyle.Render(res.Path),
				redirectFmt,
				lipgloss.NewStyle().Foreground(draculaComment).Render("(Status:"),
				statusStr,
				changeInfo,
				lipgloss.NewStyle().Foreground(draculaComment).Render(fmt.Sprintf(", Size: %s)", sizeStyle.Render(fmt.Sprintf("%d", res.Size)))),
				extras,
			)
			viewLogs = append(viewLogs, line)
		}

		// Fill empty space if not enough logs
		for len(viewLogs) < logLinesAvailable {
			viewLogs = append(viewLogs, "") // or blank lines
		}

		logView := strings.Join(viewLogs, "\n")

		scrollMsg := ""
		if m.ScrollOffset > 0 {
			scrollMsg = lipgloss.NewStyle().Background(draculaRed).Bold(true).Render(fmt.Sprintf(" SCROLLED UP %d ", m.ScrollOffset))
		}
		bottomContent = fmt.Sprintf("LOGS: %s\n%s", scrollMsg, logView)

		// Render Bottom Box
		if !m.TopFocused && !m.CommandMode {
			bottomBox = activeBoxStyle.Width(m.Width - 2).Height(bottomHeight - 2).Render(bottomContent)
		} else {
			bottomBox = boxStyle.Width(m.Width - 2).Height(bottomHeight - 2).Render(bottomContent)
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, topBox, bottomBox)
}

func (m *Model) updateTelemetry() {
	if m.Width == 0 || m.Height == 0 {
		return
	}
	content := m.renderTelemetryContent()

	newHeight := lipgloss.Height(content)
	maxTopHeight := int(float64(m.Height) * 0.75)
	if newHeight > maxTopHeight {
		newHeight = maxTopHeight
	}
	if newHeight < 10 {
		newHeight = 10
	}

	m.Viewport.Height = newHeight
	y := m.Viewport.YOffset
	m.Viewport.SetContent(content)
	m.Viewport.YOffset = y
}
