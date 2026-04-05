package tui

import (
	"dirfuzz/pkg/engine"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TUI Colors (Dracula Theme)
var (
	DraculaBg      = lipgloss.Color("#282a36")
	DraculaFg      = lipgloss.Color("#f8f8f2")
	DraculaPurple  = lipgloss.Color("#bd93f9")
	DraculaGreen   = lipgloss.Color("#50fa7b")
	DraculaCyan    = lipgloss.Color("#8be9fd")
	DraculaOrange  = lipgloss.Color("#ffb86c")
	DraculaRed     = lipgloss.Color("#ff5555")
	DraculaPink    = lipgloss.Color("#ff79c6")
	DraculaYellow  = lipgloss.Color("#f1fa8c")
	DraculaComment = lipgloss.Color("#6272a4")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(DraculaPurple).
			Background(DraculaBg).
			PaddingLeft(1).
			PaddingRight(1)

	statusStyle = lipgloss.NewStyle().
			Foreground(DraculaGreen)

	errorStyle = lipgloss.NewStyle().
			Foreground(DraculaRed)

	mutedStyle = lipgloss.NewStyle().
			Foreground(DraculaComment)

	highlightStyle = lipgloss.NewStyle().
			Foreground(DraculaCyan)

	orangeStyle = lipgloss.NewStyle().
			Foreground(DraculaOrange)

	pinkStyle = lipgloss.NewStyle().
			Foreground(DraculaPink)

	yellowStyle = lipgloss.NewStyle().
			Foreground(DraculaYellow)

	logStyle = lipgloss.NewStyle().
			Foreground(DraculaFg)

	cmdPromptStyle = lipgloss.NewStyle().
			Foreground(DraculaPurple).
			Bold(true)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(DraculaPurple).
			Padding(0, 1)
)

// CommandDef defines a TUI command.
type CommandDef struct {
	Name        string
	Description string
	Args        string
	Handler     func(m *Model, args string) string
}

// TickMsg is sent on each tick.
type TickMsg time.Time

// ViewState defines which screen the user is looking at
type ViewState int

const (
	StateList ViewState = iota
	StateDetail
)

// Model is the BubbleTea model for the TUI.
type Model struct {
	Engine        *engine.Engine
	resultsCh     <-chan engine.Result
	viewport      viewport.Model
	textInput     textinput.Model
	logs          []string
	hits          []engine.Result // Keep track of hits to view them later
	commandMode   bool
	width, height int
	ready         bool

	// View State
	state ViewState

	// List View Selection
	selectedIndex int
	listScrollIdx int // How far down the list we have scrolled

	// Detail Viewports
	reqViewport viewport.Model
	resViewport viewport.Model

	// Telemetry display
	startTime time.Time

	// Command history
	cmdHistory    []string
	cmdHistoryIdx int

	// Available commands
	commands []CommandDef

	// Autocomplete state
	suggestions    []string
	selectedSugIdx int

	// State
	quitting bool
}

// NewModel initializes the TUI model.
func NewModel(eng *engine.Engine, resultsCh <-chan engine.Result) Model {
	ti := textinput.New()
	ti.Placeholder = "Type ':' to enter command mode, 'q' to quit, 'Enter' on a hit to view details"
	ti.CharLimit = 256
	ti.Width = 80

	vp := viewport.New(80, 20)
	vp.SetContent("")

	reqVp := viewport.New(40, 20)
	resVp := viewport.New(40, 20)

	m := Model{
		Engine:      eng,
		resultsCh:   resultsCh,
		viewport:    vp,
		reqViewport: reqVp,
		resViewport: resVp,
		textInput:   ti,
		logs:        []string{},
		hits:        []engine.Result{},
		startTime:   time.Now(),
		state:       StateList,
	}
	m.initCommands()
	return m
}

// initCommands registers all available TUI commands.
func (m *Model) initCommands() {
	m.commands = []CommandDef{
		{Name: "help", Description: "Show all commands", Args: "", Handler: func(m *Model, args string) string {
			var sb strings.Builder
			sb.WriteString(pinkStyle.Render("=== DirFuzz Commands ===") + "\n")
			for _, cmd := range m.commands {
				line := fmt.Sprintf("  :%s", cmd.Name)
				if cmd.Args != "" {
					line += " " + cmd.Args
				}
				sb.WriteString(highlightStyle.Render(line) + " - " + mutedStyle.Render(cmd.Description) + "\n")
			}
			return sb.String()
		}},
		{Name: "pause", Description: "Pause/resume scanning", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				return statusStyle.Render("[*] Scan resumed")
			}
			return orangeStyle.Render("[*] Scan paused")
		}},
		{Name: "threads", Description: "Set worker count", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 1 {
				return errorStyle.Render("Usage: :threads <number>")
			}
			m.Engine.SetWorkerCount(n)
			return statusStyle.Render(fmt.Sprintf("[*] Workers set to %d", n))
		}},
		{Name: "delay", Description: "Set delay (ms)", Args: "<ms>", Handler: func(m *Model, args string) string {
			ms, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || ms < 0 {
				return errorStyle.Render("Usage: :delay <milliseconds>")
			}
			m.Engine.SetDelay(time.Duration(ms) * time.Millisecond)
			return statusStyle.Render(fmt.Sprintf("[*] Delay set to %dms", ms))
		}},
		{Name: "rps", Description: "Set requests per second (0=unlimited)", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 0 {
				return errorStyle.Render("Usage: :rps <number>")
			}
			m.Engine.SetRPS(n)
			if n == 0 {
				return statusStyle.Render("[*] RPS: unlimited")
			}
			return statusStyle.Render(fmt.Sprintf("[*] RPS limit set to %d", n))
		}},
		{Name: "ua", Description: "Change User-Agent", Args: "<string>", Handler: func(m *Model, args string) string {
			if strings.TrimSpace(args) == "" {
				return errorStyle.Render("Usage: :ua <user-agent>")
			}
			m.Engine.UpdateUserAgent(strings.TrimSpace(args))
			return statusStyle.Render("[*] User-Agent updated")
		}},
		{Name: "header", Description: "Add header (key:value)", Args: "<key:value>", Handler: func(m *Model, args string) string {
			parts := strings.SplitN(strings.TrimSpace(args), ":", 2)
			if len(parts) != 2 {
				return errorStyle.Render("Usage: :header Key:Value")
			}
			m.Engine.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			return statusStyle.Render(fmt.Sprintf("[*] Header set: %s: %s", parts[0], parts[1]))
		}},
		{Name: "rmheader", Description: "Remove header", Args: "<key>", Handler: func(m *Model, args string) string {
			if args == "" {
				return errorStyle.Render("Usage: :rmheader <key>")
			}
			m.Engine.RemoveHeader(strings.TrimSpace(args))
			return statusStyle.Render(fmt.Sprintf("[*] Header removed: %s", args))
		}},
		{Name: "addcode", Description: "Add match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :addcode <code>")
			}
			m.Engine.AddMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Added match code: %d", code))
		}},
		{Name: "rmcode", Description: "Remove match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmcode <code>")
			}
			m.Engine.RemoveMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Removed match code: %d", code))
		}},
		{Name: "filter", Description: "Add filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :filter <size>")
			}
			m.Engine.AddFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Filtering size: %d", size))
		}},
		{Name: "rmfilter", Description: "Remove filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmfilter <size>")
			}
			m.Engine.RemoveFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Removed filter size: %d", size))
		}},
		{Name: "addext", Description: "Add extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :addext <extension>")
			}
			m.Engine.AddExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Added extension: %s", ext))
		}},
		{Name: "rmext", Description: "Remove extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :rmext <extension>")
			}
			m.Engine.RemoveExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Removed extension: %s", ext))
		}},
		{Name: "mutate", Description: "Toggle mutation", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.Mutate
			m.Engine.Config.RUnlock()
			m.Engine.SetMutation(!current)
			if !current {
				return statusStyle.Render("[*] Mutation enabled")
			}
			return orangeStyle.Render("[*] Mutation disabled")
		}},
		{Name: "wordlist", Description: "Change wordlist", Args: "<path>", Handler: func(m *Model, args string) string {
			path := strings.TrimSpace(args)
			if path == "" {
				return errorStyle.Render("Usage: :wordlist <path>")
			}
			if err := m.Engine.ChangeWordlist(path); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			return statusStyle.Render(fmt.Sprintf("[*] Wordlist changed to: %s", path))
		}},
		{Name: "changeurl", Description: "Change target URL", Args: "<url>", Handler: func(m *Model, args string) string {
			url := strings.TrimSpace(args)
			if url == "" {
				return errorStyle.Render("Usage: :changeurl <url>")
			}
			if err := m.Engine.SetTarget(url); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: invalid target URL: %v", err))
			}
			// Restart is needed to apply the new URL to scanning jobs
			if err := m.Engine.Restart(); err != nil {
				return errorStyle.Render(fmt.Sprintf("URL updated, but restart failed: %v", err))
			}
			return statusStyle.Render(fmt.Sprintf("[*] Target URL changed to: %s and scan restarted", url))
		}},
		{Name: "restart", Description: "Restart scan", Args: "", Handler: func(m *Model, args string) string {
			if err := m.Engine.Restart(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			return statusStyle.Render("[*] Scan restarted")
		}},
		{Name: "config", Description: "Show current config", Args: "", Handler: func(m *Model, args string) string {
			ua, filters, headers, delay, exts, followRedir := m.Engine.ConfigSnapshot()
			m.Engine.Config.RLock()
			recursive := m.Engine.Config.Recursive
			maxDepth := m.Engine.Config.MaxDepth
			mutate := m.Engine.Config.Mutate
			matchRegex := m.Engine.Config.MatchRegex
			filterRegex := m.Engine.Config.FilterRegex
			filterWords := m.Engine.Config.FilterWords
			filterLines := m.Engine.Config.FilterLines
			body := m.Engine.Config.RequestBody
			outputFmt := m.Engine.Config.OutputFormat
			filterDurMin := m.Engine.Config.FilterRTMin
			filterDurMax := m.Engine.Config.FilterRTMax
			proxyOut := m.Engine.Config.ProxyOut
			m.Engine.Config.RUnlock()

			var sb strings.Builder

			sb.WriteString(pinkStyle.Render("=== Current Config ===") + "\n")
			sb.WriteString(fmt.Sprintf("  Target:     %s\n", highlightStyle.Render(m.Engine.BaseURL())))
			sb.WriteString(fmt.Sprintf("  UA:         %s\n", ua))
			sb.WriteString(fmt.Sprintf("  Delay:      %s\n", delay))
			sb.WriteString(fmt.Sprintf("  Extensions: %v\n", exts))
			sb.WriteString(fmt.Sprintf("  Filters:    %v\n", filters))
			sb.WriteString(fmt.Sprintf("  Headers:    %v\n", headers))
			sb.WriteString(fmt.Sprintf("  Recursive:  %v (depth: %d)\n", recursive, maxDepth))
			sb.WriteString(fmt.Sprintf("  Mutate:     %v\n", mutate))
			sb.WriteString(fmt.Sprintf("  Follow:     %v\n", followRedir))
			sb.WriteString(fmt.Sprintf("  OutputFmt:  %s\n", outputFmt))
			if matchRegex != "" {
				sb.WriteString(fmt.Sprintf("  MatchRegex: %s\n", matchRegex))
			}
			if filterRegex != "" {
				sb.WriteString(fmt.Sprintf("  FilterRegex: %s\n", filterRegex))
			}
			if filterWords >= 0 {
				sb.WriteString(fmt.Sprintf("  FilterWords: %d\n", filterWords))
			}
			if filterLines >= 0 {
				sb.WriteString(fmt.Sprintf("  FilterLines: %d\n", filterLines))
			}
			if filterDurMin > 0 {
				sb.WriteString(fmt.Sprintf("  RTmin:      %s\n", filterDurMin))
			}
			if filterDurMax > 0 {
				sb.WriteString(fmt.Sprintf("  RTmax:      %s\n", filterDurMax))
			}
			if proxyOut != "" {
				sb.WriteString(fmt.Sprintf("  ProxyOut:   %s\n", proxyOut))
			}
			if body != "" {
				sb.WriteString(fmt.Sprintf("  Body:       %s\n", body))
			}
			return sb.String()
		}},
		{Name: "mr", Description: "Set match regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetMatchRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Match regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Match regex set: %s", pattern))
		}},
		{Name: "fr", Description: "Set filter regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetFilterRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Filter regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter regex set: %s", pattern))
		}},
		{Name: "fw", Description: "Filter by word count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fw <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterWords = n
			m.Engine.Config.Unlock()
			if n < 0 {
				return statusStyle.Render("[*] Word filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter words: %d", n))
		}},
		{Name: "fl", Description: "Filter by line count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fl <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterLines = n
			m.Engine.Config.Unlock()
			if n < 0 {
				return statusStyle.Render("[*] Line filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter lines: %d", n))
		}},
		{Name: "follow", Description: "Toggle redirect following", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.FollowRedirects
			m.Engine.Config.RUnlock()
			m.Engine.SetFollowRedirects(!current)
			if !current {
				return statusStyle.Render("[*] Follow redirects enabled")
			}
			return orangeStyle.Render("[*] Follow redirects disabled")
		}},
		{Name: "body", Description: "Set request body for POST/PUT", Args: "<body>", Handler: func(m *Model, args string) string {
			m.Engine.Config.Lock()
			m.Engine.Config.RequestBody = strings.TrimSpace(args)
			m.Engine.Config.Unlock()
			if args == "" {
				return statusStyle.Render("[*] Request body cleared")
			}
			return statusStyle.Render("[*] Request body set")
		}},
		{Name: "rtmin", Description: "Set min response time filter (e.g. 500ms, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMin = 0
				m.Engine.Config.Unlock()
				return statusStyle.Render("[*] Min response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmin <duration> (e.g. 500ms, 1s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMin = d
			m.Engine.Config.Unlock()
			return statusStyle.Render(fmt.Sprintf("[*] Min response time filter: %s", d))
		}},
		{Name: "rtmax", Description: "Set max response time filter (e.g. 5s, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMax = 0
				m.Engine.Config.Unlock()
				return statusStyle.Render("[*] Max response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmax <duration> (e.g. 5s, 10s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMax = d
			m.Engine.Config.Unlock()
			return statusStyle.Render(fmt.Sprintf("[*] Max response time filter: %s", d))
		}},
		{Name: "proxyout", Description: "Set proxy-out for Burp replay (empty = off)", Args: "<url>", Handler: func(m *Model, args string) string {
			addr := strings.TrimSpace(args)
			m.Engine.Config.Lock()
			m.Engine.Config.ProxyOut = addr
			if addr == "" || addr == "off" {
				m.Engine.Config.ProxyOut = ""
				m.Engine.Config.Unlock()
				return statusStyle.Render("[*] Proxy-out disabled")
			}
			m.Engine.Config.Unlock()
			return statusStyle.Render(fmt.Sprintf("[*] Proxy-out: %s", addr))
		}},
		{Name: "clear", Description: "Clear log output", Args: "", Handler: func(m *Model, args string) string {
			m.logs = []string{}
			m.hits = []engine.Result{}
			m.viewport.SetContent("")
			m.selectedIndex = 0
			m.listScrollIdx = 0
			return ""
		}},
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), m.listenForResults())
}

// ResultMsg wraps a result coming from the engine.
type ResultMsg engine.Result

// listenForResults returns a command that reads from the Results channel.
func (m Model) listenForResults() tea.Cmd {
	return func() tea.Msg {
		result, ok := <-m.resultsCh
		if !ok {
			return nil
		}
		return ResultMsg(result)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := 10
		footerHeight := 3
		vpHeight := m.height - headerHeight - footerHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		vpWidth := m.width - 2
		if vpWidth < 20 {
			vpWidth = 20
		}

		paneWidth := (vpWidth / 2) - 4

		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.viewport.SetContent(strings.Join(m.logs, "\n"))

			// Detail viewports
			m.reqViewport = viewport.New(paneWidth, vpHeight-2)
			m.resViewport = viewport.New(paneWidth, vpHeight-2)

			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight

			m.reqViewport.Width = paneWidth
			m.reqViewport.Height = vpHeight - 2
			m.resViewport.Width = paneWidth
			m.resViewport.Height = vpHeight - 2
		}
		m.textInput.Width = vpWidth - 4

	case TickMsg:
		m.Engine.UpdateRPS()
		cmds = append(cmds, tickCmd())

	case ResultMsg:
		result := engine.Result(msg)
		if result.IsAutoFilter {
			msgStr := ""
			if result.Headers != nil {
				msgStr = result.Headers["Msg"]
			}
			if msgStr != "" {
				m.appendLog(orangeStyle.Render(fmt.Sprintf("[!] %s: %s", result.Path, msgStr)), nil)
			}
		} else if result.IsEagleAlert {
			m.appendLog(yellowStyle.Render(fmt.Sprintf("[EAGLE] %s changed: %d -> %d", result.Path, result.OldStatusCode, result.StatusCode)), nil)
		} else {
			m.appendLog(formatResult(result), &result)
		}
		cmds = append(cmds, m.listenForResults())

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "q":
			if m.state == StateDetail {
				m.state = StateList
				return m, nil
			}
			if !m.commandMode {
				m.quitting = true
				return m, tea.Quit
			}

		case ":":
			if !m.commandMode && m.state == StateList {
				m.commandMode = true
				m.textInput.SetValue("")
				m.textInput.Focus()
				m.suggestions = nil
				m.selectedSugIdx = 0
				return m, nil
			}

		case "esc":
			if m.commandMode {
				m.commandMode = false
				m.textInput.Blur()
				m.suggestions = nil
				return m, nil
			}
			if m.state == StateDetail {
				m.state = StateList
				return m, nil
			}

		case "enter":
			if m.commandMode {
				val := strings.TrimSpace(m.textInput.Value())
				if val != "" {
					output := m.executeCommand(val)
					if output != "" {
						m.appendLog(output, nil)
					}
					m.cmdHistory = append(m.cmdHistory, val)
					m.cmdHistoryIdx = len(m.cmdHistory)
				}
				m.commandMode = false
				m.textInput.Blur()
				m.textInput.SetValue("")
				m.suggestions = nil
				return m, nil
			}

			if m.state == StateList && len(m.hits) > 0 {
				// We don't track selection across all logs, only hits, but we want to show the detail of the 'last' selected one.
				// However, if we implement true list selection, we would transition to state detail here
				// For now, if they press enter in list mode and have hits, let's just show the last one, or maybe we build a selection.
				if m.selectedIndex >= 0 && m.selectedIndex < len(m.logs) {
					// We need a way to map log lines back to results. Let's just enter detail mode for the last hit for simplicity if not selected properly,
					// or we implement a full selection mechanism.
					// We'll implement basic selection.
					if len(m.hits) > 0 {
						// Calculate which hit corresponds to the selected log line
						// This is tricky because logs contain non-hit messages.
						// Instead, let's make selection navigate through 'hits' directly, and just highlight the line in the text.
						m.state = StateDetail
						m.updateDetailView()
					}
				}
				return m, nil
			}

		case "up", "k":
			if m.commandMode && len(m.suggestions) > 0 {
				m.selectedSugIdx--
				if m.selectedSugIdx < 0 {
					m.selectedSugIdx = len(m.suggestions) - 1
				}
				return m, nil
			}
			if m.commandMode && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx > 0 {
					m.cmdHistoryIdx--
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
				}
				return m, nil
			}

			if m.state == StateList {
				if m.selectedIndex > 0 {
					m.selectedIndex--
					// Adjust scroll if necessary
					if m.selectedIndex < m.listScrollIdx {
						m.listScrollIdx = m.selectedIndex
					}
					m.renderListView()
				}
				return m, nil
			}
			if m.state == StateDetail {
				m.reqViewport.LineUp(1)
				m.resViewport.LineUp(1)
				return m, nil
			}

		case "down", "j":
			if m.commandMode && len(m.suggestions) > 0 {
				m.selectedSugIdx++
				if m.selectedSugIdx >= len(m.suggestions) {
					m.selectedSugIdx = 0
				}
				return m, nil
			}
			if m.commandMode && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx < len(m.cmdHistory)-1 {
					m.cmdHistoryIdx++
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
				}
				return m, nil
			}

			if m.state == StateList {
				if m.selectedIndex < len(m.logs)-1 {
					m.selectedIndex++
					// Adjust scroll
					if m.selectedIndex >= m.listScrollIdx+m.viewport.Height {
						m.listScrollIdx++
					}
					m.renderListView()
				}
				return m, nil
			}
			if m.state == StateDetail {
				m.reqViewport.LineDown(1)
				m.resViewport.LineDown(1)
				return m, nil
			}

		case "pagedown":
			if m.state == StateList {
				m.selectedIndex += m.viewport.Height
				if m.selectedIndex >= len(m.logs) {
					m.selectedIndex = len(m.logs) - 1
				}
				m.listScrollIdx += m.viewport.Height
				if m.listScrollIdx > len(m.logs)-m.viewport.Height {
					m.listScrollIdx = len(m.logs) - m.viewport.Height
					if m.listScrollIdx < 0 {
						m.listScrollIdx = 0
					}
				}
				m.renderListView()
			} else if m.state == StateDetail {
				m.reqViewport.ViewDown()
				m.resViewport.ViewDown()
			}
			return m, nil

		case "pageup":
			if m.state == StateList {
				m.selectedIndex -= m.viewport.Height
				if m.selectedIndex < 0 {
					m.selectedIndex = 0
				}
				m.listScrollIdx -= m.viewport.Height
				if m.listScrollIdx < 0 {
					m.listScrollIdx = 0
				}
				m.renderListView()
			} else if m.state == StateDetail {
				m.reqViewport.ViewUp()
				m.resViewport.ViewUp()
			}
			return m, nil

		case "tab":
			if m.commandMode && len(m.suggestions) > 0 {
				val := m.textInput.Value()
				if strings.HasPrefix(val, "wordlist ") {
					// Append the completion instead of replacing the whole string
					base := val
					lastSlash := strings.LastIndex(val, "/")
					if lastSlash != -1 {
						base = val[:lastSlash+1]
					} else {
						base = "wordlist "
					}

					suggestion := m.suggestions[m.selectedSugIdx]
					if strings.HasSuffix(suggestion, "/") {
						newVal := base + suggestion
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						// Trigger new completion
						m.updateSuggestions(newVal)
					} else {
						newVal := base + suggestion + " "
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						m.suggestions = nil
					}
				} else {
					newVal := m.suggestions[m.selectedSugIdx] + " "
					m.textInput.SetValue(newVal)
					m.textInput.SetCursor(len(newVal))
					m.suggestions = nil
				}
				return m, nil
			}
		}

		if m.commandMode {
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)

			// Autocomplete
			val := m.textInput.Value()
			m.updateSuggestions(val)

			return m, tea.Batch(cmds...)
		}

		// Non-command mode key shortcuts
		switch msg.String() {
		case "p":
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				m.appendLog(statusStyle.Render("[*] Scan resumed"), nil)
			} else {
				m.appendLog(orangeStyle.Render("[*] Scan paused"), nil)
			}
		case "?":
			output := m.commands[0].Handler(&m, "")
			m.appendLog(output, nil)
		}
	}

	return m, tea.Batch(cmds...)
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	var wrapped strings.Builder
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		// Handle carriage returns
		line = strings.ReplaceAll(line, "\r", "")
		for len(line) > width {
			wrapped.WriteString(line[:width] + "\n")
			line = line[width:]
		}
		wrapped.WriteString(line + "\n")
	}
	return strings.TrimSuffix(wrapped.String(), "\n")
}

func (m *Model) updateDetailView() {
	if len(m.hits) == 0 {
		return
	}

	// Figure out which hit corresponds to the selected log line.
	var selectedHit *engine.Result
	if m.selectedIndex >= 0 && m.selectedIndex < len(m.logs) {
		selectedText := m.logs[m.selectedIndex]
		for i := len(m.hits) - 1; i >= 0; i-- {
			// Basic heuristic: if the log line contains the path of the hit
			if strings.Contains(selectedText, m.hits[i].Path) {
				selectedHit = &m.hits[i]
				break
			}
		}
	}

	if selectedHit == nil {
		// Fallback to the last hit
		selectedHit = &m.hits[len(m.hits)-1]
	}

	reqContent := "No raw request available. Set follow redirects or disable body filters if using HEAD."
	if selectedHit.Request != "" {
		reqContent = selectedHit.Request
	}

	resContent := "No raw response available."
	if selectedHit.Response != "" {
		resContent = selectedHit.Response
	}

	// Wrap text to viewport width to prevent horizontal overflow
	m.reqViewport.SetContent(wrapText(reqContent, m.reqViewport.Width))
	m.resViewport.SetContent(wrapText(resContent, m.resViewport.Width))

	m.reqViewport.GotoTop()
	m.resViewport.GotoTop()
}

func (m *Model) renderListView() {
	if len(m.logs) == 0 {
		m.viewport.SetContent("")
		return
	}

	var visibleLines []string
	start := m.listScrollIdx
	end := start + m.viewport.Height
	if end > len(m.logs) {
		end = len(m.logs)
	}

	for i := start; i < end; i++ {
		line := m.logs[i]
		if i == m.selectedIndex {
			// Highlight the selected line
			line = lipgloss.NewStyle().Background(DraculaComment).Render(line)
		}
		visibleLines = append(visibleLines, line)
	}

	m.viewport.SetContent(strings.Join(visibleLines, "\n"))
}

func (m *Model) updateSuggestions(val string) {
	m.suggestions = nil
	if val == "" {
		return
	}

	if strings.HasPrefix(val, "wordlist ") {
		path := strings.TrimPrefix(val, "wordlist ")
		dir := "."
		base := path

		lastSlash := strings.LastIndex(path, "/")
		if lastSlash != -1 {
			dir = path[:lastSlash]
			base = path[lastSlash+1:]
			if dir == "" {
				dir = "/"
			}
		}

		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, base) {
					if entry.IsDir() {
						m.suggestions = append(m.suggestions, name+"/")
					} else {
						m.suggestions = append(m.suggestions, name)
					}
				}
			}
		}
		m.selectedSugIdx = 0
		return
	}

	for _, c := range m.commands {
		if strings.HasPrefix(c.Name, val) {
			m.suggestions = append(m.suggestions, c.Name)
		}
	}
	m.selectedSugIdx = 0
}

func (m *Model) appendLog(text string, hit *engine.Result) {
	if text == "" {
		return
	}
	m.logs = append(m.logs, text)
	if hit != nil {
		m.hits = append(m.hits, *hit)
	}

	// Auto-scroll to bottom if we are at the bottom
	if m.selectedIndex >= len(m.logs)-2 {
		m.selectedIndex = len(m.logs) - 1
		m.listScrollIdx = len(m.logs) - m.viewport.Height
		if m.listScrollIdx < 0 {
			m.listScrollIdx = 0
		}
	}

	m.renderListView()
}

// executeCommand parses and runs a TUI command.
func (m *Model) executeCommand(input string) string {
	parts := strings.SplitN(input, " ", 2)
	name := strings.ToLower(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	for _, cmd := range m.commands {
		if cmd.Name == name {
			return cmd.Handler(m, args)
		}
	}
	return errorStyle.Render(fmt.Sprintf("Unknown command: %s (type :help for list)", name))
}

// formatResult formats a result for display.
func formatResult(r engine.Result) string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}

	statusColor := statusStyle
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		statusColor = lipgloss.NewStyle().Foreground(DraculaGreen)
	case r.StatusCode >= 300 && r.StatusCode < 400:
		statusColor = lipgloss.NewStyle().Foreground(DraculaCyan)
	case r.StatusCode == 403:
		statusColor = lipgloss.NewStyle().Foreground(DraculaOrange)
	case r.StatusCode >= 400 && r.StatusCode < 500:
		statusColor = lipgloss.NewStyle().Foreground(DraculaYellow)
	case r.StatusCode >= 500:
		statusColor = lipgloss.NewStyle().Foreground(DraculaRed)
	}

	extras := ""
	if r.Redirect != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" -> %s", r.Redirect))
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [Server: %s]", val))
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [X-Powered-By: %s]", val))
	}
	if r.ContentType != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" [%s]", r.ContentType))
	}
	if r.Duration > 0 {
		extras += mutedStyle.Render(fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond)))
	}

	return fmt.Sprintf("%s %s %s %s %s %s%s",
		statusColor.Render(fmt.Sprintf("[%d]", r.StatusCode)),
		pinkStyle.Render(methodStr),
		highlightStyle.Render(r.Path),
		mutedStyle.Render(fmt.Sprintf("(Size:%d", r.Size)),
		mutedStyle.Render(fmt.Sprintf("W:%d L:%d)", r.Words, r.Lines)),
		extras,
		"",
	)
}

func (m Model) View() string {
	if m.quitting {
		return "\n  " + mutedStyle.Render("DirFuzz finished. Goodbye!") + "\n"
	}

	if !m.ready {
		return "Initializing..."
	}

	// Header
	elapsed := time.Since(m.startTime).Round(time.Second)
	total := atomic.LoadInt64(&m.Engine.TotalLines)
	processed := atomic.LoadInt64(&m.Engine.ProcessedLines)
	rps := atomic.LoadInt64(&m.Engine.CurrentRPS)
	queueSize := m.Engine.QueueSize()
	count200 := atomic.LoadInt64(&m.Engine.Count200)
	count403 := atomic.LoadInt64(&m.Engine.Count403)
	count404 := atomic.LoadInt64(&m.Engine.Count404)
	count429 := atomic.LoadInt64(&m.Engine.Count429)
	count500 := atomic.LoadInt64(&m.Engine.Count500)
	connErr := atomic.LoadInt64(&m.Engine.CountConnErr)

	m.Engine.Config.RLock()
	paused := m.Engine.Config.IsPaused
	workers := m.Engine.Config.MaxWorkers
	delay := m.Engine.Config.Delay
	m.Engine.Config.RUnlock()

	progressPct := float64(0)
	if total > 0 {
		progressPct = float64(processed) / float64(total) * 100
	}

	// Build progress bar
	barWidth := 30
	if m.width > 60 {
		barWidth = m.width / 4
	}
	filled := int(progressPct / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := statusStyle.Render(strings.Repeat("█", filled)) + mutedStyle.Render(strings.Repeat("░", barWidth-filled))

	pauseStr := ""
	if paused {
		pauseStr = errorStyle.Render(" [PAUSED]")
	}

	header := fmt.Sprintf(
		"%s %s%s\n"+
			"  %s %s  %s  %s  %s  %s\n"+
			"  Progress: %s %s  |  RPS: %s  |  Queue: %s\n"+
			"  Workers: %s  Delay: %s  Elapsed: %s\n"+
			"  %s\n",
		titleStyle.Render(" 🦇 DirFuzz "),
		highlightStyle.Render(m.Engine.BaseURL()),
		pauseStr,
		statusStyle.Render(fmt.Sprintf("2xx:%d", count200)),
		orangeStyle.Render(fmt.Sprintf("403:%d", count403)),
		mutedStyle.Render(fmt.Sprintf("404:%d", count404)),
		yellowStyle.Render(fmt.Sprintf("429:%d", count429)),
		errorStyle.Render(fmt.Sprintf("5xx:%d", count500)),
		errorStyle.Render(fmt.Sprintf("Err:%d", connErr)),
		bar,
		highlightStyle.Render(fmt.Sprintf("%.1f%%", progressPct)),
		pinkStyle.Render(fmt.Sprintf("%d", rps)),
		mutedStyle.Render(fmt.Sprintf("%d", queueSize)),
		highlightStyle.Render(fmt.Sprintf("%d", workers)),
		mutedStyle.Render(delay.String()),
		mutedStyle.Render(elapsed.String()),
		mutedStyle.Render(fmt.Sprintf("(%d/%d)", processed, total)),
	)

	var mainContent string

	if m.state == StateList {
		mainContent = m.viewport.View()
	} else if m.state == StateDetail {
		reqPane := paneStyle.Width(m.reqViewport.Width + 2).Height(m.reqViewport.Height + 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				statusStyle.Render(" Request "),
				m.reqViewport.View(),
			),
		)
		resPane := paneStyle.Width(m.resViewport.Width + 2).Height(m.resViewport.Height + 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				orangeStyle.Render(" Response "),
				m.resViewport.View(),
			),
		)
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, reqPane, resPane)
	}

	// Footer
	var footer string
	if m.commandMode {
		cmdLine := cmdPromptStyle.Render(":") + m.textInput.View()

		// Show suggestions
		if len(m.suggestions) > 0 {
			var sugLines []string
			for i, s := range m.suggestions {
				if i == m.selectedSugIdx {
					sugLines = append(sugLines, statusStyle.Render("> "+s))
				} else {
					sugLines = append(sugLines, mutedStyle.Render("  "+s))
				}
			}
			cmdLine += "\n" + strings.Join(sugLines, "\n")
		}

		footer = cmdLine
	} else {
		if m.state == StateDetail {
			footer = mutedStyle.Render("  Press 'Esc' or 'q' to return to list | Up/Down to scroll")
		} else {
			footer = mutedStyle.Render("  Press ':' for commands | 'p' to pause | '?' for help | 'q' to quit | 'Enter' on hit to view")
		}
	}

	// Compose
	return lipgloss.JoinVertical(lipgloss.Top, header, mainContent, footer)
}
