package main

import (
	"os/signal"
	"syscall"

	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/viper"
)

// headerFlags is a custom type to support multiple -h flags
type headerFlags map[string]string

func (h *headerFlags) String() string {
	var parts []string
	for k, v := range *h {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, ", ")
}

func (h *headerFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid header format: %q. Expected 'Header: Value'", value)
	}
	if *h == nil {
		*h = make(map[string]string)
	}
	(*h)[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	return nil
}

// parseStatusCodes parses status codes including ranges like 200-299,401-403
func parseStatusCodes(input string) ([]int, error) {
	var codes []int
	parts := strings.Split(input, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a range
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start in range: %s", part)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end in range: %s", part)
			}

			if start > end {
				return nil, fmt.Errorf("invalid range (start > end): %s", part)
			}

			for i := start; i <= end; i++ {
				codes = append(codes, i)
			}
		} else {
			// Single code
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid status code: %s", part)
			}
			codes = append(codes, code)
		}
	}

	return codes, nil
}

// isFlagSet checks if a flag was explicitly set on command line
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// ScanOptions holds all configuration for a scan run.
type ScanOptions struct {
	Target              string
	Wordlist            string
	Threads             int
	DelayMs             int
	UserAgent           string
	Headers             map[string]string
	MatchCodes          []int
	FilterSizes         []int
	Extensions          []string
	Methods             []string
	SmartAPI            bool
	RequestBody         string
	Mutate              bool
	Mutations           []string
	Recursive           bool
	MaxDepth            int
	ProxyFile           string
	EagleScan           string
	OutputFile          string
	OutputFormat        string
	NoTUI               bool
	AutoCalibrate       bool
	MatchRegex          string
	FilterRegex         string
	FilterWords         int
	FilterLines         int
	MatchWords          int
	MatchLines          int
	FollowRedirects     bool
	MaxRedirects        int
	ResumeFile          string
	RTMin               time.Duration
	RTMax               time.Duration
	ProxyOut            string
	Timeout             time.Duration
	ConnectTimeout      time.Duration
	ReadTimeout         time.Duration
	Insecure            bool
	Cookies             string
	UseHTTP2            bool
	PluginMatch         string
	PluginMutate        string
	AutoFilterThreshold int
	MaxRetries          int
}

func main() {
	// Version
	version := flag.Bool("v", false, "Print DirFuzz version")

	// Required
	target := flag.String("u", "", "Target URL (use {PAYLOAD} for injection point)")
	wordlist := flag.String("w", "", "Path to wordlist file(s), comma-separated")

	// Basic options
	threads := flag.Int("t", 50, "Number of concurrent threads")
	delay := flag.Int("delay", 0, "Delay between requests in ms (per-worker)")
	retries := flag.Int("retry", 0, "Number of retries for failed transient network connections")
	userAgent := flag.String("ua", "DirFuzz/2.0", "User-Agent string")
	var parsedHeaders headerFlags
	flag.Var(&parsedHeaders, "h", "Custom HTTP header (can be specified multiple times, e.g. -h 'Key: Value')")

	// Status code matching
	matchCodesStr := flag.String("mc", "200,204,301,302,307,308,401,403,405,500", "Match HTTP status codes (comma-separated)")
	filterSizesStr := flag.String("fs", "", "Filter response sizes (comma-separated)")
	autoFilterThreshold := flag.Int("af", engine.DefaultAutoFilterThreshold, "Number of identical responses before auto-filtering (0 = off)")

	// Body matching/filtering
	matchRegex := flag.String("mr", "", "Match body regex pattern")
	filterRegex := flag.String("fr", "", "Filter body regex pattern")
	filterWords := flag.Int("fw", -1, "Filter responses with exact word count (-1 = off)")
	filterLines := flag.Int("fl", -1, "Filter responses with exact line count (-1 = off)")
	matchWords := flag.Int("mw", -1, "Match responses with exact word count (-1 = off)")
	matchLines := flag.Int("ml", -1, "Match responses with exact line count (-1 = off)")

	// Extensions & mutation
	extensions := flag.String("e", "", "Extensions to append (comma-separated, e.g. php,html,js)")
	mutate := flag.Bool("mutate", false, "Enable smart mutation")
	mutationsStr := flag.String("me", engine.DefaultMutations, "Mutation extensions (comma-separated)")

	// Recursive scanning
	recursive := flag.Bool("r", false, "Enable recursive scanning")
	maxDepth := flag.Int("depth", 3, "Max recursion depth")

	// Method fuzzing
	methods := flag.String("m", "", "HTTP methods to fuzz (comma-separated, e.g. GET,POST,PUT,DELETE)")
	smartAPI := flag.Bool("smart-api", false, "Only use multi-method for API-like paths")
	requestBody := flag.String("d", "", "Request body for POST/PUT/PATCH (use {PAYLOAD} for injection)")

	// Redirect handling
	followRedirects := flag.Bool("follow", false, "Follow HTTP redirects")
	maxRedirects := flag.Int("max-redirects", 5, "Maximum redirects to follow")

	// Proxy
	proxyFile := flag.String("proxy", "", "File containing SOCKS5 proxy list")

	// HTTP/TLS Configuration
	timeout := flag.Int("timeout", 5, "HTTP request timeout in seconds")
	connectTimeout := flag.Int("connect-timeout", 0, "Connection timeout in seconds (0 = use -timeout value)")
	readTimeout := flag.Int("read-timeout", 0, "Read timeout in seconds (0 = use -timeout value)")
	insecure := flag.Bool("k", false, "Skip TLS certificate verification (insecure)")
	useHTTP2 := flag.Bool("http2", false, "Use HTTP/2 protocol")

	// Cookies
	cookies := flag.String("b", "", "Cookies to send with requests (e.g. 'session=abc; token=xyz')")

	// Eagle Mode
	eagleScan := flag.String("eagle", "", "Previous scan file for differential comparison")

	// Output
	outputFile := flag.String("o", "", "Output file path (default: scans/<hostname>/scan_<timestamp>.<format>)")
	outputFormat := flag.String("of", "jsonl", "Output format: jsonl, csv, url")
	noTUI := flag.Bool("no-tui", false, "Disable TUI, print results to stdout")

	// Response time filtering
	rtMin := flag.String("rt-min", "", "Filter responses faster than this duration (e.g. 500ms, 1s)")
	rtMax := flag.String("rt-max", "", "Filter responses slower than this duration (e.g. 5s, 10s)")

	// Proxy-out (replay hits through external proxy)
	proxyOut := flag.String("proxy-out", "", "Replay hits through HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")

	// Auto-calibrate
	autoCalibrate := flag.Bool("ac", false, "Auto-calibrate to detect wildcard responses")

	// Resume
	resumeFile := flag.String("resume", "", "Resume from a previous scan state file")

	// Multiple targets
	urlsFile := flag.String("urls", "", "File containing target URLs (one per line)")

	// Config file
	configFile := flag.String("config", "", "Load config from YAML/TOML file")

	// Plugins
	pluginMatch := flag.String("plugin-match", "", "Lua plugin file for custom response matching")
	pluginMutate := flag.String("plugin-mutate", "", "Lua plugin file for payload mutation")

	flag.Parse()

	// Load config file if specified
	if *configFile != "" {
		viper.SetConfigFile(*configFile)
		if err := viper.ReadInConfig(); err != nil {
			fmt.Printf("Error reading config file: %v\n", err)
			os.Exit(1)
		}

		// Override flags with config file values (only if flag wasn't explicitly set)
		if !isFlagSet("u") && viper.IsSet("target") {
			*target = viper.GetString("target")
		}
		if !isFlagSet("w") && viper.IsSet("wordlist") {
			*wordlist = viper.GetString("wordlist")
		}
		if !isFlagSet("t") && viper.IsSet("threads") {
			*threads = viper.GetInt("threads")
		}
		if !isFlagSet("ua") && viper.IsSet("user_agent") {
			*userAgent = viper.GetString("user_agent")
		}
		if !isFlagSet("mc") && viper.IsSet("match_codes") {
			*matchCodesStr = viper.GetString("match_codes")
		}
		if !isFlagSet("fs") && viper.IsSet("filter_sizes") {
			*filterSizesStr = viper.GetString("filter_sizes")
		}
		if !isFlagSet("af") && viper.IsSet("auto_filter_threshold") {
			*autoFilterThreshold = viper.GetInt("auto_filter_threshold")
		}
		if !isFlagSet("me") && viper.IsSet("mutations") {
			*mutationsStr = viper.GetString("mutations")
		}
		if !isFlagSet("e") && viper.IsSet("extensions") {
			*extensions = viper.GetString("extensions")
		}
		if !isFlagSet("proxy") && viper.IsSet("proxy_file") {
			*proxyFile = viper.GetString("proxy_file")
		}
		if !isFlagSet("o") && viper.IsSet("output") {
			*outputFile = viper.GetString("output")
		}
		if !isFlagSet("timeout") && viper.IsSet("timeout") {
			*timeout = viper.GetInt("timeout")
		}
		if !isFlagSet("k") && viper.IsSet("insecure") {
			*insecure = viper.GetBool("insecure")
		}
		if !isFlagSet("b") && viper.IsSet("cookies") {
			*cookies = viper.GetString("cookies")
		}
	}

	// Print version and exit
	if *version {
		fmt.Println("🦇 DirFuzz v2.1")
		os.Exit(0)
	}

	// Validate required args
	if *target == "" && *urlsFile == "" && *resumeFile == "" {
		fmt.Println("Usage: dirfuzz -u <URL> -w <wordlist> [options]")
		fmt.Println("       dirfuzz -urls <file> -w <wordlist> [options]")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *wordlist == "" && *resumeFile == "" {
		fmt.Println("Error: -w <wordlist> is required")
		os.Exit(1)
	}

	// Build target list
	var targets []string
	if *urlsFile != "" {
		data, err := os.ReadFile(*urlsFile)
		if err != nil {
			fmt.Printf("Error reading URLs file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
				targets = append(targets, line)
			}
		}
		if len(targets) == 0 {
			fmt.Println("Error: no valid URLs found in file")
			os.Exit(1)
		}
	} else if *target != "" {
		targets = []string{*target}
	}

	// Parse match codes (support ranges like 200-299)
	var matchCodes []int
	if *matchCodesStr != "" {
		codes, err := parseStatusCodes(*matchCodesStr)
		if err != nil {
			fmt.Printf("Error parsing status codes: %v\n", err)
			os.Exit(1)
		}
		matchCodes = codes
	}

	// Parse filter sizes
	var filterSizes []int
	if *filterSizesStr != "" {
		for _, fs := range strings.Split(*filterSizesStr, ",") {
			size, err := strconv.Atoi(strings.TrimSpace(fs))
			if err != nil {
				fmt.Printf("Invalid filter size: %s\n", fs)
				os.Exit(1)
			}
			filterSizes = append(filterSizes, size)
		}
	}

	// Parse mutations
	var mutationsList []string
	if *mutationsStr != "" {
		for _, m := range strings.Split(*mutationsStr, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				if m != "~" && !strings.HasPrefix(m, ".") {
					m = "." + m
				}
				mutationsList = append(mutationsList, m)
			}
		}
	}

	// Parse extensions
	var exts []string
	if *extensions != "" {
		for _, ext := range strings.Split(*extensions, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				exts = append(exts, ext)
			}
		}
	}

	// Parse response time filters
	var rtMinDur, rtMaxDur time.Duration
	if *rtMin != "" {
		d, err := time.ParseDuration(*rtMin)
		if err != nil {
			fmt.Printf("Invalid -rt-min duration: %s\n", *rtMin)
			os.Exit(1)
		}
		rtMinDur = d
	}
	if *rtMax != "" {
		d, err := time.ParseDuration(*rtMax)
		if err != nil {
			fmt.Printf("Invalid -rt-max duration: %s\n", *rtMax)
			os.Exit(1)
		}
		rtMaxDur = d
	}

	// Parse methods
	var methodList []string
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			m = strings.TrimSpace(strings.ToUpper(m))
			if m != "" {
				methodList = append(methodList, m)
			}
		}
	}

	// Calculate timeout values
	timeoutVal := time.Duration(*timeout) * time.Second
	connectTimeoutVal := timeoutVal
	readTimeoutVal := timeoutVal
	if *connectTimeout > 0 {
		connectTimeoutVal = time.Duration(*connectTimeout) * time.Second
	}
	if *readTimeout > 0 {
		readTimeoutVal = time.Duration(*readTimeout) * time.Second
	}

	// Run for each target
	for i, tgt := range targets {
		if len(targets) > 1 {
			fmt.Printf("\n[*] Scanning target %d/%d: %s\n", i+1, len(targets), tgt)
		}

		opts := ScanOptions{
			Target:              tgt,
			Wordlist:            *wordlist,
			Threads:             *threads,
			DelayMs:             *delay,
			UserAgent:           *userAgent,
			Headers:             parsedHeaders,
			MatchCodes:          matchCodes,
			FilterSizes:         filterSizes,
			Extensions:          exts,
			Mutations:           mutationsList,
			Methods:             methodList,
			SmartAPI:            *smartAPI,
			RequestBody:         *requestBody,
			Mutate:              *mutate,
			Recursive:           *recursive,
			MaxDepth:            *maxDepth,
			ProxyFile:           *proxyFile,
			EagleScan:           *eagleScan,
			OutputFile:          *outputFile,
			OutputFormat:        *outputFormat,
			NoTUI:               *noTUI,
			AutoCalibrate:       *autoCalibrate,
			MatchRegex:          *matchRegex,
			FilterRegex:         *filterRegex,
			FilterWords:         *filterWords,
			FilterLines:         *filterLines,
			MatchWords:          *matchWords,
			MatchLines:          *matchLines,
			FollowRedirects:     *followRedirects,
			MaxRedirects:        *maxRedirects,
			ResumeFile:          *resumeFile,
			RTMin:               rtMinDur,
			RTMax:               rtMaxDur,
			ProxyOut:            *proxyOut,
			Timeout:             timeoutVal,
			ConnectTimeout:      connectTimeoutVal,
			ReadTimeout:         readTimeoutVal,
			Insecure:            *insecure,
			Cookies:             *cookies,
			UseHTTP2:            *useHTTP2,
			PluginMatch:         *pluginMatch,
			PluginMutate:        *pluginMutate,
			AutoFilterThreshold: *autoFilterThreshold,
			MaxRetries:          *retries,
		}

		runScan(opts)
	}
}

func runScan(opts ScanOptions) {
	// Init engine
	eng := engine.NewEngine(opts.Threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
	eng.ConfigureFilters(opts.MatchCodes, opts.FilterSizes)

	// Set target
	if err := eng.SetTarget(opts.Target); err != nil {
		fmt.Printf("Error: invalid target URL: %v\n", err)
		return
	}

	// Apply config
	eng.UpdateUserAgent(opts.UserAgent)
	eng.SetDelay(time.Duration(opts.DelayMs) * time.Millisecond)

	eng.Config.Lock()
	eng.Config.Headers = opts.Headers
	// Add Cookie header if provided
	if opts.Cookies != "" {
		eng.Config.Headers["Cookie"] = opts.Cookies
	}
	eng.Config.Extensions = opts.Extensions
	eng.Config.Methods = opts.Methods
	eng.Config.SmartAPI = opts.SmartAPI
	eng.Config.Mutate = opts.Mutate
	eng.Config.Recursive = opts.Recursive
	eng.Config.MaxDepth = opts.MaxDepth
	eng.Config.FollowRedirects = opts.FollowRedirects
	eng.Config.MaxRedirects = opts.MaxRedirects
	eng.Config.RequestBody = opts.RequestBody
	eng.Config.FilterWords = opts.FilterWords
	eng.Config.FilterLines = opts.FilterLines
	eng.Config.MatchWords = opts.MatchWords
	eng.Config.MatchLines = opts.MatchLines
	eng.Config.OutputFormat = opts.OutputFormat
	eng.Config.FilterRTMin = opts.RTMin
	eng.Config.FilterRTMax = opts.RTMax
	eng.Config.ProxyOut = opts.ProxyOut
	eng.Config.Timeout = opts.Timeout
	eng.Config.Insecure = opts.Insecure
	eng.Config.AutoFilterThreshold = opts.AutoFilterThreshold
	eng.Config.MaxRetries = opts.MaxRetries
	eng.Config.Unlock()

	// Match/Filter regex
	if opts.MatchRegex != "" {
		if err := eng.SetMatchRegex(opts.MatchRegex); err != nil {
			fmt.Printf("Error: invalid match regex: %v\n", err)
			return
		}
	}
	if opts.FilterRegex != "" {
		if err := eng.SetFilterRegex(opts.FilterRegex); err != nil {
			fmt.Printf("Error: invalid filter regex: %v\n", err)
			return
		}
	}

	// Load plugins
	if opts.PluginMatch != "" {
		matcher, err := engine.NewPluginMatcher(opts.PluginMatch)
		if err != nil {
			fmt.Printf("Error loading match plugin: %v\n", err)
			return
		}
		eng.SetMatchPlugin(matcher)
		fmt.Printf("[*] Loaded match plugin: %s\n", opts.PluginMatch)
	}
	if opts.PluginMutate != "" {
		mutator, err := engine.NewPluginMutator(opts.PluginMutate)
		if err != nil {
			fmt.Printf("Error loading mutate plugin: %v\n", err)
			return
		}
		eng.SetMutatePlugin(mutator)
		fmt.Printf("[*] Loaded mutate plugin: %s\n", opts.PluginMutate)
	}

	var startLine int64
	// Resume support
	if opts.ResumeFile != "" {
		eng.ResumeFile = opts.ResumeFile
		var err error
		var wl string
		wl, startLine, err = eng.LoadResumeState(opts.ResumeFile)
		if err != nil {
			fmt.Printf("Error loading resume file: %v\n", err)
			return
		}
		if opts.Wordlist == "" {
			opts.Wordlist = wl
		}
		fmt.Printf("[*] Resuming from: %s\n", opts.ResumeFile)
	}

	// Load proxies
	if opts.ProxyFile != "" {
		if err := eng.LoadProxies(opts.ProxyFile); err != nil {
			fmt.Printf("Warning: failed to load proxies: %v\n", err)
		}
	}

	// Eagle Mode
	if opts.EagleScan != "" {
		if err := eng.LoadPreviousScan(opts.EagleScan); err != nil {
			fmt.Printf("Warning: failed to load previous scan: %v\n", err)
		} else {
			fmt.Printf("[*] Eagle Mode: loaded %d endpoints from previous scan\n", len(eng.PreviousState))
		}
	}

	// Auto-calibrate
	if opts.AutoCalibrate {
		fmt.Println("[*] Running auto-calibration...")
		if err := eng.AutoCalibrate(); err != nil {
			fmt.Printf("Warning: auto-calibration failed: %v\n", err)
		}
	}

	// Determine output file
	outputFile := opts.OutputFile

	// Check if output should go to stdout
	if outputFile == "-" {
		// Stdout mode - force headless and use stdout
		opts.NoTUI = true
	} else if outputFile == "" {
		host := eng.Host()
		host = strings.ReplaceAll(host, ":", "_")
		dir := filepath.Join("scans", host)
		os.MkdirAll(dir, 0755)
		ext := "jsonl"
		if opts.OutputFormat == "csv" {
			ext = "csv"
		} else if opts.OutputFormat == "url" {
			ext = "txt"
		}
		outputFile = filepath.Join(dir, fmt.Sprintf("scan_%s.%s", time.Now().Format("2006-01-02_15-04-05"), ext))
	}
	eng.Config.Lock()
	eng.Config.OutputFile = outputFile
	eng.Config.Unlock()

	// Start workers
	eng.Start()

	// Start wordlist scanner
	eng.KickoffScanner(opts.Wordlist, startLine)

	if opts.NoTUI {
		runHeadless(eng, outputFile, opts.OutputFormat)
	} else {
		runWithTUI(eng, outputFile, opts.OutputFormat)
	}
}

func runHeadless(eng *engine.Engine, outputFile, outputFormat string) {
	var outFile *os.File
	var csvWriter *csv.Writer
	var initialized bool
	var hasResults bool

	initOutput := func() error {
		if initialized {
			return nil
		}
		initialized = true
		if outputFile == "-" {
			outFile = os.Stdout
		} else {
			var err error
			outFile, err = os.Create(outputFile)
			if err != nil {
				return err
			}
		}
		if outputFormat == "csv" {
			csvWriter = csv.NewWriter(outFile)
			engine.WriteCSVHeader(csvWriter)
		}
		return nil
	}

	defer func() {
		if outFile != nil && outputFile != "-" {
			if csvWriter != nil {
				csvWriter.Flush()
			}
			outFile.Close()
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	go func() {
		eng.Wait()
		close(eng.Results)
	}()

	for {
		select {
		case <-sigs:
			fmt.Println("\n[!] Caught interrupt, saving output and exiting...")
			if hasResults && outputFile != "-" {
				fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
			}
			return
		case result, ok := <-eng.Results:
			if !ok {
				if hasResults && outputFile != "-" {
					fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
				}
				return
			}

			if result.IsAutoFilter {
				if msg, ok := result.Headers["Msg"]; ok {
					fmt.Printf("[!] %s: %s\n", result.Path, msg)
				}
				continue
			}

			if err := initOutput(); err != nil {
				fmt.Printf("Error creating output file: %v\n", err)
				continue
			}

			hasResults = true
			fmt.Println(result.String())

			switch outputFormat {
			case "csv":
				csvWriter.Write(result.ToCSV())
			case "url":
				if result.URL != "" {
					fmt.Fprintln(outFile, result.URL)
				}
			default: // jsonl
				data, _ := json.Marshal(result)
				outFile.Write(append(data, '\n'))
			}
		}
	}
}
func runWithTUI(eng *engine.Engine, outputFile, outputFormat string) {
	var outFile *os.File
	var csvWriter *csv.Writer
	initialized := false
	var hasResults int32

	initOutput := func() error {
		if initialized {
			return nil
		}
		initialized = true
		var err error
		if outputFile == "-" {
			outFile = os.Stdout
		} else {
			outFile, err = os.Create(outputFile)
			if err != nil {
				return err
			}
		}
		if outputFormat == "csv" {
			csvWriter = csv.NewWriter(outFile)
			engine.WriteCSVHeader(csvWriter)
		}
		return nil
	}

	defer func() {
		if outFile != nil {
			if csvWriter != nil {
				csvWriter.Flush()
			}
			outFile.Close()
		}
	}()

	// Create a new channel for the TUI to read from
	tuiResults := make(chan engine.Result, 100)
	var wg sync.WaitGroup
	wg.Add(1)

	// Intercept results from the engine
	go func() {
		defer wg.Done()
		for r := range eng.Results {
			if !r.IsAutoFilter {
				if err := initOutput(); err == nil {
					atomic.StoreInt32(&hasResults, 1)
					switch outputFormat {
					case "csv":
						csvWriter.Write(r.ToCSV())
					case "url":
						if r.URL != "" {
							fmt.Fprintln(outFile, r.URL)
						}
					default:
						data, _ := json.Marshal(r)
						outFile.Write(append(data, '\n'))
					}
				}
			}

			// Forward to TUI non-blockingly so we don't hold up the writer
			select {
			case tuiResults <- r:
			default:
			}
		}
		if csvWriter != nil {
			csvWriter.Flush()
		}
	}()

	model := tui.NewModel(eng, tuiResults)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}

	if atomic.LoadInt32(&hasResults) == 1 && outputFile != "-" {
		fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
	}
}
