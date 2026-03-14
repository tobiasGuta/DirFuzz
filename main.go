package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// Required
	target := flag.String("u", "", "Target URL (use {PAYLOAD} for injection point)")
	wordlist := flag.String("w", "", "Path to wordlist file")

	// Basic options
	threads := flag.Int("t", 50, "Number of concurrent threads")
	delay := flag.Int("delay", 0, "Delay between requests in ms (per-worker)")
	userAgent := flag.String("ua", "DirFuzz/2.0", "User-Agent string")

	// Status code matching
	matchCodesStr := flag.String("mc", "200,204,301,302,307,308,401,403,405,500", "Match HTTP status codes (comma-separated)")
	filterSizesStr := flag.String("fs", "", "Filter response sizes (comma-separated)")

	// Body matching/filtering
	matchRegex := flag.String("mr", "", "Match body regex pattern")
	filterRegex := flag.String("fr", "", "Filter body regex pattern")
	filterWords := flag.Int("fw", -1, "Filter responses with exact word count (-1 = off)")
	filterLines := flag.Int("fl", -1, "Filter responses with exact line count (-1 = off)")
	matchWords := flag.Int("mw", -1, "Match responses with exact word count (-1 = off)")
	matchLines := flag.Int("ml", -1, "Match responses with exact line count (-1 = off)")

	// Extensions & mutation
	extensions := flag.String("e", "", "Extensions to append (comma-separated, e.g. php,html,js)")
	mutate := flag.Bool("mutate", false, "Enable smart mutation (.bak, .old, .save, etc.)")

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

	flag.Parse()

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

	// Parse match codes
	var matchCodes []int
	if *matchCodesStr != "" {
		for _, cs := range strings.Split(*matchCodesStr, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(cs))
			if err != nil {
				fmt.Printf("Invalid match code: %s\n", cs)
				os.Exit(1)
			}
			matchCodes = append(matchCodes, code)
		}
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

	// Run for each target
	for i, tgt := range targets {
		if len(targets) > 1 {
			fmt.Printf("\n[*] Scanning target %d/%d: %s\n", i+1, len(targets), tgt)
		}
		runScan(tgt, *wordlist, *threads, *delay, *userAgent, matchCodes, filterSizes,
			exts, methodList, *smartAPI, *requestBody, *mutate, *recursive, *maxDepth,
			*proxyFile, *eagleScan, *outputFile, *outputFormat, *noTUI,
			*autoCalibrate, *matchRegex, *filterRegex, *filterWords, *filterLines,
			*matchWords, *matchLines, *followRedirects, *maxRedirects, *resumeFile,
			rtMinDur, rtMaxDur, *proxyOut)
	}
}

func runScan(target, wordlist string, threads, delayMs int, userAgent string,
	matchCodes, filterSizes []int, extensions, methods []string, smartAPI bool,
	requestBody string, mutate, recursive bool, maxDepth int,
	proxyFile, eagleScan, outputFile, outputFormat string, noTUI, autoCalibrate bool,
	matchRegex, filterRegex string, filterWords, filterLines, matchWords, matchLines int,
	followRedirects bool, maxRedirects int, resumeFile string,
	rtMin, rtMax time.Duration, proxyOut string) {

	// Init engine
	eng := engine.NewEngine(threads, 10_000_000, 0.001)
	eng.ConfigureFilters(matchCodes, filterSizes)

	// Set target
	if err := eng.SetTarget(target); err != nil {
		fmt.Printf("Error: invalid target URL: %v\n", err)
		return
	}

	// Apply config
	eng.UpdateUserAgent(userAgent)
	eng.SetDelay(time.Duration(delayMs) * time.Millisecond)

	eng.Config.Lock()
	eng.Config.Extensions = extensions
	eng.Config.Methods = methods
	eng.Config.SmartAPI = smartAPI
	eng.Config.Mutate = mutate
	eng.Config.Recursive = recursive
	eng.Config.MaxDepth = maxDepth
	eng.Config.FollowRedirects = followRedirects
	eng.Config.MaxRedirects = maxRedirects
	eng.Config.RequestBody = requestBody
	eng.Config.FilterWords = filterWords
	eng.Config.FilterLines = filterLines
	eng.Config.MatchWords = matchWords
	eng.Config.MatchLines = matchLines
	eng.Config.OutputFormat = outputFormat
	eng.Config.FilterRTMin = rtMin
	eng.Config.FilterRTMax = rtMax
	eng.Config.ProxyOut = proxyOut
	eng.Config.Unlock()

	// Match/Filter regex
	if matchRegex != "" {
		if err := eng.SetMatchRegex(matchRegex); err != nil {
			fmt.Printf("Error: invalid match regex: %v\n", err)
			return
		}
	}
	if filterRegex != "" {
		if err := eng.SetFilterRegex(filterRegex); err != nil {
			fmt.Printf("Error: invalid filter regex: %v\n", err)
			return
		}
	}

	// Resume support
	if resumeFile != "" {
		eng.ResumeFile = resumeFile
		wl, _, err := eng.LoadResumeState(resumeFile)
		if err != nil {
			fmt.Printf("Error loading resume file: %v\n", err)
			return
		}
		if wordlist == "" {
			wordlist = wl
		}
		fmt.Printf("[*] Resuming from: %s\n", resumeFile)
	}

	// Load proxies
	if proxyFile != "" {
		if err := eng.LoadProxies(proxyFile); err != nil {
			fmt.Printf("Warning: failed to load proxies: %v\n", err)
		}
	}

	// Eagle Mode
	if eagleScan != "" {
		if err := eng.LoadPreviousScan(eagleScan); err != nil {
			fmt.Printf("Warning: failed to load previous scan: %v\n", err)
		} else {
			fmt.Printf("[*] Eagle Mode: loaded %d endpoints from previous scan\n", len(eng.PreviousState))
		}
	}

	// Auto-calibrate
	if autoCalibrate {
		fmt.Println("[*] Running auto-calibration...")
		if err := eng.AutoCalibrate(); err != nil {
			fmt.Printf("Warning: auto-calibration failed: %v\n", err)
		}
	}

	// Determine output file
	if outputFile == "" {
		host := eng.Host()
		host = strings.ReplaceAll(host, ":", "_")
		dir := filepath.Join("scans", host)
		os.MkdirAll(dir, 0755)
		ext := "jsonl"
		if outputFormat == "csv" {
			ext = "csv"
		} else if outputFormat == "url" {
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
	eng.KickoffScanner(wordlist)

	if noTUI {
		runHeadless(eng, outputFile, outputFormat)
	} else {
		runWithTUI(eng, outputFile, outputFormat)
	}
}

func runHeadless(eng *engine.Engine, outputFile, outputFormat string) {
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outFile.Close()

	var csvWriter *csv.Writer
	if outputFormat == "csv" {
		csvWriter = csv.NewWriter(outFile)
		engine.WriteCSVHeader(csvWriter)
		defer csvWriter.Flush()
	}

	go func() {
		eng.Wait()
		close(eng.Results)
	}()

	for result := range eng.Results {
		if result.IsAutoFilter {
			if msg, ok := result.Headers["Msg"]; ok {
				fmt.Printf("[!] %s: %s\n", result.Path, msg)
			}
			continue
		}

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

	fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
}

func runWithTUI(eng *engine.Engine, outputFile, outputFormat string) {
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outFile.Close()

	var csvWriter *csv.Writer
	if outputFormat == "csv" {
		csvWriter = csv.NewWriter(outFile)
		engine.WriteCSVHeader(csvWriter)
		defer csvWriter.Flush()
	}

	// Create a new channel for the TUI to read from
	tuiResults := make(chan engine.Result, 100)
	var wg sync.WaitGroup
	wg.Add(1)

	// Intercept results from the engine
	go func() {
		defer wg.Done()
		for r := range eng.Results {
			// Write to file
			if !r.IsAutoFilter {
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

	// Since we are no longer closing eng.Results natively (to survive restarts),
	// we just let the TUI run until the user quits it.
	model := tui.NewModel(eng, tuiResults)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}

	fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
}
