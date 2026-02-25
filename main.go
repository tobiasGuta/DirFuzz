package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// Parse command line flags
	targetURL := flag.String("url", "", "Target URL to fuzz (e.g., http://localhost:3000)")
	wordlistPath := flag.String("wordlist", "", "Path to the wordlist file")
	matchCodesStr := flag.String("mc", "200,204,301,302,307,401,403", "Match Status Codes (comma-separated)")
	filterSizesStr := flag.String("fs", "", "Filter Body Sizes (comma-separated)")
	delayStr := flag.String("delay", "0ms", "Delay between requests (e.g., 10ms, 1s)")
	recursive := flag.Bool("recursive", false, "Enable recursive fuzzing")
	depth := flag.Int("depth", 3, "Max recursion depth")
	runTUI := flag.Bool("tui", true, "Enable TUI mode")
	cliMode := flag.Bool("cli", false, "Run in CLI mode (stdout only, disables TUI)")
	outputFile := flag.String("o", "", "Output valid hits to a file (JSONL format)")
	projectFlag := flag.String("project", "default", "Project name for logging/isolation")
	eagleFlag := flag.String("eagle", "", "Path to previous scan for differential comparison")
	proxyListFlag := flag.String("proxies", "", "Path to SOCKS5 proxy list")
	extFlag := flag.String("ext", "", "Extensions to append (comma-separated, e.g., php,txt)")
	mutateFlag := flag.Bool("mutate", false, "Enable smart mutation for file backups")
	methodFlag := flag.String("X", "", "HTTP Method(s) to use (comma-separated, e.g., GET,POST)")
	smartAPIFlag := flag.Bool("smart-api", false, "Intelligently apply methods only to likely API paths")

	// Custom Usage message to include TUI commands
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nTUI Commands (Internal):")
		fmt.Fprintln(os.Stderr, "  :set-ua [AgentString]    Set User-Agent string")
		fmt.Fprintln(os.Stderr, "  :add-header [Key]: [Val] Add custom HTTP header")
		fmt.Fprintln(os.Stderr, "  :set-delay [duration]    Set request delay")
		fmt.Fprintln(os.Stderr, "  :filter-size [bytes]     Filter response size")
		fmt.Fprintln(os.Stderr, "  :wordlist [path]         Hot-swap wordlist file")
		fmt.Fprintln(os.Stderr, "  :help                    Show available commands")
	}

	flag.Parse()

	// Handle implicit help command via argument
	if len(flag.Args()) > 0 && (flag.Arg(0) == "help" || flag.Arg(0) == ":help") {
		flag.Usage()
		os.Exit(0)
	}

	if *targetURL == "" {
		fmt.Println("Error: -url flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse the URL to get the host for the raw request
	parsedURL, err := url.Parse(*targetURL)
	if err != nil || parsedURL.Host == "" {
		fmt.Println("Error: Invalid URL provided")
		os.Exit(1)
	}
	// host := parsedURL.Host (host unused)

	fmt.Println("Starting DirFuzz Engine...")

	// Configuration
	numWorkers := 100
	expectedItems := uint(10_000_000) // 10 million payloads
	falsePositiveRate := 0.001        // 0.1% false positive rate

	// Initialize the engine
	eng := engine.NewEngine(numWorkers, expectedItems, falsePositiveRate)

	// Configure initial delay
	if *delayStr != "" && *delayStr != "0ms" {
		if d, err := time.ParseDuration(*delayStr); err == nil {
			eng.SetDelay(d)
		} else {
			fmt.Printf("Warning: Invalid delay format %s. Using 0ms.\n", *delayStr)
		}
	}

	// Configure Target
	if err := eng.SetTarget(*targetURL); err != nil {
		fmt.Printf("Error setting target: %v\n", err)
		os.Exit(1)
	}

	// Helper to parse comma-separated integers
	parseInts := func(s string) []int {
		var nums []int
		if s == "" {
			return nums
		}
		parts := strings.Split(s, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if n, err := strconv.Atoi(part); err == nil {
				nums = append(nums, n)
			}
		}
		return nums
	}

	// Configure Filters
	mc := parseInts(*matchCodesStr)
	fs := parseInts(*filterSizesStr)
	eng.ConfigureFilters(mc, fs)

	// Set Recursive settings
	eng.Config.Recursive = *recursive
	eng.Config.MaxDepth = *depth

	// Extensions
	if *extFlag != "" {
		exts := strings.Split(*extFlag, ",")
		eng.Config.Extensions = exts
		fmt.Printf("[*] Extensions loaded: %v\n", exts)
	}

	// Mutation
	eng.Config.Mutate = *mutateFlag
	if *mutateFlag {
		fmt.Println("[*] Smart Mutation enabled")
	}

	// Smart API Method Fuzzer
	if *methodFlag != "" {
		eng.Config.Methods = strings.Split(*methodFlag, ",")
		for i := range eng.Config.Methods {
			eng.Config.Methods[i] = strings.TrimSpace(strings.ToUpper(eng.Config.Methods[i]))
		}
	}
	eng.Config.SmartAPI = *smartAPIFlag
	if len(eng.Config.Methods) > 0 {
		fmt.Printf("[*] Methods loaded: %v (Smart API: %v)\n", eng.Config.Methods, eng.Config.SmartAPI)
	}

	// Proxies
	if *proxyListFlag != "" {
		if err := eng.LoadProxies(*proxyListFlag); err != nil {
			fmt.Printf("Error loading proxy list: %v\n", err)
			os.Exit(1)
		}
	}

	// Auto-Calibrate (detect wildcards)
	fmt.Println("[*] Auto-calibrating...")
	if err := eng.AutoCalibrate(); err != nil {
		fmt.Printf("[!] Calibration warning: %v\n", err)
	}

	// Start the worker pool
	eng.Start()

	// Start reading wordlist (if we have one on CLI)
	if *wordlistPath != "" {
		go eng.StartWordlistScanner(*wordlistPath)
	}

	// Prepare output file (prioritizing -o if given, otherwise using project structure)
	var outputEncoder *json.Encoder
	var eagleEncoder *json.Encoder
	var filename string

	// Determine Project Directory for Eagle Mode logging
	project := "default"
	if *projectFlag != "" {
		project = *projectFlag
	}
	scanDir := fmt.Sprintf("scans/%s", project)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		fmt.Printf("Error creating project directory: %v\n", err)
	}

	// Eagle Mode Setup
	if *eagleFlag != "" {
		fmt.Printf("[*] Loading Eagle Mode baseline: %s\n", *eagleFlag)
		if err := eng.LoadPreviousScan(*eagleFlag); err != nil {
			fmt.Printf("[!] Error loading previous scan: %v\n", err)
			os.Exit(1)
		}

		// Setup dedicated alert log
		alertFile := fmt.Sprintf("%s/eagle_alerts.jsonl", scanDir)
		af, err := os.OpenFile(alertFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("[!] Error creating alert log: %v\n", err)
		} else {
			eagleEncoder = json.NewEncoder(af)
			// defer af.Close() // defer in loop/complex scope is tricky, but main is fine
		}
	}

	if *outputFile != "" {
		filename = *outputFile
	} else {
		// Default to project structure logs
		// Generate timestamped filename
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		filename = fmt.Sprintf("%s/scan_%s.jsonl", scanDir, timestamp)

		if *cliMode {
			fmt.Printf("[*] Logging results to: %s\n", filename)
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	outputEncoder = json.NewEncoder(f)

	// TUI Mode (Default unless -cli is passed)
	if *runTUI && !*cliMode {
		p := tea.NewProgram(tui.NewModel(eng, numWorkers), tea.WithAltScreen())

		// Goroutine to funnel engine results to TUI
		go func() {
			for res := range eng.Results {
				if outputEncoder != nil {
					outputEncoder.Encode(res)
				}
				if res.IsEagleAlert && eagleEncoder != nil {
					eagleEncoder.Encode(res)
				}
				p.Send(tui.LogMsg(res))
			}
		}()

		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// CLI Mode: Print results to stdout
	// We need to consume results in main thread or separate goroutine while waiting
	go func() {
		for res := range eng.Results {
			if outputEncoder != nil {
				outputEncoder.Encode(res)
			}
			if res.IsEagleAlert && eagleEncoder != nil {
				eagleEncoder.Encode(res)
			}
			if res.IsEagleAlert {
				fmt.Printf("[EAGLE ALERT] %s (Old: %d -> New: %d)\n", res.Path, res.OldStatusCode, res.StatusCode)
			}
			fmt.Println(res)
		}
	}()

	eng.Wait()
	fmt.Printf("\n[+] Scan complete. Results saved to: %s\n", filename)
}
