# DirFuzz

DirFuzz is a high-performance directory fuzzing tool written in Go, featuring a Terminal User Interface (TUI) for real-time monitoring and interaction. It supports recursive scanning, smart filtering, mutation strategies, and differential analysis.

## Features

- **High Concurrency**: Tunable worker pool for scanning.
- **Interactive TUI**: View real-time progress, modify settings on the fly, and manage filters without restarting.
- **Smart Filtering**:
  - **Auto-Calibration**: Detects wildcard responses based on consistency.
  - **Auto-Filter**: Automatically identifies and blocks repetitive responses (e.g., custom 404 pages returning 200 OK) during the scan.
- **Recursive Scanning**: Automatically discovers directories and queues them for deeper scanning.
- **Smart Mutation**: Generates common backup file checks (e.g., `.bak`, `.old`, `~`) when a file extension is detected.
- **Smart API Method Fuzzer**: Test hidden REST API endpoints using a comma-separated list of HTTP methods, intelligently applied only to likely API paths to save bandwidth.
- **Differential Analysis (Eagle Mode)**: Compare current scan results with a previous JSONL output to highlight changes.
- **Proxy Support**: SOCKS5 proxy rotation.

## Installation

```bash
go build -o dirfuzz main.go
```

## Usage

### Basic Scan

```bash
./dirfuzz -url http://example.com -wordlist path/to/wordlist.txt
```

### Advanced Scan

```bash
./dirfuzz -url http://example.com -wordlist wordlist.txt -extensions php,txt -recursive -mutate
```

### Smart API Method Fuzzing

```bash
./dirfuzz -url http://example.com -wordlist wordlist.txt -X GET,POST,PUT,DELETE -smart-api
```

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL to fuzz (Required) | |
| `-wordlist` | Path to the wordlist file | |
| `-tui` | Enable TUI mode | `true` |
| `-cli` | Run in CLI mode (stdout only, disables TUI) | `false` |
| `-recursive` | Enable recursive fuzzing | `false` |
| `-depth` | Max recursion depth | `3` |
| `-ext` | Extensions to append (comma-separated) | |
| `-mutate` | Enable smart mutation for file backups | `false` |
| `-X` | HTTP Method(s) to use (comma-separated, e.g., `GET,POST`) | |
| `-smart-api` | Intelligently apply methods only to likely API paths | `false` |
| `-fs` | Filter Body Sizes (comma-separated) | |
| `-mc` | Match Status Codes (comma-separated) | `200,204,301,302,307,401,403` |
| `-delay` | Delay between requests (e.g., `10ms`, `1s`) | `0ms` |
| `-eagle` | Path to previous scan for differential comparison | |
| `-o` | Output valid hits to a file (JSONL format) | |
| `-proxies` | Path to SOCKS5 proxy list | |
| `-project` | Project name for logging/isolation | `default` |

## Interactive TUI Controls

While running in TUI mode, you can control the scanner using keyboard shortcuts and commands.

### Keyboard Shortcuts

- `p`: Pause/Resume the scanner.
- `:`: Enter Command Mode.
- `Tab`: Switch focus between Telemetry/Help and Logs.
- `Esc`: Exit Command Mode (restores previous pause state).
- `Ctrl+C` / `q`: Quit.

### Command Mode

Press `:` to enter command mode. The scanner will pause while you type.

| Command | Usage | Description |
|---------|-------|-------------|
| `:worker` | `:worker [int]` | Set the number of concurrent workers. |
| `:set-ua` | `:set-ua [string]` | Set a custom User-Agent string. |
| `:add-header` | `:add-header [Key]: [Value]` | Add a custom HTTP header. |
| `:rm-header` | `:rm-header [Key]` | Remove a custom HTTP header. |
| `:set-delay` | `:set-delay [duration]` | Set request delay (e.g., `50ms`). |
| `:filter-size` | `:filter-size [bytes]` | Add a response size to the filter list. |
| `:rm-filter-size` | `:rm-filter-size [bytes]` | Remove a response size from the filter list. |
| `:filter-code` | `:filter-code [code]` | Add a status code to the match list. |
| `:rm-filter-code` | `:rm-filter-code [code]` | Remove a status code from the match list. |
| `:add-ext` | `:add-ext [extension]` | Add an extension to append to requests. |
| `:rm-ext` | `:rm-ext [extension]` | Remove an extension. |
| `:set-mutate` | `:set-mutate [on|off]` | Toggle smart mutation. |
| `:wordlist` | `:wordlist [path]` | Hot-swap the current wordlist file. |
| `:run` | `:run` | Execute the command and force resume scanning. |
| `:help` | `:help` | Show the available command list. |

## Auto-Filtering

The engine includes an intelligent auto-filtering mechanism. If a specific status code and response size combination is detected repetitively (threshold: 15 occurrences), it is automatically added to the size filter to reduce noise. These events are logged as `[AUTO-FILTER]` alerts.

<img width="1915" height="1025" alt="image" src="https://github.com/user-attachments/assets/94b4f5d1-fdcb-4a7c-acc4-590dbe62a916" />

<img width="1912" height="1023" alt="image" src="https://github.com/user-attachments/assets/52363bda-551f-40cf-ad5c-ebda4e2245a5" />

## Commands 

worker 10, set-delay 166ms, see more here [Go to Command Mode](#command-mode)

<img width="1913" height="988" alt="image" src="https://github.com/user-attachments/assets/ffe6ce82-2f5f-48a3-9600-2066b6e0a5ae" />

## Note

DirFuzz is intentionally **not designed for collaborative development**.

The architecture, optimizations, filtering logic, and performance tuning are based on my personal workflow, testing methodology, and performance benchmarks. Because of this, I will not be enabling open collaboration or accepting structural modification pull requests.

However:

-   You are absolutely free to fork the project.

-   You may modify it as you wish.

-   You can adapt it to your own workflows or research needs.

If you build something interesting on top of it, feel free to reference the project.
