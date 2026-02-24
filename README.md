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

The engine includes an intelligent auto-filtering mechanism. If a specific status code and response size combination is detected repetitively (threshold: 15 occurrences), it is automatically added to the size filter to reduce noise. These events are logged as `[AUTO-FILTER]` alerts.
# DirFuzz
