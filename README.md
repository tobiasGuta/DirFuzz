# DirFuzz

DirFuzz is a high-performance directory fuzzing tool written in Go, featuring a Terminal User Interface (TUI) for real-time monitoring and interaction. It supports recursive scanning, smart filtering, mutation strategies, and differential analysis.

<p align="center">
  <img width="472" height="433" alt="image" src="https://github.com/user-attachments/assets/62b98b2e-1b36-4953-81a5-db05dabf2b71" />
</p>


## Features

- **High Concurrency**: Tunable worker pool for scanning.
- **Interactive TUI**: View real-time progress, modify settings on the fly, and manage filters without restarting.
- **Redirect Detection**: Automatically extracts and displays the `Location` header for `30x` responses natively in the dashboard output (`-> /redirect_url`).
- **Smart Filtering**:
  - **Auto-Calibration**: Detects wildcard responses based on consistency.
  - **Auto-Filter**: Automatically identifies and blocks repetitive responses (e.g., custom 404 pages returning 200 OK) during the scan.
- **Recursive Scanning**: Automatically discovers directories and queues them for deeper scanning.
- **Smart Mutation**: Generates common backup file checks (e.g., `.bak`, `.old`, `~`) when a file extension is detected.
- **Smart API Method Fuzzer**: Test hidden REST API endpoints using a comma-separated list of HTTP methods, intelligently applied only to likely API paths to save bandwidth.
- **Arbitrary Payload Injection**: Use the `{PAYLOAD}` keyword anywhere in the URL (e.g., `http://example.com/api/{PAYLOAD}/users`) to fuzz specific path segments or subdomains.
- **Differential Analysis (Eagle Mode)**: Compare current scan results with a previous JSONL output to highlight changes.
- **Proxy Support**: SOCKS5 proxy rotation.

## Installation

```bash
go build -o dirfuzz main.go
```

Install with Go
---------------

From inside your project directory (`DirFuzz/`), run:
```bash
go install
```

This builds the binary and places it in:
```bash
$HOME/go/bin
```

Now make sure that directory is in your PATH:
```bash
echo $PATH
```

If you don’t see $HOME/go/bin, add it:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

For zsh:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

Now you can run:
```bash
dirfuzz -h
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

### Arbitrary Payload Injection

```bash
./dirfuzz -url http://localhost:3000/api/{PAYLOAD}/users -wordlist wordlist.txt -W 10
```

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL to fuzz (Required) | |
| `-wordlist` | Path to the wordlist file | |
| `-W` | Number of concurrent workers | `100` |
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
| `:add-header` | `:add-header [Key]: [Value]` | Add a custom HTTP header. Ensures duplicate headers are safely rejected. |
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
| `:run` | `:run` | Dynamically executes a complete scanner restart with all live configuration changes (wipes analytics cleanly, zeroes progress, and securely drains old queue requests). |
| `:help` | `:help` | Show the available command list. |

## Interactive Upgrades & Configuration View
The DirFuzz Terminal UI now explicitly maps Mouse-Wheel natively for clean vertical viewport scrolling without layout desyncs. The configuration UI panel will now dynamically scale to fit all of your updated user agents, header strings, and loaded extensions simultaneously and without arbitrary `...` truncation overlapping into your execution table!

## Auto-Filtering

The engine includes an intelligent auto-filtering mechanism. If a specific status code and response size combination is detected repetitively (threshold: 15 occurrences), it is automatically added to the size filter to reduce noise. These events are logged as `[AUTO-FILTER]` alerts.

<img width="1915" height="1025" alt="image" src="https://github.com/user-attachments/assets/94b4f5d1-fdcb-4a7c-acc4-590dbe62a916" />

<img width="1912" height="1023" alt="image" src="https://github.com/user-attachments/assets/52363bda-551f-40cf-ad5c-ebda4e2245a5" />

## Commands 

worker 10, set-delay 166ms, see more here [Go to Command Mode](#command-mode)

<img width="1913" height="988" alt="image" src="https://github.com/user-attachments/assets/ffe6ce82-2f5f-48a3-9600-2066b6e0a5ae" />

## Smart-api

<img width="1919" height="1016" alt="Screenshot 2026-02-24 212226" src="https://github.com/user-attachments/assets/26765ee4-1a56-4132-936a-b43a3e031130" />

## Note

DirFuzz is intentionally **not designed for collaborative development**.

The architecture, optimizations, filtering logic, and performance tuning are based on my personal workflow, testing methodology, and performance benchmarks. Because of this, I will not be enabling open collaboration or accepting structural modification pull requests.

However:

-   You are absolutely free to fork the project.

-   You may modify it as you wish.

-   You can adapt it to your own workflows or research needs.

If you build something interesting on top of it, feel free to reference the project.