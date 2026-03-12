# DirFuzz

DirFuzz is a high-performance directory fuzzing tool written in Go, featuring a Terminal User Interface (TUI) for real-time monitoring and interaction. It supports recursive scanning, smart filtering, mutation strategies, body matching/filtering, auto-throttling, redirect following, multiple output formats, and differential analysis.

<p align="center">
  <img width="472" height="433" alt="image" src="https://github.com/user-attachments/assets/62b98b2e-1b36-4953-81a5-db05dabf2b71" />
</p>

## Features

- **High Concurrency**: Tunable worker pool with live RPS tracking and dynamic scaling.
- **Interactive TUI**: Dracula-themed real-time dashboard with command mode, autocomplete, and scrollable log viewport.
- **Redirect Detection & Following**: Extracts `Location` headers for `30x` responses. Optionally follows redirect chains with `-follow`.
- **Smart Filtering**:
  - **Auto-Calibration**: Detects wildcard responses based on consistency.
  - **Auto-Filter**: Automatically identifies and blocks repetitive responses (e.g., custom 404 pages returning 200 OK) during the scan.
  - **Word/Line Filtering**: Filter or match responses by exact word count (`-fw`, `-mw`) or line count (`-fl`, `-ml`).
  - **Body Regex**: Match (`-mr`) or filter (`-fr`) responses by regex patterns applied to the response body.
- **Auto-Throttle**: Automatically reduces workers and increases delay when 429 (rate limit) responses are detected.
- **Recursive Scanning**: Automatically discovers directories and queues them for deeper scanning with wildcard detection.
- **Smart Mutation**: Generates common backup file checks (e.g., `.bak`, `.old`, `.save`, `~`, `.swp`) when a file extension is detected.
- **Smart API Method Fuzzer**: Test hidden REST API endpoints using multiple HTTP methods, intelligently applied only to API-like paths.
- **Request Body Support**: Send custom request bodies for POST/PUT/PATCH fuzzing with `-d` flag. Supports `{PAYLOAD}` injection.
- **Arbitrary Payload Injection**: Use `{PAYLOAD}` anywhere in the URL (e.g., `http://example.com/api/{PAYLOAD}/users`).
- **Multiple Output Formats**: JSONL (default), CSV, or URL-only output with `-of`.
- **Multi-Target Scanning**: Scan multiple targets from a file with `-urls`.
- **Differential Analysis (Eagle Mode)**: Compare current scan results with a previous JSONL output to highlight changes.
- **Proxy Support**: SOCKS5 proxy rotation from file.
- **Response Metadata**: Captures Content-Type, response time (duration), word count, and line count per result.
- **HEAD→GET Caching**: Automatically detects HEAD rejection (405/501) and caches it to skip HEAD for all subsequent requests.
- **Headless Mode**: Run without TUI using `-no-tui` for scripting and CI/CD pipelines.

## Installation

```bash
go build -o dirfuzz main.go
```

### Install with Go

From inside your project directory (`DirFuzz/`), run:
```bash
go install
```

This builds the binary and places it in:
```bash
$HOME/go/bin
```

Make sure that directory is in your PATH:
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
./dirfuzz -u http://example.com -w path/to/wordlist.txt
```

### Advanced Scan

```bash
./dirfuzz -u http://example.com -w wordlist.txt -e php,txt -r -mutate
```

### Smart API Method Fuzzing

```bash
./dirfuzz -u http://example.com -w wordlist.txt -m GET,POST,PUT,DELETE -smart-api
```

### Arbitrary Payload Injection

```bash
./dirfuzz -u "http://localhost:3000/api/{PAYLOAD}/users" -w wordlist.txt -t 10
```

### Body Matching & Filtering

```bash
# Only show responses containing "admin" in the body
./dirfuzz -u http://example.com -w wordlist.txt -mr "admin|dashboard"

# Filter out responses matching a pattern
./dirfuzz -u http://example.com -w wordlist.txt -fr "Page not found"

# Filter by word count (e.g., filter responses with exactly 5 words)
./dirfuzz -u http://example.com -w wordlist.txt -fw 5
```

### Follow Redirects

```bash
./dirfuzz -u http://example.com -w wordlist.txt -follow
```

### POST Fuzzing with Body

```bash
./dirfuzz -u http://example.com/api/login -w usernames.txt -m POST -d '{"username":"{PAYLOAD}","password":"test"}'
```

### Multiple Targets

```bash
./dirfuzz -urls targets.txt -w wordlist.txt -t 30
```

### CSV Output

```bash
./dirfuzz -u http://example.com -w wordlist.txt -of csv -o results.csv
```

### Headless Mode (No TUI)

```bash
./dirfuzz -u http://example.com -w wordlist.txt -no-tui
```

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL to fuzz (Required unless `-urls` is used) | |
| `-w` | Path to the wordlist file (Required) | |
| `-t` | Number of concurrent threads/workers | `50` |
| `-delay` | Delay between requests in milliseconds | `0` |
| `-ua` | User-Agent string | `DirFuzz/2.0` |
| `-mc` | Match HTTP status codes (comma-separated) | `200,204,301,302,307,308,401,403,405,500` |
| `-fs` | Filter response sizes (comma-separated) | |
| `-mr` | Match body regex pattern | |
| `-fr` | Filter body regex pattern | |
| `-fw` | Filter responses with exact word count (-1 = off) | `-1` |
| `-fl` | Filter responses with exact line count (-1 = off) | `-1` |
| `-mw` | Match responses with exact word count (-1 = off) | `-1` |
| `-ml` | Match responses with exact line count (-1 = off) | `-1` |
| `-e` | Extensions to append (comma-separated, e.g. `php,html,js`) | |
| `-mutate` | Enable smart mutation (.bak, .old, .save, etc.) | `false` |
| `-r` | Enable recursive scanning | `false` |
| `-depth` | Max recursion depth | `3` |
| `-m` | HTTP methods to fuzz (comma-separated, e.g. `GET,POST,PUT,DELETE`) | |
| `-smart-api` | Only use multi-method for API-like paths | `false` |
| `-d` | Request body for POST/PUT/PATCH (use `{PAYLOAD}` for injection) | |
| `-follow` | Follow HTTP redirects | `false` |
| `-max-redirects` | Maximum redirects to follow | `5` |
| `-proxy` | Path to SOCKS5 proxy list file | |
| `-eagle` | Previous scan file for differential comparison | |
| `-o` | Output file path | auto-generated |
| `-of` | Output format: `jsonl`, `csv`, `url` | `jsonl` |
| `-no-tui` | Disable TUI, print results to stdout | `false` |
| `-ac` | Auto-calibrate to detect wildcard responses | `false` |
| `-resume` | Resume from a previous scan state file | |
| `-urls` | File containing target URLs (one per line) | |

## Interactive TUI Controls

While running in TUI mode, you can control the scanner using keyboard shortcuts and commands.

### Keyboard Shortcuts

- `p`: Pause/Resume the scanner.
- `:`: Enter Command Mode.
- `?`: Show help.
- `Esc`: Exit Command Mode.
- `Ctrl+C` / `q`: Quit.

### Command Mode

Press `:` to enter command mode. Commands support Tab autocomplete and Up/Down history navigation.

| Command | Usage | Description |
|---------|-------|-------------|
| `:help` | `:help` | Show all available commands. |
| `:pause` | `:pause` | Toggle pause/resume. |
| `:threads` | `:threads 20` | Set the number of concurrent workers. |
| `:delay` | `:delay 100` | Set delay between requests in ms. |
| `:rps` | `:rps 50` | Set requests per second limit (0 = unlimited). |
| `:ua` | `:ua Mozilla/5.0...` | Set a custom User-Agent string. |
| `:header` | `:header Key:Value` | Add a custom HTTP header. |
| `:rmheader` | `:rmheader Key` | Remove a custom HTTP header. |
| `:addcode` | `:addcode 201` | Add a match status code. |
| `:rmcode` | `:rmcode 403` | Remove a match status code. |
| `:filter` | `:filter 1234` | Add a response size to the filter list. |
| `:rmfilter` | `:rmfilter 1234` | Remove a response size from the filter. |
| `:addext` | `:addext php` | Add an extension to append. |
| `:rmext` | `:rmext php` | Remove an extension. |
| `:mutate` | `:mutate` | Toggle smart mutation on/off. |
| `:wordlist` | `:wordlist /path/to/new.txt` | Hot-swap the wordlist file. |
| `:restart` | `:restart` | Restart the scan with current config. |
| `:config` | `:config` | Display all current configuration. |
| `:mr` | `:mr admin\|secret` | Set match regex for response body. |
| `:fr` | `:fr Page not found` | Set filter regex for response body. |
| `:fw` | `:fw 5` | Filter by word count (-1 to disable). |
| `:fl` | `:fl 10` | Filter by line count (-1 to disable). |
| `:follow` | `:follow` | Toggle redirect following. |
| `:body` | `:body {"key":"value"}` | Set request body for POST/PUT. |
| `:clear` | `:clear` | Clear log output. |

## Auto-Filtering

The engine includes an intelligent auto-filtering mechanism. If a specific status code and response size combination is detected repetitively (threshold: 15 occurrences), it is automatically added to the size filter to reduce noise. These events are logged as `[AUTO-FILTER]` alerts.

## Auto-Throttle

When the engine detects 429 (Too Many Requests) responses, it automatically:
1. Reduces the worker count by 50% (minimum 5 workers)
2. Increases the delay by 200ms per throttle event (capped at 5s)
3. Logs the adjustment as an `[AUTO-THROTTLE]` alert in the TUI

This helps maintain scanning effectiveness while respecting rate limits.

<img width="1915" height="1025" alt="image" src="https://github.com/user-attachments/assets/94b4f5d1-fdcb-4a7c-acc4-590dbe62a916" />

<img width="1912" height="1023" alt="image" src="https://github.com/user-attachments/assets/52363bda-551f-40cf-ad5c-ebda4e2245a5" />

## Commands

worker 10, set-delay 166ms, see more here [Go to Command Mode](#command-mode)

<img width="1913" height="988" alt="image" src="https://github.com/user-attachments/assets/ffe6ce82-2f5f-48a3-9600-2066b6e0a5ae" />

## Smart-api

<img width="1919" height="1016" alt="Screenshot 2026-02-24 212226" src="https://github.com/user-attachments/assets/26765ee4-1a56-4132-936a-b43a3e031130" />

## Changes in v2.0

### Bug Fixes
- **Fixed `randomString()`**: Now uses `math/rand/v2` for proper randomization instead of generating identical characters.
- **Fixed rate limiter default**: Defaults to unlimited RPS instead of silently throttling at 50 RPS.
- **Fixed `SetDelay`**: Now actually updates the rate limiter when delay is changed.
- **Fixed drain loop panic**: `ChangeWordlist` drain loop is now bounded to prevent WaitGroup going negative.
- **Fixed RPS calculation**: RPS is now calculated from delta between ticks and displayed in the TUI.
- **Fixed connection handling**: Removed dead connection pool code, connections now properly close with `defer`.

### Performance Improvements
- **Single config snapshot per job**: Workers take one config snapshot per job instead of 3-4 separate RLock calls, reducing lock contention.
- **HEAD→GET caching**: When a host rejects HEAD (405/501), all subsequent requests skip HEAD entirely.
- **Unlimited default RPS**: No more silent throttling — scanning runs at full speed unless you configure a delay.

### New Features
- **Body regex matching** (`-mr`): Only show responses whose body matches a regex pattern.
- **Body regex filtering** (`-fr`): Filter out responses whose body matches a regex pattern.
- **Word/Line filtering** (`-fw`, `-fl`, `-mw`, `-ml`): Filter or match by exact word/line count.
- **Auto-throttle on 429**: Automatically reduces workers and increases delay when rate-limited.
- **Follow redirects** (`-follow`): Follow redirect chains up to `-max-redirects` depth.
- **Request body** (`-d`): Send custom bodies for POST/PUT/PATCH with `{PAYLOAD}` injection.
- **Output formats** (`-of`): Choose between JSONL, CSV, or URL-only output.
- **Multi-target scanning** (`-urls`): Scan multiple targets from a file.
- **Headless mode** (`-no-tui`): Run without TUI for scripting and automation.
- **Resume support** (`-resume`): Save and resume scan progress.
- **Content-Type tracking**: Captured and displayed for each result.
- **Response time tracking**: Millisecond-precision duration captured and displayed.
- **Live RPS counter**: Real-time requests-per-second displayed in TUI header.

## Note

DirFuzz is intentionally **not designed for collaborative development**.

The architecture, optimizations, filtering logic, and performance tuning are based on my personal workflow, testing methodology, and performance benchmarks. Because of this, I will not be enabling open collaboration or accepting structural modification pull requests.

However:

-   You are absolutely free to fork the project.

-   You may modify it as you wish.

-   You can adapt it to your own workflows or research needs.

If you build something interesting on top of it, feel free to reference the project.
