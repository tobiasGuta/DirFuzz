# DirFuzz

DirFuzz is a high-performance directory fuzzing tool written in Go, featuring a Terminal User Interface (TUI) for real-time monitoring and interaction. It supports recursive scanning, smart filtering, mutation strategies, body matching/filtering, auto-throttling, redirect following, multiple output formats, and differential analysis.

<p align="center">
  <img width="472" height="433" alt="image" src="https://github.com/user-attachments/assets/62b98b2e-1b36-4953-81a5-db05dabf2b71" />
</p>

## Features

- **High Concurrency**: Tunable worker pool with live RPS tracking and dynamic scaling.
- **Interactive TUI**: Dracula-themed real-time dashboard with command mode, autocomplete, and scrollable log viewport.
  - **Live Detail View**: Press `Enter` on any hit to open a split-screen view showing the **raw HTTP Request and Response** (automatically de-chunked and gzip decompressed).
- **HTTP/2 Support**: Native HTTP/2 protocol support with `-http2` flag for modern servers.
- **Redirect Detection & Following**: Extracts `Location` headers for `30x` responses. Optionally follows redirect chains with `-follow`.
- **Smart Filtering**:
  - **Auto-Calibration**: Detects wildcard responses based on consistency.
  - **Auto-Filter**: Automatically identifies and blocks repetitive responses (e.g., custom 404 pages returning 200 OK) during the scan.
    - **403 Classification**: Classifies `403` responses as `CF_WAF_BLOCK`, `CF_ADMIN_403`, `NGINX_403`, or `GENERIC_403` using body + header signals (case-insensitive).
        - When `HEAD` returns `403`, DirFuzz performs a short `GET` follow-up for classification only, while keeping the general HEAD-first scan strategy.
  - **Word/Line Filtering**: Filter or match responses by exact word count (`-fw`, `-mw`) or line count (`-fl`, `-ml`).
  - **Body Regex**: Match (`-mr`) or filter (`-fr`) responses by regex patterns applied to the response body.
  - **Status Code Ranges**: Match status codes using ranges like `-mc 200-299,401-403,500`.
- **Auto-Throttle**: Automatically reduces workers and increases delay when 429 (rate limit) responses are detected.
- **Recursive Scanning**: Automatically discovers directories and queues them for deeper scanning with wildcard detection.
- **Smart Mutation**: Generates common backup file checks (e.g., `.bak`, `.old`, `.save`, `~`, `.swp`) when a file extension is detected.
- **Smart API Method Fuzzer**: Test hidden REST API endpoints using multiple HTTP methods, intelligently applied only to API-like paths.
- **Request Body Support**: Send custom request bodies for POST/PUT/PATCH fuzzing with `-d` flag. Supports `{PAYLOAD}` injection.
- **Arbitrary Payload Injection**: Use `{PAYLOAD}` anywhere in the URL (e.g., `http://example.com/api/{PAYLOAD}/users`).
- **Cookie Support**: Send cookies with requests using `-b "session=abc; token=xyz"`.
- **Multiple Output Formats**: JSONL (default), CSV, or URL-only output with `-of`. Supports stdout with `-o -` for piping.
- **Multi-Target Scanning**: Scan multiple targets from a file with `-urls`.
- **Differential Analysis (Eagle Mode)**: Compare current scan results with a previous JSONL output to highlight changes.
- **Proxy Support**: SOCKS5 proxy rotation from file with authentication support (`user:pass@host:port`).
- **Response Metadata**: Captures Content-Type, response time (duration), word count, line count, and `forbidden_403_type` (for classified 403 responses) per result.
- **Response Time Filtering**: Filter results by response time with `-rt-min` and `-rt-max` flags (e.g., only show slow responses over 500ms).
- **Proxy-Out (Burp Replay)**: Forward discovered hits through an HTTP proxy (e.g., Burp Suite) with `--proxy-out` for manual inspection and replay.
- **Scope-Aware Recursion**: Recursive scanning only follows redirects that stay within the target domain, preventing off-scope crawling.
- **HEAD→GET Caching**: Automatically detects HEAD rejection (405/501) and caches it to skip HEAD for all subsequent requests.
- **Headless Mode**: Run without TUI using `-no-tui` for scripting and CI/CD pipelines.
- **Config File Support**: Load settings from YAML/TOML config files with `-config`.
- **Lua Plugin System**: Extend DirFuzz with custom matchers and mutators using Lua scripts.
- **Configurable Timeouts**: Separate connection and read timeouts with `-connect-timeout` and `-read-timeout`.
- **TLS Control**: Skip certificate verification with `-k` for testing against self-signed certs.

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

### Response Time Filtering

```bash
# Only show responses slower than 500ms (interesting blind injection candidates)
./dirfuzz -u http://example.com -w wordlist.txt -rt-min 500ms

# Only show responses faster than 2s (filter out timeouts)
./dirfuzz -u http://example.com -w wordlist.txt -rt-max 2s

# Combine both for a window
./dirfuzz -u http://example.com -w wordlist.txt -rt-min 200ms -rt-max 5s
```

### Proxy-Out (Burp Replay)

```bash
# Forward all hits through Burp Suite for manual inspection
./dirfuzz -u http://example.com -w wordlist.txt --proxy-out http://127.0.0.1:8080
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

### Output to stdout (Pipe-Friendly)

```bash
# Pipe results directly to other tools
./dirfuzz -u http://example.com -w wordlist.txt -of url -o - | nuclei -t cves/
```

### HTTP/2 Support

```bash
# Use HTTP/2 protocol for modern servers
./dirfuzz -u https://example.com -w wordlist.txt -http2
```

### Cookie Support

```bash
# Send cookies with requests
./dirfuzz -u https://example.com -w wordlist.txt -b "session=abc123; token=xyz789"
```

### TLS/SSL Options

```bash
# Skip certificate verification (self-signed certs)
./dirfuzz -u https://self-signed.example.com -w wordlist.txt -k
```

### Custom Timeouts

```bash
# Set overall timeout
./dirfuzz -u http://example.com -w wordlist.txt -timeout 10

# Set separate connect and read timeouts
./dirfuzz -u http://example.com -w wordlist.txt -connect-timeout 5 -read-timeout 30
```

### Status Code Ranges

```bash
# Match specific status code ranges
./dirfuzz -u http://example.com -w wordlist.txt -mc 200-299,401-403,500

# Only successful responses and auth errors
./dirfuzz -u http://example.com -w wordlist.txt -mc 200-299,401,403
```

### Config File

```bash
# Load settings from a config file
./dirfuzz -config dirfuzz.yaml -u http://example.com -w wordlist.txt

# CLI flags override config file values
./dirfuzz -config dirfuzz.yaml -u http://example.com -w wordlist.txt -t 100
```

Example config file (`dirfuzz.yaml`):
```yaml
threads: 50
timeout: 10
user_agent: "Custom-Agent/1.0"
extensions: "php,html,js"
match_codes: "200,204,301,302,401,403"
recursive: true
depth: 3
```

### Lua Plugins

```bash
# Use a custom matcher plugin
./dirfuzz -u http://example.com -w wordlist.txt -plugin-match plugins/custom_matcher.lua

# Use a custom mutator plugin
./dirfuzz -u http://example.com -w wordlist.txt -plugin-mutate plugins/custom_mutator.lua

# Use both
./dirfuzz -u http://example.com -w wordlist.txt -plugin-match match.lua -plugin-mutate mutate.lua
```

Example matcher plugin:
```lua
-- Match responses containing "admin" or with status 500
function match(response)
    if string.find(response.body, "admin") then
        return true
    end
    if response.status_code == 500 then
        return true
    end
    return false
end
```

Example mutator plugin:
```lua
-- Add custom payload variants
function mutate(payload)
    return {
        payload,
        payload .. ".backup",
        payload .. ".old",
        "." .. payload
    }
end
```

### Proxy with Authentication

```bash
# SOCKS5 proxy with credentials
# Format in proxy file: user:pass@host:port
./dirfuzz -u http://example.com -w wordlist.txt -proxy proxies.txt
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
| `-timeout` | HTTP request timeout in seconds | `5` |
| `-connect-timeout` | Connection timeout in seconds (0 = use -timeout) | `0` |
| `-read-timeout` | Read timeout in seconds (0 = use -timeout) | `0` |
| `-ua` | User-Agent string | `DirFuzz/2.0` |
| `-h` | Custom HTTP headers (can be specified multiple times, e.g. `-h 'Key: Value'`) | |
| `-b` | Cookies to send with requests (e.g. `'session=abc; token=xyz'`) | |
| `-mc` | Match HTTP status codes (comma-separated, supports ranges: `200-299,401-403`) | `200,204,301,302,307,308,401,403,405,500` |
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
| `-http2` | Use HTTP/2 protocol | `false` |
| `-k` | Skip TLS certificate verification (insecure) | `false` |
| `-proxy` | Path to SOCKS5 proxy list file (supports `user:pass@host:port`) | |
| `-eagle` | Previous scan file for differential comparison | |
| `-o` | Output file path (use `-` for stdout) | auto-generated |
| `-of` | Output format: `jsonl`, `csv`, `url` | `jsonl` |
| `-no-tui` | Disable TUI, print results to stdout | `false` |
| `-ac` | Auto-calibrate to detect wildcard responses | `false` |
| `-resume` | Resume from a previous scan state file | |
| `-urls` | File containing target URLs (one per line) | |
| `-rt-min` | Filter responses faster than this duration (e.g. `500ms`, `1s`) | |
| `-rt-max` | Filter responses slower than this duration (e.g. `5s`, `10s`) | |
| `--proxy-out` | Replay hits through HTTP proxy (e.g. `http://127.0.0.1:8080` for Burp) | |
| `-config` | Load config from YAML/TOML file | |
| `-plugin-match` | Lua plugin file for custom response matching | |
| `-plugin-mutate` | Lua plugin file for payload mutation | |

## Interactive TUI Controls

While running in TUI mode, you can control the scanner using keyboard shortcuts and commands.

### Keyboard Shortcuts

- `p`: Pause/Resume the scanner.
- `:`: Enter Command Mode.
- `?`: Show help.
- `Esc`: Exit Command Mode or Detail View.
- `Enter`: Open Detail View for the selected hit (shows raw request/response).
- `Up/Down` or `k/j`: Scroll through the log list or the Request/Response detail views.
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
| `:changeurl`| `:changeurl <url>` | Change target URL and restart scan. |
| `:restart` | `:restart` | Restart the scan with current config. |
| `:config` | `:config` | Display all current configuration. |
| `:mr` | `:mr admin\|secret` | Set match regex for response body. |
| `:fr` | `:fr Page not found` | Set filter regex for response body. |
| `:fw` | `:fw 5` | Filter by word count (-1 to disable). |
| `:fl` | `:fl 10` | Filter by line count (-1 to disable). |
| `:follow` | `:follow` | Toggle redirect following. |
| `:body` | `:body {"key":"value"}` | Set request body for POST/PUT. |
| `:rtmin` | `:rtmin 500ms` | Set min response time filter (0 = off). |
| `:rtmax` | `:rtmax 5s` | Set max response time filter (0 = off). |
| `:proxyout` | `:proxyout http://127.0.0.1:8080` | Set proxy-out for Burp replay (empty = off). |
| `:clear` | `:clear` | Clear log output. |

## Auto-Filtering

The engine includes an intelligent auto-filtering mechanism. If a specific response fingerprint is detected repetitively (threshold: 15 occurrences), it is automatically added to the size filter to reduce noise. These events are logged as `[AUTO-FILTER]` alerts.

- For most responses, the fingerprint is based on `status code + response size`.
- For `403` responses, the fingerprint includes `forbidden_403_type + response size` so Cloudflare WAF blocks, Cloudflare admin 403s, nginx 403s, and generic 403s are not auto-filtered together.

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

## Configuration Files

DirFuzz supports YAML and TOML configuration files for storing common settings. Use `-config` to load a config file, and CLI flags will override any config file values.

### Supported Settings

```yaml
# Target and wordlist
target: "http://example.com"
wordlist: "/path/to/wordlist.txt"

# Threading and timing
threads: 50
delay: 0
timeout: 10
connect_timeout: 5
read_timeout: 30

# HTTP options
user_agent: "DirFuzz/2.0"
cookies: "session=abc123"
http2: false
insecure: false  # Skip TLS verification

# Filtering
match_codes: "200,204,301,302,401-403,500"
filter_sizes: "0,1234"
match_regex: "admin|secret"
filter_regex: "not found"
filter_words: -1
filter_lines: -1
match_words: -1
match_lines: -1

# Scanning behavior
extensions: "php,html,js,txt"
mutate: true
recursive: true
depth: 3
methods: "GET,POST"
smart_api: true
follow_redirects: false
max_redirects: 5

# Output
output: "results.jsonl"
output_format: "jsonl"
no_tui: false

# Proxy
proxy_file: ""
proxy_out: ""

# Plugins
plugin_match: "plugins/matcher.lua"
plugin_mutate: "plugins/mutator.lua"
```

### Example Config Files

See `dirfuzz.yaml.example` in the repository for a complete example.

## Lua Plugin System

DirFuzz supports Lua plugins for custom response matching and payload mutation. This allows you to extend the tool's functionality without modifying the source code.

### Matcher Plugins

Matcher plugins decide whether a response should be included in results. The plugin receives a table with response metadata and must return `true` or `false`.

**Available response fields:**
| Field | Type | Description |
|-------|------|-------------|
| `status_code` | number | HTTP status code (e.g., 200, 404) |
| `size` | number | Response body size in bytes |
| `words` | number | Word count in response body |
| `lines` | number | Line count in response body |
| `body` | string | Raw response body text |
| `content_type` | string | Content-Type header value |

**Example matcher plugin:**
```lua
-- plugins/admin_finder.lua
-- Only match responses containing admin-related content
function match(response)
    local body = response.body:lower()
    
    -- Match admin panels
    if string.find(body, "admin") or string.find(body, "dashboard") then
        return true
    end
    
    -- Match configuration files
    if string.find(body, "password") or string.find(body, "api_key") then
        return true
    end
    
    -- Match server errors (might reveal info)
    if response.status_code >= 500 then
        return true
    end
    
    return false
end
```

### Mutator Plugins

Mutator plugins generate additional payload variants. The plugin receives a payload string and must return a table of strings (variants to test).

**Example mutator plugin:**
```lua
-- plugins/backup_mutator.lua
-- Generate backup and archive variants
function mutate(payload)
    local variants = {
        payload,                    -- Original
        payload .. ".bak",
        payload .. ".backup",
        payload .. ".old",
        payload .. ".orig",
        payload .. ".save",
        payload .. ".copy",
        payload .. ".tmp",
        payload .. "~",
        payload .. ".swp",
        "." .. payload,             -- Hidden file
        payload .. ".tar.gz",
        payload .. ".zip",
        payload .. ".7z",
    }
    
    -- Add date-based variants
    table.insert(variants, payload .. ".2024")
    table.insert(variants, payload .. ".2023")
    table.insert(variants, payload .. "_backup")
    
    return variants
end
```

### Using Plugins

```bash
# Matcher plugin only
./dirfuzz -u http://example.com -w wordlist.txt -plugin-match plugins/admin_finder.lua

# Mutator plugin only  
./dirfuzz -u http://example.com -w wordlist.txt -plugin-mutate plugins/backup_mutator.lua

# Both plugins
./dirfuzz -u http://example.com -w wordlist.txt \
    -plugin-match plugins/admin_finder.lua \
    -plugin-mutate plugins/backup_mutator.lua
```

### Plugin Development Tips

1. **Keep plugins simple** - Plugins run for every request, so complex logic adds latency
2. **Use string.find() over patterns** - Simple substring matching is faster
3. **Return early** - Check the most likely conditions first
4. **Test standalone** - Test your Lua logic in a Lua interpreter before using with DirFuzz
5. **Benchmark your plugin** - At 50 threads, a plugin adding 1ms per call costs ~50ms of 
   aggregate throughput per second. Profile the real impact by comparing RPS with and without 
   your plugin using `-no-tui`:
```bash
   # Baseline RPS
   dirfuzz -u http://example.com -w wordlist.txt -no-tui

   # Plugin RPS
   dirfuzz -u http://example.com -w wordlist.txt -plugin-match matcher.lua -no-tui
```
   If RPS drops significantly, simplify your plugin logic.

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
- **Live Detail View**: View raw HTTP Requests and Responses directly in the TUI, side-by-side. Handles chunked transfer encoding and GZIP compression natively.
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
- **Response time filtering** (`-rt-min`, `-rt-max`): Filter results by response duration — useful for blind injection detection or filtering timeouts.
- **Proxy-out** (`--proxy-out`): Forward all discovered hits through an HTTP proxy (e.g., Burp Suite at `http://127.0.0.1:8080`) for manual replay and inspection.
- **Scope-aware recursion**: Recursive scanning now checks that redirect targets stay within the original domain before queuing them, preventing off-scope crawling.
- **Live RPS counter**: Real-time requests-per-second displayed in TUI header.

## Changes in v2.1

### Code Quality Improvements
- **Centralized constants**: All magic numbers extracted to `pkg/engine/constants.go` for maintainability.
- **ScanOptions struct**: Replaced 30+ parameter function signature with clean configuration struct.
- **Error handling**: Improved error handling throughout, especially in resume state saving.
- **Context cancellation**: HTTP requests now properly respect context cancellation for cleaner shutdowns.

### New Features
- **HTTP/2 support** (`-http2`): Native HTTP/2 protocol support for modern servers.
- **Cookie support** (`-b`): Send cookies with requests (e.g., `-b "session=abc; token=xyz"`).
- **Per-phase timeouts**: Separate connection (`-connect-timeout`) and read (`-read-timeout`) timeouts.
- **Status code ranges** (`-mc`): Support ranges like `-mc 200-299,401-403,500` for flexible matching.
- **Stdout output** (`-o -`): Output results to stdout for piping to other tools.
- **Config file support** (`-config`): Load settings from YAML/TOML files.
- **Lua plugin system**: Custom matchers (`-plugin-match`) and mutators (`-plugin-mutate`) via Lua scripts.
- **TLS verification control** (`-k`): Opt-in insecure mode for self-signed certificates (secure by default).
- **Proxy authentication**: SOCKS5 proxy credentials support (`user:pass@host:port` format).
- **Configurable HTTP timeout** (`-timeout`): Now configurable via CLI flag (was hardcoded at 5s).


### Advanced Engine Features & Fixes
* **Per-Host Rate Limiting**: The global queue rate limits (`-delay`, RPS) are now cleanly tracked independently at a per-host scope. This prevents slower proxy/multi-target scans on one URL from artificially starving different targets in your scan.
* **Transient Connection Retry Logic (`-retry`)**: HTTP dial connections are now protected by exponential backoff logic configurable via the `-retry X` flag—this guarantees random TCP network spikes on flaky hosts don't lead to blindly skipped payloads.  
* **Expanded `{PAYLOAD}` Injection**: The `{PAYLOAD}` parameter injection tag mapping is directly supported natively inside `-ua "User-Agent"`, header mappings (`-h`), and `Cookie` values, scaling fuzzing dynamically into any protocol layer requirement. 
* **Multi-Wordlist Native Parsing**: The `--wordlist` (`-w`) flag now functionally parses direct comma-separated arrays (e.g. `-w api.txt,common.txt`) rendering multi-layer iterations consecutively. 
* **Thread-Safe DNS Resolution Caching**: The HTTP client manages local `sync.Map` IP caching with a 60s TTL over custom dials mapping directly back to native IP structs to bypass extremely expensive and repetitive localized OS DNS/socket queries during massive proxy bypass operations.
* **Safe OS Signal Interruption**: Intercepts `SIGINT` (Ctrl+C) and `SIGTERM` signals directly into the processing engine—halting tasks safely, flushing the `bufio.Writer`/`csvWriter` instantly, and closing files gracefully preventing partially written corrupted outputs or lost JSON/CSV states. 
* **Configurable File Mutations (`-me`)**: Dynamic parameter controlling file extension overrides (defaults: `-me ".bak,.old,.save,~,.swp"`). 
* **Internal Magic Numbers Removed**: Dynamic channel queue depths corresponding linearly natively to `-threads` (`DefaultWorkerCount * 10`) handling saturation cleanly.

## Bug Bounty Playbook

Real-world strategies for using DirFuzz during bug bounty engagements. These aren't hypotheticals — they're workflows that produce results.

---

### 1. Recon Phase: First Touch on a New Target

Start quiet. You don't know the target yet — how it responds to 404s, whether it rate-limits, what stack it runs. Your first scan is about **learning the target's behavior**, not finding bugs.

```bash
dirfuzz -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 20 -ac
```

**Why this works:**
- `-t 20` — Start low. You're profiling, not hammering. You can scale up from the TUI later with `:threads 50`.
- `-ac` — Auto-calibrate catches wildcard responses immediately. If the target returns a custom 404 page with a `200 OK`, you'll know in seconds instead of drowning in false positives.

Once the scan is running, watch the TUI. If you see a wall of identical response sizes, drop into command mode and add a size filter live:
```
:filter 4523
```

No restart needed. The scan keeps running and the noise disappears.

---

### 2. Hunting Backup Files and Exposed Source Code

Developers leave things behind. `.bak`, `.old`, `.swp`, `~` files sitting in production. One forgotten `config.php.bak` can give you database credentials.

```bash
dirfuzz -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e php,asp,aspx,jsp,js,py,rb,conf,config,yml,yaml,json,xml,sql,log,txt,env,bak,old -mutate -r -depth 2
```

**Why this works:**
- `-e` with a fat extension list hits every common web stack.
- `-mutate` takes every file the wordlist finds and automatically generates `.bak`, `.old`, `.save`, `.swp`, `~` variants. If the wordlist has `config.php`, mutation will also try `config.php.bak`, `config.php.old`, `config.php~`, etc.
- `-r -depth 2` — Recursive mode. When DirFuzz finds a directory (301/302), it queues it for deeper scanning automatically. Scope-aware recursion ensures you don't wander off-domain.

**Pro tip:** If you find a `.git` directory or `web.config`, that single finding can cascade into source code disclosure. Pair this with a targeted wordlist for `.git/` enumeration on a second pass.

---

### 3. API Endpoint Discovery with Method Fuzzing

Modern apps hide functionality behind REST APIs. A path might return 404 on GET but 200 on POST. Most fuzzers only send GET — you're leaving bugs on the table.

```bash
dirfuzz -u https://api.target.com -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -m GET,POST,PUT,DELETE,PATCH -smart-api -mc 200,201,204,301,302,401,403,405,500
```

**Why this works:**
- `-m GET,POST,PUT,DELETE,PATCH` — Tests every common HTTP method against each path.
- `-smart-api` — Doesn't waste time sending DELETE to `/images/logo.png`. It only applies multi-method testing to paths that look like API endpoints (`/api/`, `/v1/`, `/graphql`, paths without file extensions).
- `-mc` includes `405` — A `405 Method Not Allowed` confirms the endpoint **exists** but rejects that method. That's recon gold. It tells you which methods the endpoint *does* accept.

**During the scan**, if you spot an interesting 401 or 403, try adding an auth header live:
```
:header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

---

### 4. Blind Injection Detection via Response Timing

This is where `-rt-min` becomes a weapon. If you're injecting payloads that cause server-side delays (SQL sleep, SSRF to internal hosts, template injection), the response time tells you if it worked.

```bash
dirfuzz -u "https://target.com/search?q={PAYLOAD}" -w sqli-payloads.txt -t 5 -rt-min 3s -delay 500
```

**Why this works:**
- `{PAYLOAD}` injection — The payload goes directly into the query parameter, not appended as a path.
- `-rt-min 3s` — Only show responses that took 3+ seconds. If your payload list contains `' OR SLEEP(5)--`, a 5-second response will light up while everything else is silently filtered.
- `-t 5 -delay 500` — Low and slow. You're doing injection testing, not directory brute-forcing. Be surgical.

**This also works for SSRF detection:**
```bash
dirfuzz -u "https://target.com/proxy?url={PAYLOAD}" -w ssrf-urls.txt -t 3 -rt-min 2s
```

If an internal URL causes a noticeable delay compared to external ones, you've found an SSRF.

---

### 5. Piping Everything to Burp with Proxy-Out

You found hits. Now you need to **replay, modify, and exploit** them. Instead of manually copying URLs into Burp, let DirFuzz do it automatically.

```bash
dirfuzz -u https://target.com -w wordlist.txt -r -mutate --proxy-out http://127.0.0.1:8080
```

Every hit DirFuzz finds gets replayed through Burp's proxy. Open Burp's HTTP History tab and you'll see every discovered endpoint ready for manual testing — with the exact method, headers, and path that triggered the hit.

**Workflow:**
1. Run DirFuzz with `--proxy-out` pointed at Burp.
2. Let it scan. Every 200, 301, 403 — all hits land in Burp's history.
3. After the scan, sort Burp's history by status code or response size.
4. Right-click interesting endpoints → Send to Repeater → Start manual testing.

You can also enable this mid-scan from the TUI:
```
:proxyout http://127.0.0.1:8080
```

---

### 6. Eagle Mode: Catch What Changed

Bug bounty targets push code constantly. Endpoints appear and disappear. What was a 404 last week might be a 200 today — new feature, new attack surface.

```bash
# First scan — establish baseline
dirfuzz -u https://target.com -w wordlist.txt -r -o baseline.jsonl

# Later — run the exact same scan and compare
dirfuzz -u https://target.com -w wordlist.txt -r -eagle baseline.jsonl
```

**Why this works:**
- Eagle Mode loads your previous scan and compares every result. If a path changed status code (was 404, now 200 — or was 200, now 403), it gets flagged as an `[EAGLE]` alert in the TUI.
- New deployments, staging endpoints accidentally exposed, features behind feature flags that just went live — Eagle Mode catches all of it.

**Pro tip:** Automate this. Run a baseline scan during recon, save the JSONL. Set up a cron job or script that re-scans weekly with `-eagle` and `-no-tui`, then grep the output for eagle alerts:
```bash
dirfuzz -u https://target.com -w wordlist.txt -r -eagle baseline.jsonl -no-tui 2>&1 | grep EAGLE
```

---

### 7. Dealing with WAFs and Rate Limits

You hit a target and immediately get 429s or your IP gets temporarily blocked. DirFuzz handles this, but you need to use the right approach.

```bash
dirfuzz -u https://target.com -w wordlist.txt -t 10 -delay 200 -proxy /path/to/socks5-proxies.txt -ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

**Why this works:**
- `-t 10 -delay 200` — Low threads, 200ms between requests. Flies under most rate limiters.
- `-proxy` — SOCKS5 proxy rotation. Each request goes through a different proxy, distributing the load across IPs.
- `-ua` with a real browser User-Agent — Some WAFs flag non-browser UAs immediately.

If you start getting 429s mid-scan, DirFuzz's auto-throttle will kick in automatically — reducing threads by 50% and adding delay. You can also react manually:
```
:delay 500
:threads 5
```

**Custom headers for WAF bypass:**
```
:header X-Forwarded-For: 127.0.0.1
:header X-Original-URL: /admin
:header X-Rewrite-URL: /admin
```

---

### 8. 403 Bypass Discovery

A `403 Forbidden` doesn't mean "nothing here." It means "something here, access denied." That's an invitation.

```bash
dirfuzz -u https://target.com -w wordlist.txt -mc 200,204,301,302,307,403,500 -r -mutate -e php,html,jsp
```

When you find 403 paths, switch your approach. Use `{PAYLOAD}` to fuzz path variations that might bypass access controls:

```bash
# Create a file with 403 bypass patterns
# ..;/admin
# admin..
# /./admin
# admin%20
# admin%09
# %2fadmin
# admin/./
# .admin

dirfuzz -u "https://target.com/{PAYLOAD}" -w 403-bypass-payloads.txt -t 10 -mc 200,301,302
```

If any bypass returns 200 instead of 403, you just found a broken access control vulnerability — that's a high/critical finding on most programs.

---

### 9. Multi-Target Hunting at Scale

You have 50 subdomains from your recon. Scanning them one by one wastes time.

```bash
# subfinder + httpx to get live targets
subfinder -d target.com -silent | httpx -silent -o live-targets.txt

# Scan all of them
dirfuzz -urls live-targets.txt -w wordlist.txt -t 30 -r -mutate -ac -no-tui -of url -o all-findings.txt
```

**Why this works:**
- `-urls` — Feed the entire list. DirFuzz scans each target sequentially.
- `-ac` — Auto-calibrate runs per target, so each one gets its own wildcard detection.
- `-no-tui -of url` — Headless mode, outputs just the discovered URLs. Perfect for piping into other tools.
- After the scan, feed `all-findings.txt` into nuclei, Burp, or your manual testing workflow.

---

### 10. Live Tuning: The TUI Advantage

The biggest edge DirFuzz has is the ability to **change everything mid-scan**. Most fuzzers are fire-and-forget. DirFuzz lets you react to what you're seeing in real time.

**Real scenario:** You start a scan and notice a pattern:
1. You see twenty responses with size `4523` — that's the custom 404 page. Type `:filter 4523`.
2. The noise clears. Now you see a few `403` responses for `/admin`, `/api`, `/internal`. Interesting.
3. You want to focus on those paths recursively. The scan is already running, so just let DirFuzz's recursive mode handle it.
4. You spot a `301` redirect to a subdomain. Because scope-aware recursion is on, DirFuzz only follows it if it stays in-domain.
5. You want deeper inspection — open the Detail view by pressing `Enter` on the hit to read the raw body, or enable Burp proxy live: `:proxyout http://127.0.0.1:8080`.
6. Want to check if there are slow responses suggesting server-side processing? `:rtmin 1s`.
7. Swap to a bigger wordlist without restarting: `:wordlist /path/to/large-wordlist.txt`.

This is how you hunt. Not by running 10 tools — by running one tool that adapts with you.

---

### Quick Reference: High-Value Flag Combos

| Scenario | Command |
|----------|---------|
| First recon on new target | `dirfuzz -u URL -w raft-medium-directories.txt -t 20 -ac` |
| Backup file hunting | `dirfuzz -u URL -w raft-medium-files.txt -e php,asp,js,conf,env -mutate -r` |
| API endpoint discovery | `dirfuzz -u URL -w api-endpoints.txt -m GET,POST,PUT,DELETE -smart-api` |
| Blind injection timing | `dirfuzz -u "URL?param={PAYLOAD}" -w payloads.txt -t 5 -rt-min 3s` |
| All hits to Burp | `dirfuzz -u URL -w wordlist.txt --proxy-out http://127.0.0.1:8080` |
| Diff scan (what changed?) | `dirfuzz -u URL -w wordlist.txt -eagle previous-scan.jsonl` |
| WAF-aware slow scan | `dirfuzz -u URL -w wordlist.txt -t 10 -delay 200 -proxy proxies.txt` |
| Mass subdomain scan | `dirfuzz -urls targets.txt -w wordlist.txt -ac -no-tui -of url` |
| HTTP/2 modern server | `dirfuzz -u URL -w wordlist.txt -http2 -t 50` |
| Self-signed cert target | `dirfuzz -u URL -w wordlist.txt -k` |
| With authentication | `dirfuzz -u URL -w wordlist.txt -b "session=abc" -h "Authorization: Bearer token"` |
| Custom status ranges | `dirfuzz -u URL -w wordlist.txt -mc 200-299,401-403,500` |
| Pipe to other tools | `dirfuzz -u URL -w wordlist.txt -of url -o - \| nuclei -t cves/` |
| Using config file | `dirfuzz -config dirfuzz.yaml -u URL -w wordlist.txt` |
| With Lua plugins | `dirfuzz -u URL -w wordlist.txt -plugin-match matcher.lua -plugin-mutate mutator.lua` |
| Full aggressive (authorized) | `dirfuzz -u URL -w big.txt -t 100 -r -depth 3 -mutate -e php,asp,aspx,jsp,js,py,conf,env,bak,old -m GET,POST,PUT,DELETE -smart-api --proxy-out http://127.0.0.1:8080` |

## Note

DirFuzz is intentionally **not designed for collaborative development**.

The architecture, optimizations, filtering logic, and performance tuning are based on my personal workflow, testing methodology, and performance benchmarks. Because of this, I will not be enabling open collaboration or accepting structural modification pull requests.

However:

-   You are absolutely free to fork the project.

-   You may modify it as you wish.

-   You can adapt it to your own workflows or research needs.

If you build something interesting on top of it, feel free to reference the project.
