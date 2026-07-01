# DirFuzz: Bug Bounty Intelligence OS

DirFuzz has evolved from a high-performance web security fuzzer into a deterministic **Bug Bounty Intelligence Operating System**. It is built around an immutable Event Ledger, capable of projecting complex attack surface graphs, continuous regression tracking, playbook intelligence, and deterministic Analyst workflows.

## The Architecture

DirFuzz enforces a strict intelligence pipeline:

```text
HTTP Engine / Workers
     |
     v
Discovery Graph (Evidence Extraction)
     |
     v
Event Ledger (Immutable Source of Truth)
     |
     +-------------------------+
     |                         |
Knowledge Projection      Campaign Analytics
     |                         |
Decay Engine              Risk Engine
     |                         |
     +------------+------------+
                  |
                  v
          Analyst Control Plane (TUI)
                  |
            Analyst Validation
                  |
            Engine Execution
```

### Key Architectural Pillars

1. **Immutable Event Ledger**: Every discovery, diff, playbook suggestion, and analyst decision is recorded as an immutable event. The entire platform state can be perfectly resurrected from the ledger natively.
2. **Deterministic Replay**: DirFuzz allows complete time-travel. A campaign's interface, intelligence projection, and target state can be rebuilt and replayed in O(N) linear time without state corruption.
3. **Analyst Control Plane**: The system never executes autonomous blind loops. Intelligence suggests actions via `PlaybookSuggestions`, but Analysts retain ultimate execution rights (`ValidationCommand`), closing the human-in-the-loop lifecycle.
4. **Continuous Regression & Diff Memory**: DirFuzz tracks structural application shifts (e.g., `403 -> 200`). Utilizing `DiffMemory`, if an Analyst dismisses a noisy diff, DirFuzz remembers and suppresses identical structural noise across future campaigns.
5. **Knowledge Decay**: Intelligence organically decays via an exponential half-life model. A `403` discovered 2 years ago naturally fades in priority, preventing stale API intelligence from poisoning modern queues.
6. **Playbook Efficacy Grading**: The intelligence layer self-audits, measuring Playbook confirmed yields against false positives (e.g., IDOR_CHECK yields 13% bugs) to influence suggestion ranking organically.
7. **Explainable Campaign Risk**: Generates high-level posture overviews tracking Attack Surface Growth, Auth Boundary Changes, and Critical Findings—backed by explicitly traceable `RiskReasons`.

## Included Components

- `cmd/dirfuzz`: The main CLI Analyst Control Plane (TUI) and scanning engine interface.
- `cmd/monitor`: The continuous campaign monitoring and baseline evaluator.
- `cmd/mcp`: The MCP server for scoped AI-assisted workflows.
- `pkg/engine`: The underlying deterministic execution and HTTP workers.
- `pkg/campaign`: The Campaign Intelligence Projection, Risk Engine, and Playbook ecosystem.
- `pkg/knowledge`: The Memory mapping, Decay Engine, and Analyst Decision hierarchy.

## Core Scanning Capabilities

Despite its OS-level architecture, the underlying HTTP engine retains all standard capabilities:
- Fast HTTP/1.1 and HTTP/2 scanning with connection pooling and proxy support.
- Smart filtering: status, size, word/line, regex, response-time, AutoFilter, and SimHash suppression.
- WAF handling and Headless anti-bot fallbacks.
- Recursive wildcards, JS/OpenAPI route harvesting, and generic JSON API response extraction.
- Hidden parameter fuzzing, chunked probing, and timing-oracle enumeration.
- Native Nuclei orchestrator subprocess integration (`--nuclei`).
- Opt-in distributed execution via Swarm mode (`--swarm`).

## Build

Requirements: Go 1.24.2 or newer.

```bash
go build -o dirfuzz ./cmd/dirfuzz
go build -o dirfuzz-monitor ./cmd/monitor
go build -o dirfuzz-mcp ./cmd/mcp
```

## Quick Start (Analyst Workflows)

### 1. Basic Intelligence Collection
```bash
./dirfuzz -u https://example.com -w wordlists/common.txt
```

### 2. Campaign Baseline & Append Mode (Recommended)
```bash
./dirfuzz -u https://example.com -w wordlists/common.txt -o results.jsonl --history-mode append --save-raw
```
In `append` mode, DirFuzz maintains the long-lived Event Ledger (`results.jsonl`). It reconstructs the previous timeline natively upon startup, perfectly preserving Repeater Tabs, Analyst Marks, Knowledge Decay, and Diff Memory.

### 3. Safe Authenticated Routing with Pruning
```bash
./dirfuzz -u https://app.example.com -w wordlists/common.txt \
  --auth admin="Cookie: session=A" \
  --exclude-path "(?i)logout|delete|destroy|reset"
```

### 4. Headless Ledger Generation
```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --no-tui -o results.jsonl
```

### 5. Swarm Distributed Execution
```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --swarm --swarm-nodes 8
```

## TUI: Analyst Control Plane

The Terminal UI is the primary interface for Intelligence Validation.

- `Enter`: Open Hit Details and Playbook Suggestions.
- `h` / `H`: Open Raw Request/Response Hex Views.
- `Tab`: Toggle Request/Response.
- `R`: Save Response as Reference.
- `d` / `D`: Split-screen Diffing against saved reference.
- `r`: Send to Repeater Session.
- `[` / `]`: Cycle Repeater Sessions.
- `Ctrl+Y` / `Alt+Y`: Copy Request / Response to Clipboard.
- `Alt+C`: Generate `curl` command.
- `L`: Toggle Live Event Ledger logs.
- `1` - `5`: Cycle Analytics Dashboards (Campaign Risk, Playbook Metrics, Graph Health).
- `t`: Triage / Mark finding for validation.
- `a`: Anomaly-Only filtering mode.

## Monitoring and MCP

- **`cmd/monitor`**: Run background timelines continuously, computing Diff Severities and triggering webhooks on high-risk regression.
- **`cmd/mcp`**: Exposes the Analyst Graph via standard MCP protocol. Features strict Scope evaluation (`DIRFUZZ_SCOPE_DIR`) and explicit Approval Tokens (`DIRFUZZ_SCAN_APPROVAL_TOKEN`) protecting execution boundaries.

## Docker Deployment
```bash
cp .env.example .env
docker compose up --build -d
```
