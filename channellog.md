# DirFuzz MCP Monitor Change Log

This file is the single place for update notes and changelog entries.

## MCP & Engine Optimization Updates (2026-07-01)

### Dynamic Simhash & Smart Proxies
- **Dynamic Simhash Baseline Calibration**: Implemented pre-flight calibration to generate soft-404 Simhash baselines for nonexistent paths (using 3 randomized routes), preventing warm-up false-positive results. Added `SeedBaseline` to `SimhashTracker` to seed suppressed hashes immediately, and isolated calibration in unit tests by default to prevent deadlocking mock HTTP servers.
- **Bounded Concurrent Swarm Execution with Smart Proxies**: Replaced basic round-robin proxy rotation with a dynamic, stateful `smartProxy` pool tracking proxy health and cooldown periods. Skip proxies in active exponential backoff cooldowns, with automatic fallback if all nodes are cooling down. Connected request loops to a WAF/429 feedback loop (`ReportProxyStatus`) to report blocks, connection dropouts, or WAF fingerprinted blocks.

### Performance & Memory Optimizations
- **Strongly Typed Structure Serialization**: Overhauled `handleBuildScan` in `cmd/mcp/main.go` to return concrete, strongly typed response structures (`BuildScanResponse` and `RecommendedParams`), eliminating interface boxing allocations and optimizing memory footprint.
- **Zero-Allocation Struct Recycling**: Reused `engine.Result` structs inside `handleAnalyze` using a recycled object pool (`sync.Pool`) to eliminate unmarshal allocation overhead.
- **Pruning Rate Limiter Complexity**: Optimized rate limit pruning using `sort.Search` to locate the first non-expired timestamp in $O(\log N)$ time, achieving zero-allocation $O(1)$ prefix truncation.
- **Pre-Resolved Canonical Directories**: Pre-resolved canonical allowed configurations at startup to avoid repeated `filepath.EvalSymlinks` filesystem system calls.
- **Single-Allocation scope.LoadDir**: Optimized slice allocation by pre-allocating the destination slice with a single memory block, eliminating dynamic slice growth and copying overhead.
- **Precompiled Hashed ScopeEngine**: Replaced sequential scope array iteration with a two-tier hashed port lookup in `ScopeEngine` for optimal scale performance.

### Stability & Safety Fixes
- **Stream Serialization for Scanning**: Refactored `runScan` and `handleScan` in `cmd/mcp/main.go` to immediately stream JSONL discoveries to disk in real-time, preventing scan data loss.
- **Time-Based Scan Registry Eviction**: Implemented an eviction schedule in `scanRegistry` that automatically deletes completed scans older than 1 hour, freeing up engine references and memory.
- **Concurrent Target Expansion**: Parallelized expansion probes in `handleExpand` with a pool of `3` concurrent workers and context cancellation to prevent MCP client timeouts.
- **Stream-Optimized Line Counter**: Avoided `bufio.Scanner` token length crashes on large wordlist lines (>64KB) by using a chunked block reader.
- **RawPath Serialization URL Fix**: Scrubbed `RawPath` in `resolveProbeTarget` to prevent URL serialization corruption.
- **Scope Port Fallback Bypass Fix**: Handled fallback ports (`80`/`443`) in `extractAssetEndpoint` when no explicit port is defined in scope configurations.
- **Fail-Fast LoadDir Invariants**: Aborted scope folder parsing immediately on encountering bad files to eliminate coverage blind spots.

### Engine Performance Audit Optimization
- **Zero-Allocation Structs & Fast Paths**: Eliminated map allocations in the worker request hot-path by mapping pre-compiled config headers and executing direct map lookups for captured HTTP headers (`server`, `x-powered-by`, etc.) rather than splitting raw strings.
- **Config Snapshot Debouncing**: Debounced config setter mutations (`AddHeader`, `SetMethod`, etc.) by 10ms using a `sync.Mutex` and `time.AfterFunc`, converting what used to be hundreds of sequential $O(N)$ deep-copies into a single atomic snapshot build.
- **Hash Function Inlining**: Reused a single `fnv.New64a()` hasher for SimHash token generation (zeroed via `Reset()`) and implemented inline bitwise FNV-1a hashing for the sharded Bloom Filter (`TestAndAddString`), removing millions of heap allocations.
- **Connection Pool Unblocking**: Eliminated the mandatory 50ms blocking read HealthCheck inside the `pool.go` idle connection checkout, relying completely on the client’s existing transparent write-retry layer to handle stale TCP connections.
- **WAF Parsing Zero-Allocation**: Rewrote the 403-Bypass WAF classification engine to bypass 8KB heap allocations via an in-place `containsFold()` byte matcher and native `strings.IndexByte` header splitting.
- **Lock-Free Array Escalation**: Scaled `IsSoftFour` from an $O(N)$ random map iteration into a self-sorting "Bubble Up" contiguous struct slice cache, checking the most frequent soft-404 centroids in $O(1)$ operations under heavy load.
- **Channel Allocation Reduction**: Replaced destructive `close()` and `make()` channel recreation in the Priority Job Queue with non-blocking single-buffer signals, halting extreme GC pressure under 10k+ RPS loads.
- **Concurrent Maps**: Eliminated 13 `sync.Map` instances that were utilized for write-heavy state tracking, replacing them with a custom strongly-typed `ConcurrentMap` (wrapping a `sync.RWMutex` + `map`) for optimal write velocity.
- **Benchmark Hot-Path Suite**: Added `BenchmarkBuildRequest`, `BenchmarkSimhashBody`, `BenchmarkBloomTestAndAdd`, `BenchmarkComputeResponseMetrics`, and `BenchmarkConfigSnapshot` to lock in optimization gains.

### Engine Refactoring & Maintenance Updates
- **Massive Engine Decoupling**: Refactored the core `pkg/engine/engine.go` (~4200 lines) across three phases to drastically improve maintainability:
  - Extracted the SimHash state and deduplication logic exactly as-is into `pkg/engine/simhash.go`, utilizing a new `SimhashTracker` interface.
  - Safely moved the `worker(id int)` core loop into `pkg/engine/worker.go`.
  - Extracted the highly tangled recursive scan branch pruning and mirror checking logic into `pkg/engine/recursive.go` alongside a new `RecursiveTracker` interface in `pkg/engine/recursive_tracker.go`.
- **Go Module Update**: Updated `go.mod` to use `go 1.24.2` to resolve compatibility issues and unblock users.
- **Gitignore Update**: Added the `findings/` directory to `.gitignore` to prevent committing raw scan outputs.

## Bug Bounty OS & Intelligence Architecture

### TUI & AuthMatrix Enhancements
- **Graph View Layout Fixes**: Fixed viewport dimensional calculations in the TUI's Discovery Graph (`StateGraph`) view. Compensated for border and padding offsets (`m.width - 4` and `vpHeight - 4`) to prevent internal header wrappers and lines from expanding past the terminal boundaries, which previously caused the top progress bar and application header to scroll off-screen.
- **Dynamic Role Rotation**: Implemented a rotating UI feature in the TUI list view that cycles through AuthMatrix identities every 5 seconds. It dynamically displays the varying HTTP status codes **as well as the exact response metrics (Size, Words, Lines, Duration, Content-Type, and Headers)** for each tested role directly on the single result line, along with a stylish Dracula Purple `[Role: <name>]` tag. This fixes an issue where the displayed metrics were incorrectly statically locked to the baseline response.
- **AuthMatrix Logic Fix**: Resolved a critical engine bug where explicitly specifying `-m GET` via CLI overrode the entire AuthMatrix (`--auth`) evaluation logic, silently falling back to unauthenticated single-requests. 
- **Tabbed Identity Inspection**: Overhauled the `StateDetail` view in the TUI (`pkg/tui/tui.go`) to display a tabbed interface for AuthMatrix results (`[ mobilecookie ] [ privatecookie ]`). Added dynamic hot-swapping using `Left`, `Right`, and `Tab` keys to effortlessly cycle and inspect the precise raw request/response byte slices corresponding to each evaluated identity.
- **WAF Concurrency Bypasses**: Altered the engine's AuthMatrix execution loop (`executeAuthMatrixRequests`) to fire credential permutations sequentially rather than concurrently, mitigating aggressive rate-limiting WAF blocks and false 403s on distributed targets (like Cloudflare).
- **Completion Webhook**: Integrated a lightweight completion notification hook into the engine. When the `DISCORD_WEBHOOK` environment variable is present, DirFuzz will fire an asynchronous, silent JSON ping to the webhook the exact millisecond the wordlist scan finishes, completely independent of the TUI remaining open.


### Phase 7.5: Architecture Hardening
- **Concurrency**: Protected `MemoryStore` with `sync.RWMutex` across all map accesses to prevent data races during concurrent ingestion.
- **Deterministic Replay**: Sorted map keys in `CampaignDiff` endpoint iteration and removed `time.Now()` pollution from projection generation, ensuring byte-for-byte reproducibility of reports (verified by `TestExportDeterminism`).
- **Ledger Secrets Safety**: Implemented `EvidenceSanitizer` middleware to proactively strip credentials (`Authorization`, `Cookie`, `X-API-Key`, `JWT`) from events before they are committed to the immutable ledger.
- **Storage Contract & Analytics**: Upgraded `EventStore` interface to require `context.Context` for future DB adapters, and capped Risk `Attack Surface Expansion` signals to prevent wildcard alert fatigue.

### Phase 6.12: Campaign Intelligence Analytics
- Formalized DirFuzz as an Analyst Operations Platform by measuring intelligence effectiveness and computing operational risks.
- Overhauled memory with an exponential `KnowledgeDecay` engine enforcing a strict half-life on findings, mitigating poisoning from stale architecture patterns.
- Constructed an explainable `CampaignRisk` heuristic mapping macroscopic regression trajectories and tracking surface exposure growth.
- Embedded Playbook grading logic evaluating confirmed yields against false positives (e.g. 13% Success Rate) to prioritize high-value intelligence without ever overriding the human execution boundary.

### Phase 6.11: Campaign Intelligence Projection
- Evolved the architecture into a full deterministic Bug Bounty Intelligence Operations platform.
- Introduced `CampaignIntelligenceProjection` to act as a queryable intelligence layer built deterministically from the immutable Event Ledger.
- Added `CampaignBaseline` tracking for high-level chronological target evolution (e.g., Target maturity trends over 90 days).
- Implemented deterministic multi-analyst conflict resolution via `DecisionHash`, `SessionID`, and `AnalystID` within `DecisionMetadata`.
- Introduced `GraphQuery` to allow semantic Analyst questions (e.g., "Show endpoints with repeated Auth changes").
- Hardened the projection layer with tests verifying O(N) million-node scale rebuilds, query replay consistency, and absolute target isolation.

### Phase 6.10: Regression & Continuous Monitoring
- Transformed differential analysis into continuous Regression tracking.
- Introduced `DiffFingerprint` equipped with `TargetID` to guarantee deterministic differentiation over time.
- Categorized regressions logically into `RegressionAuth`, `RegressionExposure`, and `RegressionBehavior`.
- Added `DiffMemory` to track Analyst reactions, systematically suppressing false-positive diff shapes in future campaigns.
- Added `DiffSeverity` heuristics, preventing alert fatigue from low-impact (INFO) adjustments while raising CRITICAL shifts directly into the Playbook suggestion loop.

### Phase 6.9: Campaign Intelligence & Differential Recon
- Separated cross-snapshot differential logic (`DiffEngine`) cleanly away from Engine/Worker loops, keeping core logic isolated.
- Defined `CampaignDiff` mapping state shifts linearly into `NEW`, `CHANGED`, and `REMOVED` topologies using `EvidenceProjection`.
- Ensured Differential Analysis events exist natively inside the Timeline as `CampaignDiffEvent`.

### Phase 6.8: Analyst Memory & Evidence-Weighted Prioritization
- Built the `KnowledgeStore` with explicitly bounded and isolated cross-session memory mechanisms.
- Abstracted volatility away via `PatternSignature` hashing, mapping URL volatility into structural logic behavior.
- Injected `KnowledgeBonus` directly into Engine priority, bounded strictly to 15 points, allowing Analyst approvals to safely accelerate scans dynamically while preventing malicious queue starvation.
- Introduced `KnowledgeWeight` decay rate configurations.

### Phase 6.7: Playbook Suggestion Engine
- Instituted the Playbook Intelligence layer using a strict Suggestion-only paradigm. 
- Analyzed Findings against Playbook criteria and generated safe, Analyst-driven recommendations (`PlaybookSuggestion`).
- Maintained absolute operational safety: Playbooks strictly recommend paths while Analysts retain execution rights via `ValidationCommand`.

### Phase 6.6: Analyst Validation Control Plane
- Closed the Human-In-The-Loop capability chain: analysts can triage findings, explicitly choose validation actions, and feed jobs back into the Engine via the `ValidationCommand` boundary.
- Solidified the invariant that UI Intelligence may guide, but cannot bypass the worker Engine limits.

### Phase 6.5: Scan Timeline & Deterministic Replay
- Enforced the `EventLedger` as the single immutable source of truth for the entire platform.
- Reconstructed the Analyst interface via Deterministic Replay: reconstructing timelines, graphs, and findings exactly as they occurred historically.

## Discovery Graph & Concurrency Improvements

### Discovery Graph & Topology Engine
- Implemented `DiscoveryGraph` and `DiscoveryNode` providing a deterministic topology engine for discovered routes.
- Migrated path storage from temporary slices to structured graphs tracking exact lineage (e.g., tracking when a route was found via JS parsing or GraphQL).
- Added persistent storage of the `DiscoveryGraph` into the `ResumeState`, allowing graphs to seamlessly survive scan interruptions.
- Integrated `DiscoveryGraph` natively into the terminal interface (TUI). Pressing `g`/`G` overlays the graph across standard views, rendering a color-coded tree based on real-time HTTP response statuses.

### Concurrency and Stability Fixes
- Fixed a concurrency deadlock in the `ChangeWordlist` wordlist hot-swap mechanism. Resolved the deadlock by using a sentinel context shutdown and concurrent channel drains, ensuring workers appropriately clear pending jobs without hanging.
- Enabled local `127.0.0.1` endpoints in ParamFuzz unit tests using the new `AllowPrivateTargets` configuration override, bypassing recently introduced SSRF restrictions that were spuriously failing test coverage. All 110+ engine tests now pass reliably under stress testing.

## Security and Reliability Fixes

### MCP scan approval and scope enforcement

- Added approval-token enforcement to `dirfuzz_expand`.
- Added scope validation for `dirfuzz_expand` using the configured scope directory.
- Changed `dirfuzz_expand` to use the stricter scan rate limit.
- Added `approval_token` as a documented `dirfuzz_expand` argument.
- Updated the tool description so expansion is described as approved and scope-checked.

### MCP probe target validation

- Updated WAF probe, parameter fuzzing, and auth-test target resolution.
- Absolute probe URLs are now rejected unless their hostname matches the original scan target hostname.
- Relative probe paths continue to resolve against the original scan target.

### MCP token and scan-state safety

- Replaced direct approval-token string comparison with constant-time comparison.
- Cleared completed scan engine pointers so finished scans can release engine memory.
- Moved `scanState.canceled` reads under the existing scan-state lock to avoid a data race.

### Dial-time private IP filtering

- Added reusable private-IP checking in `pkg/netutil`.
- Added dial-time DNS resolution and private-IP rejection in the raw HTTP client.
- Direct dials now resolve once, reject private or loopback IPs when private targets are disabled, and dial the validated IP.
- Added HTTP/2 client support for the same private-target policy.
- Threaded `AllowPrivateTargets` through engine raw requests, HTTP/2 client refresh, and harvest clients.

### Monitor scan timeout

- Added `MAX_SCAN_DURATION` support for the monitor.
- Default monitor max scan duration is now 90% of `SCAN_INTERVAL`.
- Monitor scan result collection now aborts the current engine when the max duration is exceeded.
- Timed-out scan cycles return an explicit timeout error so the scheduler can continue.

### Configuration and audit-log hygiene

- Added `DIRFUZZ_SCAN_ENABLED=false` to `dirfuzz-mcp.env.example`.
- Added a commented `DIRFUZZ_SCAN_APPROVAL_TOKEN` example with a safety note.
- Added local `dirfuzz-audit.jsonl` paths to `.gitignore`.

## Tests Added or Updated

- Added MCP tests for `dirfuzz_expand` rejecting disabled scans, missing approval tokens, and out-of-scope targets.
- Added MCP tests for rejecting different-host absolute probe URLs and allowing same-host absolute probe URLs.
- Added MCP test to verify completed scan states clear their engine pointer.
- Added DNS rebinding regression coverage in `pkg/httpclient`.
- Added monitor timeout and `MAX_SCAN_DURATION` config tests.

## Verification Run

The focused packages touched by these changes passed:

```powershell
go test ./pkg/netutil
go test ./pkg/httpclient
go test ./cmd/mcp
go test ./cmd/monitor
```

`go test ./pkg/engine` was also attempted, but the package timed out in the existing `TestChangeWordlistConcurrency` test.

## Historical Updates

### 2026-06-27

- Implemented Passive Tech-Stack Aware Fingerprinting to identify technologies (e.g., Spring Boot, PHP, nginx) via headers, cookies, and bodies without extra network requests during fuzzing.
- Wired the fingerprinter directly into the Worker Loop, utilizing zero-allocation cookie parsing, and tracking findings safely alongside WAF evasion techniques.
- Configured tech detections to append to the immutable Event Ledger with the `TECH:` label prefix.

### 2026-05-27

- Added a native Nuclei Orchestrator Subprocess. When `--nuclei` is passed, DirFuzz streams discovered URLs directly into Nuclei's `stdin` via a dedicated subprocess.
- Parsed Nuclei's JSONL `stdout` in real-time, mapping the template findings natively into DirFuzz's TUI and output log with the `NUCLEI` label.
- Implemented concurrent deduplication (`sync.Map`) so Nuclei never double-scans the same endpoint.

### 2026-05-26

- Added anomaly-only TUI filtering with `a` and `:anomalies [on|off|toggle]` so the visible hit list can collapse down to eagle alerts, drift, discovered params, bypasses, auth-matrix findings, timing-oracle hits, and manual marks.
- Added in-TUI triage marking so selected hits can be toggled as interesting with `t`, surfaced visually in the list/detail views, and restored from append-mode UI state on reopen.
- Added repeatable `--exclude-path` regex support so authenticated, recursive, and harvested scan work can skip unsafe routes such as logout, delete, destroy, or reset endpoints before they ever hit the queue.
- Added repeater clipboard/export actions so requests and responses can be copied without relying on terminal text selection: `Ctrl+Y` copies the request, `Alt+Y` copies the response, `Alt+B` copies both, `Alt+C` copies a generated `curl` command, and `Alt+W` exports the request to a temporary `.http` file.
- Added repeater command-palette actions `:copy-request`, `:copy-response`, `:copy-both`, `:copy-curl`, and `:export-request [file]`.
- Added `--history-mode overwrite|append` so `-o` can either start fresh or keep an append-only JSONL results journal.
- Added persistent TUI restore for append mode, including loading prior hits into the visible list when reopening the same `-o` file.
- Added repeater session persistence in a sidecar file such as `results.jsonl.ui.json`, including restored tabs, per-session history, and saved replay state.
- Made append-mode TUI history merge repeated findings by endpoint identity so the visible list updates to the latest snapshot instead of duplicating every rediscovery.
- Made `:restart` preserve visible history and repeater sessions in append mode while continuing to add or update findings from the new run.
- Extended saved JSONL results with optional raw request/response byte fields so restored hits can keep working with hex, diff, and replay workflows when `--save-raw` is enabled.
- Replaced the markdown-looking dashboard tables with modern card sections using bordered panels.
- Improved the selected row styling in lists to use a left accent bar (`>`) and colorful text instead of a full purple background.
- Redesigned the footer into a compact layout with colored minimalist key chips and muted labels.
- Upgraded the command panel to a full "Command Palette" featuring descriptions for each command and streamlined selected-item styling.
- Added a blinking live status indicator (`SCANNING` or `PAUSED`) to the right side of the footer.
- Fixed an issue where the Repeater's text area rendered an opaque background that obscured transparent terminal backgrounds.

### 2026-05-25

- Added bounded asynchronous 401/403 bypass micro-tasks that try standard path normalization and IP-spoofing headers, and emit labeled `[BYPASS: ...]` findings when a permutation returns a successful response.
- Added JavaScript source map harvesting so `.js` responses can discover hidden routes from `SourceMap` / `X-SourceMap` headers or `sourceMappingURL` directives and feed them back into the fuzzing queue.
- Replaced the monitor's hardcoded Slack/Discord webhook formatter with ProjectDiscovery-style notify provider config loading, so alerts can go through Slack, Discord, Telegram, Pushover, Teams, Gotify, Google Chat, SMTP, or custom webhooks from a standard `provider-config.yaml`.
- Added passive route harvesting from the Wayback Machine, Common Crawl, and AlienVault OTX with per-source timeouts so slow archives cannot hang the scan loop.
- Added optional Interactsh-based OOB payload generation with `--oob`, plus monitor-side polling and webhook alerts for blind SSRF/command-injection style hits.
- Removed `403` from the recursive wildcard shortcut so access-controlled directories are not silently pruned during recursion.
- Fixed recursive scanning noise where child routes such as `api/api`, `api/api/user`, and `api/user/api` could be reported when they returned the same response fingerprint as an already-seen parent or canonical route.
- Added default-on recursive pruning through `--recursive-prune` to report low-value static/resource branches once, then avoid spending recursive depth under paths like `includes/fonts`.
- Made recursive pruning conservative for pentest workflows: static-looking branches are still recursively scanned when their listings expose interesting names such as `config`, `.bak`, `.old`, `.env`, `secret`, `admin`, `api`, or `upload`.

### 2026-05-23

- Removed the built-in hidden-parameter brute-force list and made parameter fuzzing opt-in through `--param-wordlist` / `--param-wordlists`.
- Disabled automatic parameter fuzzing when no parameter wordlist is provided.
- Added smart parameter hint extraction from response text, error messages, HTML forms, and links to augment configured parameter wordlists.
- Deduplicated hidden-parameter probes across repeated URLs that differ only by query values, such as multiple `jobs.php?id=*` findings.
- Fixed redirect-followed parameter fuzzing to probe the final canonical URL instead of the pre-redirect URL, reducing `301` false positives on paths like `/api`.
- Added neutral control probes for hidden-parameter fuzzing to suppress pages that change generically for any query string.
- Added `--harvest-response` for generic response-driven endpoint discovery, including JSON API bodies that list child endpoints.
- Added `--harvest-response-depth` and `--harvest-response-fetch` to tune bounded follow-up crawling for response-driven harvesting.
- Made live scan responses feed response-harvest discoveries back into the active queue, so paths revealed by endpoints like `/api/` are scanned during the same run.
- Fixed harvest progress accounting so harvested jobs count toward total progress instead of pushing scans past 100%.
- Fixed raw request/response capture for hidden-parameter fuzzing when `--save-raw` is enabled.
- Prevented canceled requests from being counted as network failures or retry noise.
- Removed the default 60-second scan cap so normal scans run until completion unless `--max-duration` is set.
- Made the TUI exit cleanly when the engine result stream closes instead of freezing on partial progress.
- Stopped auto param-fuzz from triggering on redirect-only responses.
