# DirFuzz Operations Roadmap

DirFuzz's intelligence engine architecture is conceptually complete. The focus now shifts entirely from adding analytical features to operational hardening and real-world Bug Bounty lifecycle management.

## Current Architecture State (Phase 6.12)
DirFuzz currently operates as a pure **Bug Bounty Intelligence OS**, governed by strict architectural boundaries:
- **Event Ledger**: The single immutable source of truth.
- **Discovery Graph**: Deterministic topological mapping of the target.
- **Knowledge Decay**: Exponential half-life priority fading.
- **Explainable Campaign Risk**: Macro-trajectory heuristics driven by structural `RiskSignals`.
- **Playbook Self-Auditing**: Effectiveness metrics grading yield vs false positives.

## Phase 8: Operational Reality

The intelligence architecture is frozen. The next era focuses exclusively on surviving messy real-world targets.

### 1. Storage Backend (The Ledger Persistence)
Move the EventStore from an in-memory interface into robust backends.
- `SQLite` for single Analyst local workflows.
- `BadgerDB` for embedded high-performance persistence.
- `PostgreSQL` for distributed Team Campaigns.
- **Focus**: Crash recovery, migrations, and chronological indexing.

### 2. Real Target Asset Model
Raw endpoints (`/api/users`) are meaningless without context. Evolve tracking into structural assets.
- Define `Asset`: `Domain`, `API`, `Mobile Backend`, `Cloud Service`.
- Incorporate programmatic `Scope Rules` so the Engine knows its boundaries mathematically.

### 3. Execution Identity
As Swarm mode matures, explicitly stamp every Event Ledger entry with strict telemetry.
- Define `ExecutionID`, `WorkerID`, `CampaignID`, and `StartedAt` so every event is traceable (Who, When, Where, Why).

### 4. Real Tool Adapters
DirFuzz is the central brain and ledger. It does not need to be the only scanner.
- Build input adapters for: `ffuf`, `nuclei`, `Burp Suite imports`, `proxy logs`, and `HAR parsers`.
- Ingest external execution telemetry natively into the Event Ledger.

### 5. Actual Bug Bounty Testing
Stop writing code and run the platform.
- Execute campaigns against intentionally vulnerable labs and private authorized Bug Bounty programs.
- **Measure**: Discovery coverage, False Positives, Report Quality, and Time-to-Validation.
- Let the system naturally discover its own unnecessary complexities.
