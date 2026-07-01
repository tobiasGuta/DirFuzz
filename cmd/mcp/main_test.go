package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dirfuzz/pkg/engine"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestLoadConfigScanEnabledDefaultsFalseWhenMissing(t *testing.T) {
	withUnsetEnv(t, "DIRFUZZ_SCAN_ENABLED")
	cfg := loadConfigForTest(t)

	if cfg.scanEnabled {
		t.Fatal("expected scanning to be disabled when DIRFUZZ_SCAN_ENABLED is missing")
	}
}

func TestLoadConfigScanEnabledFalseValueDisablesScans(t *testing.T) {
	t.Setenv("DIRFUZZ_SCAN_ENABLED", "false")
	cfg := loadConfigForTest(t)

	if cfg.scanEnabled {
		t.Fatal("expected scanning to be disabled when DIRFUZZ_SCAN_ENABLED=false")
	}
}

func TestHandleScanFailsWhenScanningDisabled(t *testing.T) {
	cfg := mcpConfig{scanEnabled: false, scanApprovalToken: "secret", scopeDir: filepath.Join(t.TempDir(), "missing-scope")}
	req := scanRequest(map[string]any{
		"target":         "https://example.com",
		"wordlist":       "common.txt",
		"approval_token": "secret",
	})

	result, err := handleScan(context.Background(), req, cfg, newScanRegistry())
	if err != nil {
		t.Fatalf("handleScan returned protocol error: %v", err)
	}
	assertToolError(t, result, "Scanning is disabled. Set DIRFUZZ_SCAN_ENABLED=true and provide approval_token to run scans.")
}

func TestListScopeWorksWhenScanningDisabled(t *testing.T) {
	cfg := mcpConfig{scanEnabled: false, scopeDir: t.TempDir()}

	result, err := handleListScope(context.Background(), mcp.CallToolRequest{}, cfg)
	if err != nil {
		t.Fatalf("handleListScope returned protocol error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.IsError {
		t.Fatalf("expected list scope to work while scanning is disabled: %s", toolResultText(t, result))
	}
}

func TestHandleScanFailsWhenApprovalTokenMissing(t *testing.T) {
	registry := newScanRegistry()
	cfg := mcpConfig{scanEnabled: true, scanApprovalToken: "secret", scopeDir: filepath.Join(t.TempDir(), "missing-scope")}
	req := scanRequest(map[string]any{
		"target":   "https://example.com",
		"wordlist": "common.txt",
	})

	result, err := handleScan(context.Background(), req, cfg, registry)
	if err != nil {
		t.Fatalf("handleScan returned protocol error: %v", err)
	}
	assertToolError(t, result, "approval_token is required to run scans")
	assertNoRegisteredScans(t, registry)
}

func TestHandleScanFailsWhenApprovalTokenWrong(t *testing.T) {
	registry := newScanRegistry()
	cfg := mcpConfig{scanEnabled: true, scanApprovalToken: "secret", scopeDir: filepath.Join(t.TempDir(), "missing-scope")}
	req := scanRequest(map[string]any{
		"target":         "https://example.com",
		"wordlist":       "common.txt",
		"approval_token": "wrong",
	})

	result, err := handleScan(context.Background(), req, cfg, registry)
	if err != nil {
		t.Fatalf("handleScan returned protocol error: %v", err)
	}
	assertToolError(t, result, "approval_token is invalid")
	assertNoRegisteredScans(t, registry)
}

func TestHandleExpandFailsWhenScanningDisabled(t *testing.T) {
	cfg := mcpConfig{scanEnabled: false, scanApprovalToken: "secret"}
	req := scanRequest(map[string]any{
		"base_target":    "https://api.example.com",
		"hits_jsonl":     "scan-results.jsonl",
		"approval_token": "secret",
	})

	result, err := handleExpand(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("handleExpand returned protocol error: %v", err)
	}
	assertToolError(t, result, "Scanning is disabled. Set DIRFUZZ_SCAN_ENABLED=true and provide approval_token to run scans.")
}

func TestHandleExpandFailsWhenApprovalTokenMissing(t *testing.T) {
	cfg := mcpConfig{scanEnabled: true, scanApprovalToken: "secret"}
	req := scanRequest(map[string]any{
		"base_target": "https://api.example.com",
		"hits_jsonl":  "scan-results.jsonl",
	})

	result, err := handleExpand(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("handleExpand returned protocol error: %v", err)
	}
	assertToolError(t, result, "approval_token is required to run scans")
}

func TestHandleExpandFailsWhenBaseTargetOutOfScope(t *testing.T) {
	scopeDir := t.TempDir()
	writeScopeFile(t, scopeDir, `[{"asset_type":"URL","asset_identifier":"api.example.com","eligible_for_bounty":true}]`)
	cfg := mcpConfig{scanEnabled: true, scanApprovalToken: "secret", scopeDir: scopeDir}
	req := scanRequest(map[string]any{
		"base_target":    "https://out-of-scope.example",
		"hits_jsonl":     "scan-results.jsonl",
		"approval_token": "secret",
	})

	result, err := handleExpand(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("handleExpand returned protocol error: %v", err)
	}
	assertToolErrorContains(t, result, "target blocked by scope validator")
}

func TestResolveProbeTargetRejectsDifferentAbsoluteHost(t *testing.T) {
	_, err := resolveProbeTarget("https://api.example.com/base", "https://evil.example/path")
	if err == nil {
		t.Fatal("expected different-host absolute probe URL to fail")
	}
	if !strings.Contains(err.Error(), "does not match scan target host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveProbeTargetAllowsSameAbsoluteHost(t *testing.T) {
	got, err := resolveProbeTarget("https://api.example.com/base", "https://api.example.com/admin")
	if err != nil {
		t.Fatalf("resolveProbeTarget returned error: %v", err)
	}
	if got != "https://api.example.com/admin" {
		t.Fatalf("resolveProbeTarget() = %q", got)
	}
}

func TestResolveProbeTargetAllowsEscapedPaths(t *testing.T) {
	got, err := resolveProbeTarget("https://api.example.com/base%20path", "/admin")
	if err != nil {
		t.Fatalf("resolveProbeTarget returned error: %v", err)
	}
	if got != "https://api.example.com/base%20path/admin" {
		t.Fatalf("resolveProbeTarget() = %q, want https://api.example.com/base%%20path/admin", got)
	}
}

func TestScanStateFinishClearsEngine(t *testing.T) {
	state := &scanState{engine: &engine.Engine{}}
	state.finish("scan.jsonl", filepath.Join(t.TempDir(), "scan.jsonl"), false)

	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.engine != nil {
		t.Fatal("expected finish to clear engine pointer")
	}
}

func TestApprovalTokenRedactedInAuditLog(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := newAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("newAuditLogger: %v", err)
	}

	handler := wrapToolHandler(toolName, rateLimitRule{}, nil, audit, func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultError("blocked"), nil
	})
	_, err = handler(context.Background(), scanRequest(map[string]any{
		"target":         "https://example.com",
		"wordlist":       "common.txt",
		"approval_token": "super-secret-token",
		"nested": map[string]any{
			"approval_token": "nested-secret-token",
		},
	}))
	if err != nil {
		t.Fatalf("wrapped handler returned protocol error: %v", err)
	}
	if err := audit.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if strings.Contains(string(raw), "super-secret-token") || strings.Contains(string(raw), "nested-secret-token") {
		t.Fatalf("audit log leaked approval token: %s", raw)
	}

	var entry auditEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("unmarshal audit entry: %v", err)
	}
	args, ok := entry.Arguments.(map[string]any)
	if !ok {
		t.Fatalf("expected audit arguments map, got %T", entry.Arguments)
	}
	if args["approval_token"] != "[REDACTED]" {
		t.Fatalf("expected redacted approval_token, got %#v", args["approval_token"])
	}
}

func TestApprovalFailureHappensBeforeScopeOrScanSetup(t *testing.T) {
	registry := newScanRegistry()
	cfg := mcpConfig{
		scanEnabled:       true,
		scanApprovalToken: "secret",
		scopeDir:          filepath.Join(t.TempDir(), "scope-does-not-exist"),
		wordlistDir:       filepath.Join(t.TempDir(), "wordlists-does-not-exist"),
	}
	req := scanRequest(map[string]any{
		"target":         "https://example.com",
		"wordlist":       "missing.txt",
		"approval_token": "wrong",
	})

	result, err := handleScan(context.Background(), req, cfg, registry)
	if err != nil {
		t.Fatalf("handleScan returned protocol error: %v", err)
	}
	assertToolError(t, result, "approval_token is invalid")
	if strings.Contains(toolResultText(t, result), "scope") || strings.Contains(toolResultText(t, result), "wordlist") {
		t.Fatalf("approval failure did not happen before later validation: %q", toolResultText(t, result))
	}
	assertNoRegisteredScans(t, registry)
}

func loadConfigForTest(t *testing.T) mcpConfig {
	t.Helper()
	root := t.TempDir()
	wordlists := filepath.Join(root, "wordlists")
	scopeDir := filepath.Join(root, "scope")
	outputDir := filepath.Join(root, "output")
	for _, dir := range []string{wordlists, scopeDir, outputDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Setenv("DIRFUZZ_WORDLIST_DIR", wordlists)
	t.Setenv("DIRFUZZ_SCOPE_DIR", scopeDir)
	t.Setenv("DIRFUZZ_OUTPUT_DIR", outputDir)
	t.Setenv("DIRFUZZ_SCAN_APPROVAL_TOKEN", "secret")

	cfg, err := loadConfig(filepath.Join(root, "dirfuzz-mcp.exe"))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func withUnsetEnv(t *testing.T, key string) {
	t.Helper()
	old, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func scanRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		},
	}
}

func assertToolError(t *testing.T, result *mcp.CallToolResult, want string) {
	t.Helper()
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !result.IsError {
		t.Fatalf("expected tool error, got success: %#v", result)
	}
	if got := toolResultText(t, result); got != want {
		t.Fatalf("unexpected error text:\nwant: %q\n got: %q", want, got)
	}
}

func assertToolErrorContains(t *testing.T, result *mcp.CallToolResult, want string) {
	t.Helper()
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !result.IsError {
		t.Fatalf("expected tool error, got success: %#v", result)
	}
	if got := toolResultText(t, result); !strings.Contains(got, want) {
		t.Fatalf("unexpected error text:\nwant substring: %q\n           got: %q", want, got)
	}
}

func writeScopeFile(t *testing.T, dir, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "scope.json"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write scope file: %v", err)
	}
}

func toolResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("expected text content, got %#v", result)
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return text.Text
}

func assertNoRegisteredScans(t *testing.T, registry *scanRegistry) {
	t.Helper()
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if len(registry.scans) != 0 {
		t.Fatalf("expected no registered scans, got %d", len(registry.scans))
	}
}

func TestCountLines(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{"Empty file", "", 0},
		{"Single word no newline", "hello", 1},
		{"Single word with newline", "hello\n", 1},
		{"Multiple lines trailing newline", "hello\nworld\n", 2},
		{"Multiple lines no trailing newline", "hello\nworld", 2},
		{"Extremely long line exceeding 64KB", strings.Repeat("A", 70000) + "\n" + "secondline", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, strings.ReplaceAll(tt.name, " ", "_")+".txt")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write file: %v", err)
			}
			got, err := countLines(path)
			if err != nil {
				t.Fatalf("countLines returned error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("countLines() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestScanRegistryCleanup(t *testing.T) {
	registry := newScanRegistry()

	now := time.Now()

	// 1. Finished scan, 2 hours old (should be evicted)
	oldScan := &scanState{
		scanID:     "old-scan",
		running:    false,
		finishedAt: now.Add(-2 * time.Hour),
	}
	// 2. Finished scan, 10 minutes old (should be preserved)
	recentScan := &scanState{
		scanID:     "recent-scan",
		running:    false,
		finishedAt: now.Add(-10 * time.Minute),
	}
	// 3. Active scan, started 2 hours ago (should be preserved)
	activeScan := &scanState{
		scanID:    "active-scan",
		running:   true,
		startedAt: now.Add(-2 * time.Hour),
	}

	// Manually register all three scans first (pre-cleanup state)
	registry.scans[oldScan.scanID] = oldScan
	registry.scans[recentScan.scanID] = recentScan
	registry.scans[activeScan.scanID] = activeScan

	// 4. Register a new scan. This should trigger cleanup.
	newScan := &scanState{
		scanID:  "new-scan",
		running: true,
	}
	_, err := registry.register(newScan, 0)
	if err != nil {
		t.Fatalf("register returned unexpected error: %v", err)
	}

	// 5. Verify states
	if _, ok := registry.get("old-scan"); ok {
		t.Error("expected old-scan to be cleaned up, but it exists")
	}
	if _, ok := registry.get("recent-scan"); !ok {
		t.Error("expected recent-scan to be preserved, but it was deleted")
	}
	if _, ok := registry.get("active-scan"); !ok {
		t.Error("expected active-scan to be preserved, but it was deleted")
	}
	if _, ok := registry.get("new-scan"); !ok {
		t.Error("expected new-scan to be registered, but it was not found")
	}
}
