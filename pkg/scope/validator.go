// Package scope loads H1-Scope-Watcher JSON files from a directory and
// validates whether a target URL is bounty-eligible before a scan starts.
//
// JSON structure expected in each file:
//
//	[
//	  {"asset_type": "URL",      "asset_identifier": "api.example.com", "eligible_for_bounty": true},
//	  {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",   "eligible_for_bounty": true}
//	]
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Asset is one entry from an H1-Scope-Watcher scope file.
type Asset struct {
	AssetType         string `json:"asset_type"`
	AssetIdentifier   string `json:"asset_identifier"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
}

// LoadDir reads every *.json file inside dir, parses each one as []Asset, and
// returns the combined slice.
// Returns an error if the directory cannot be listed, or if any scope file cannot be read or parsed.
func LoadDir(dir string) ([]Asset, error) {
	pattern := filepath.Join(dir, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("scope: listing %q: %w", dir, err)
	}

	batches := make([][]Asset, 0, len(paths))
	totalSize := 0

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("scope: critical failure reading file %s: %w", p, err)
		}
		var batch []Asset
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("scope: critical parsing constraint violation in file %s: %w", p, err)
		}
		batches = append(batches, batch)
		totalSize += len(batch)
	}

	all := make([]Asset, 0, totalSize)
	for _, batch := range batches {
		all = append(all, batch...)
	}
	return all, nil
}

// ScopeEngine encapsulates parsed assets into optimized lookup structures.
type ScopeEngine struct {
	exactURLs map[string]string // Key: "host:port" or "host:" -> Value: normalized identifier
	wildcards []Asset
	cidrs     []cidrBlock
}

type cidrBlock struct {
	network *net.IPNet
	rawText string
}

// CompileAssets transforms a flat asset slice into a flawless, fast-lookup engine.
func CompileAssets(assets []Asset) *ScopeEngine {
	engine := &ScopeEngine{
		exactURLs: make(map[string]string),
		wildcards: make([]Asset, 0),
		cidrs:     make([]cidrBlock, 0),
	}

	for _, a := range assets {
		if !a.EligibleForBounty {
			continue
		}
		assetType := strings.ToUpper(strings.TrimSpace(a.AssetType))
		switch assetType {
		case "URL":
			host, port := extractAssetEndpoint(a.AssetIdentifier)
			if host != "" {
				// If port is empty, net.JoinHostPort format becomes "host:"
				// which perfectly denotes an implicit/any-port wildcard rule.
				key := net.JoinHostPort(host, port)
				if port == "" {
					key = host + ":"
				}
				engine.exactURLs[key] = normalizeAssetIdentifier(a.AssetIdentifier)
			}
		case "WILDCARD":
			engine.wildcards = append(engine.wildcards, a)
		case "CIDR":
			_, network, err := net.ParseCIDR(strings.TrimSpace(a.AssetIdentifier))
			if err == nil {
				engine.cidrs = append(engine.cidrs, cidrBlock{
					network: network,
					rawText: strings.TrimSpace(a.AssetIdentifier),
				})
			}
		}
	}
	return engine
}

// IsAllowed returns true when target is covered by at least one bounty-eligible
// asset in assets. The check is case-insensitive on hostnames.
//
// Any asset whose eligible_for_bounty is false is silently skipped.
// (Compatibility wrapper delegating to ScopeEngine).
func IsAllowed(target string, assets []Asset) (bool, string) {
	if len(assets) == 0 {
		return false, "no scope files loaded"
	}
	return CompileAssets(assets).IsAllowed(target)
}

// IsAllowed executes a safe-fail verification routing using fallback key logic.
func (se *ScopeEngine) IsAllowed(target string) (bool, string) {
	targetHost, targetPort := extractTargetEndpoint(target)
	targetIP := net.ParseIP(targetHost)
	if targetHost == "" && targetIP == nil {
		return false, fmt.Sprintf("target %q is not a valid http(s) URL or hostname", target)
	}

	// 1. Primary Check: O(1) Exact Host + Resolved Port match (e.g., "api.target.com:443")
	specificKey := net.JoinHostPort(targetHost, targetPort)
	if matchText, found := se.exactURLs[specificKey]; found {
		return true, fmt.Sprintf("matched URL %s", matchText)
	}

	// 2. Fallback Check: O(1) Host + Wildcard Port match (e.g., "api.target.com:")
	// This safely preserves the functionality where an omitted asset port matches ALL target ports.
	wildcardKey := targetHost + ":"
	if matchText, found := se.exactURLs[wildcardKey]; found {
		return true, fmt.Sprintf("matched URL %s", matchText)
	}

	// 3. Optimized Network CIDR Verification
	if targetIP != nil {
		for _, block := range se.cidrs {
			if block.network.Contains(targetIP) {
				return true, fmt.Sprintf("matched CIDR %s", block.rawText)
			}
		}
	}

	// 4. Wildcard Base Domain Iteration
	for _, a := range se.wildcards {
		if matchWildcard(targetHost, targetPort, a.AssetIdentifier) {
			return true, fmt.Sprintf("matched wildcard %s", normalizeAssetIdentifier(a.AssetIdentifier))
		}
	}

	if targetHost != "" {
		return false, fmt.Sprintf("target host %q matched no in-scope asset", targetHost)
	}
	return false, "target matched no in-scope asset"
}

// ── internal helpers ──────────────────────────────────────────────────────────

// extractTargetEndpoint returns the lowercase hostname and the effective port
// for a raw URL string or bare hostname. If a port is omitted, the helper uses
// the default port for http/https when possible.
func extractTargetEndpoint(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if scheme, ok := schemePrefix(raw); ok {
		if scheme != "http" && scheme != "https" {
			return "", ""
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = defaultPortForScheme(strings.ToLower(u.Scheme))
	}
	return host, port
}

// extractAssetEndpoint returns the lowercase hostname and explicit port, if
// present, from a scope asset identifier.
func extractAssetEndpoint(identifier string) (string, string) {
	clean := strings.ToLower(strings.TrimSpace(identifier))
	if clean == "" {
		return "", ""
	}
	if strings.Contains(clean, "://") {
		u, err := url.Parse(clean)
		if err != nil {
			return "", ""
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", ""
		}
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		if port == "" {
			port = defaultPortForScheme(scheme)
		}
		return host, port
	}
	if idx := strings.IndexAny(clean, "/?#"); idx != -1 {
		clean = clean[:idx]
	}
	if strings.HasPrefix(clean, "[") {
		if end := strings.IndexByte(clean, ']'); end != -1 {
			host := clean[1:end]
			remainder := clean[end+1:]
			if strings.HasPrefix(remainder, ":") && isNumeric(remainder[1:]) {
				return host, remainder[1:]
			}
			return host, ""
		}
		return "", ""
	}
	if idx := strings.LastIndexByte(clean, ':'); idx != -1 {
		host := clean[:idx]
		port := clean[idx+1:]
		if host != "" && isNumeric(port) && !strings.Contains(host, ":") {
			return host, port
		}
	}
	return clean, ""
}

func normalizeAssetIdentifier(identifier string) string {
	idHost, idPort := extractAssetEndpoint(identifier)
	if idHost == "" {
		return strings.TrimSpace(identifier)
	}
	if idPort == "" {
		return idHost
	}
	return net.JoinHostPort(idHost, idPort)
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func matchURL(targetHost, targetPort, identifier string) bool {
	idHost, idPort := extractAssetEndpoint(identifier)
	if idHost == "" || targetHost == "" || targetHost != idHost {
		return false
	}
	return portMatches(targetPort, idPort)
}

func matchWildcard(targetHost, targetPort, identifier string) bool {
	idHost, idPort := extractAssetEndpoint(identifier)
	if targetHost == "" || !strings.HasPrefix(idHost, "*.") {
		return false
	}
	baseDomain := idHost[2:]
	if baseDomain == "" {
		return false
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(targetHost, suffix) {
		return false
	}
	if !portMatches(targetPort, idPort) {
		return false
	}
	return len(targetHost) > len(baseDomain)
}

func matchCIDR(targetIP net.IP, identifier string) bool {
	if targetIP == nil {
		return false
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(identifier))
	if err != nil {
		return false
	}
	return network.Contains(targetIP)
}

func portMatches(targetPort, assetPort string) bool {
	if assetPort == "" {
		return true
	}
	return targetPort != "" && targetPort == assetPort
}

func schemePrefix(raw string) (string, bool) {
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 {
		return "", false
	}
	prefix := raw[:idx]
	if !isSchemeName(prefix) {
		return "", false
	}
	if idx+1 >= len(raw) {
		return prefix, true
	}
	next := raw[idx+1]
	if next >= '0' && next <= '9' {
		return "", false
	}
	if next == '[' {
		return "", false
	}
	return prefix, true
}

func isSchemeName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) || isNumericByte(c) || c == '+' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNumericByte(c byte) bool {
	return c >= '0' && c <= '9'
}

// isNumeric returns true when s consists entirely of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
