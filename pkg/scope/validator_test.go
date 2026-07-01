package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name            string
		assets          []Asset
		target          string
		expectedAllowed bool
		reasonContains  string
	}{
		{
			name:            "Direct URL match",
			assets:          []Asset{{AssetIdentifier: "api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "api.example.com",
			expectedAllowed: true,
			reasonContains:  "matched URL api.example.com",
		},
		{
			name:            "Direct URL match with explicit port",
			assets:          []Asset{{AssetIdentifier: "api.example.com:8443", AssetType: "URL", EligibleForBounty: true}},
			target:          "https://api.example.com:8443/internal",
			expectedAllowed: true,
			reasonContains:  "matched URL api.example.com:8443",
		},
		{
			name:            "Direct URL mismatch on port",
			assets:          []Asset{{AssetIdentifier: "api.example.com:8443", AssetType: "URL", EligibleForBounty: true}},
			target:          "https://api.example.com:443/internal",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "Asset scheme https implies port 443 only",
			assets:          []Asset{{AssetIdentifier: "https://api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "https://api.example.com",
			expectedAllowed: true,
			reasonContains:  "matched URL api.example.com:443",
		},
		{
			name:            "Asset scheme https rejects other ports",
			assets:          []Asset{{AssetIdentifier: "https://api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "http://api.example.com:8080",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "Asset scheme http implies port 80 only",
			assets:          []Asset{{AssetIdentifier: "http://api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "http://api.example.com",
			expectedAllowed: true,
			reasonContains:  "matched URL api.example.com:80",
		},
		{
			name:            "Asset scheme http rejects other ports",
			assets:          []Asset{{AssetIdentifier: "http://api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "https://api.example.com:8443",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "Subdomain wildcard match",
			assets:          []Asset{{AssetIdentifier: "*.example.com", AssetType: "WILDCARD", EligibleForBounty: true}},
			target:          "test.example.com",
			expectedAllowed: true,
			reasonContains:  "matched wildcard *.example.com",
		},
		{
			name:            "Wildcard with explicit port",
			assets:          []Asset{{AssetIdentifier: "*.secure.example.com:8443", AssetType: "WILDCARD", EligibleForBounty: true}},
			target:          "https://foo.secure.example.com:8443",
			expectedAllowed: true,
			reasonContains:  "matched wildcard *.secure.example.com:8443",
		},
		{
			name:            "Multi-level subdomain wildcard match",
			assets:          []Asset{{AssetIdentifier: "*.example.com", AssetType: "WILDCARD", EligibleForBounty: true}},
			target:          "a.b.c.example.com",
			expectedAllowed: true,
			reasonContains:  "matched wildcard *.example.com",
		},
		{
			name:            "Apex domain no match",
			assets:          []Asset{{AssetIdentifier: "*.example.com", AssetType: "WILDCARD", EligibleForBounty: true}},
			target:          "example.com",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "CIDR match",
			assets:          []Asset{{AssetIdentifier: "10.0.0.0/8", AssetType: "CIDR", EligibleForBounty: true}},
			target:          "10.0.0.1",
			expectedAllowed: true,
			reasonContains:  "matched CIDR 10.0.0.0/8",
		},
		{
			name:            "CIDR mismatch",
			assets:          []Asset{{AssetIdentifier: "10.0.0.0/8", AssetType: "CIDR", EligibleForBounty: true}},
			target:          "11.1.0.1",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "Scheme rejection",
			assets:          []Asset{{AssetIdentifier: "api.example.com", AssetType: "URL", EligibleForBounty: true}},
			target:          "javascript:alert(1)//api.example.com",
			expectedAllowed: false,
			reasonContains:  "not a valid http(s) URL or hostname",
		},
		{
			name:            "Passthrough source code",
			assets:          []Asset{{AssetIdentifier: "src/", AssetType: "SOURCE_CODE", EligibleForBounty: true}},
			target:          "src.example.com",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "Passthrough executable",
			assets:          []Asset{{AssetIdentifier: "app.bin", AssetType: "EXECUTABLE", EligibleForBounty: true}},
			target:          "bin.example.com",
			expectedAllowed: false,
			reasonContains:  "matched no in-scope asset",
		},
		{
			name:            "No assets loaded",
			assets:          nil,
			target:          "example.com",
			expectedAllowed: false,
			reasonContains:  "no scope files loaded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllowed, gotReason := IsAllowed(tt.target, tt.assets)
			if gotAllowed != tt.expectedAllowed {
				t.Fatalf("IsAllowed() allowed = %v, want %v", gotAllowed, tt.expectedAllowed)
			}
			if !strings.Contains(gotReason, tt.reasonContains) {
				t.Fatalf("IsAllowed() reason = %q, want substring %q", gotReason, tt.reasonContains)
			}
		})
	}
}

func TestLoadDirError(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(validPath, []byte(`[{"asset_type":"URL","asset_identifier":"api.example.com","eligible_for_bounty":true}]`), 0o600); err != nil {
		t.Fatalf("write valid scope file: %v", err)
	}

	// 1. Verify we can load when all files are valid
	assets, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() unexpected error = %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("LoadDir() assets = %d, want 1", len(assets))
	}

	// 2. Add a malformed file
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`not-json`), 0o600); err != nil {
		t.Fatalf("write malformed scope file: %v", err)
	}

	// 3. Verify LoadDir fails fast with an error
	_, err = LoadDir(dir)
	if err == nil {
		t.Fatalf("LoadDir() expected error on malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing constraint violation") {
		t.Fatalf("LoadDir() error message %q does not mention parsing constraint violation", err.Error())
	}
}

func TestScopeEngine(t *testing.T) {
	assets := []Asset{
		{AssetIdentifier: "api.example.com", AssetType: "URL", EligibleForBounty: true},
		{AssetIdentifier: "secure.example.com:8443", AssetType: "URL", EligibleForBounty: true},
	}

	engine := CompileAssets(assets)

	tests := []struct {
		target          string
		expectedAllowed bool
	}{
		// 1. Matches any port since asset "api.example.com" has no scheme/port
		{target: "https://api.example.com", expectedAllowed: true},
		{target: "http://api.example.com:8080", expectedAllowed: true},
		// 2. Matches only explicit port 8443
		{target: "https://secure.example.com:8443", expectedAllowed: true},
		{target: "https://secure.example.com:443", expectedAllowed: false},
		{target: "http://secure.example.com:80", expectedAllowed: false},
	}

	for _, tt := range tests {
		allowed, _ := engine.IsAllowed(tt.target)
		if allowed != tt.expectedAllowed {
			t.Errorf("ScopeEngine.IsAllowed(%q) = %v, want %v", tt.target, allowed, tt.expectedAllowed)
		}
	}
}
