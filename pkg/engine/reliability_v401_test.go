package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestV401GeneratedHeadersAreEngineOwned(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	eng.AddHeader("Host", "attacker.example")
	eng.AddHeader("Content-Length", "999")
	eng.AddHeader("X-Test", "ok")

	snap := eng.configSnap.Load()
	if snap == nil {
		t.Fatal("expected config snapshot")
	}
	for key := range snap.Headers {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			t.Fatalf("generated header leaked into snapshot: %q", key)
		}
	}
	if got := snap.Headers["X-Test"]; got != "ok" {
		t.Fatalf("X-Test = %q, want ok", got)
	}
}

func TestV401FastHeaderTemplateSanitizesCRLF(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	eng.AddHeader("X-Test\r\nInjected", "value\r\nX-Evil: 1")

	snap := eng.configSnap.Load()
	if snap == nil {
		t.Fatal("expected config snapshot")
	}
	if strings.Count(snap.HeadersTemplate, "\r\n") != 1 {
		t.Fatalf("expected one sanitized header line, got %q", snap.HeadersTemplate)
	}
	if strings.Contains(snap.HeadersTemplate, "\r\nInjected") || strings.Contains(snap.HeadersTemplate, "\r\nX-Evil:") {
		t.Fatalf("header template contains injected header boundary: %q", snap.HeadersTemplate)
	}
}

func TestV401ChangeWordlistConcurrentRestartsComplete(t *testing.T) {
	tmpDir := t.TempDir()
	wordlist := filepath.Join(tmpDir, "wordlist.txt")
	if err := os.WriteFile(wordlist, []byte("test\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	eng := NewEngine(4, 1000, 0.01)
	if err := eng.SetTarget("http://example.com"); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	defer func() {
		eng.submissionMu.Lock()
		eng.restarting = true
		if sc := eng.scannerCtx.Load(); sc != nil && sc.cancel != nil {
			sc.cancel()
		}
		eng.submissionMu.Unlock()
		eng.submissionWg.Wait()
		eng.scannerWg.Wait()
		eng.drainJobs()
		eng.activeJobs.Wait()
		eng.Shutdown()
	}()

	errCh := make(chan error, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 8; j++ {
					if err := eng.ChangeWordlist(wordlist); err != nil {
						errCh <- err
					}
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("concurrent ChangeWordlist calls did not complete")
	}
	close(errCh)
	for err := range errCh {
		t.Fatalf("ChangeWordlist() failed: %v", err)
	}
}

func TestV401ChangeWordlistRejectsDirectory(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	if err := eng.ChangeWordlist(t.TempDir()); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("ChangeWordlist(directory) error = %v, want directory error", err)
	}
}
