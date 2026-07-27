package engine

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestResultRawBytesRequireSaveRaw(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("response body"))
	}))
	defer server.Close()

	run := func(t *testing.T, saveRaw bool) Result {
		t.Helper()
		eng := NewEngine(1, 100, 0.01)
		defer eng.Shutdown()
		eng.UpdateConfig(func(c *Config) {
			c.AllowPrivateTargets = true
			c.Methods = []string{http.MethodGet}
			c.SaveRaw = saveRaw
			c.AutoFilterThreshold = 0
			c.SimhashClusterLimit = 0
			c.AuthMatrix = map[string][]string{
				"user": {"Authorization: Bearer test"},
			}
		})
		if err := eng.SetTarget(server.URL); err != nil {
			t.Fatalf("SetTarget() failed: %v", err)
		}
		eng.Start()
		eng.Submit(Job{Path: "/raw", Method: http.MethodGet, RunID: atomic.LoadInt64(&eng.RunID)})
		eng.Wait()

		select {
		case result := <-eng.Results:
			return result
		default:
			t.Fatal("expected a kept result")
			return Result{}
		}
	}

	withoutRaw := run(t, false)
	if withoutRaw.Request != "" || withoutRaw.Response != "" || len(withoutRaw.RequestBytes) != 0 || len(withoutRaw.ResponseBytes) != 0 {
		t.Fatalf("SaveRaw=false retained primary raw data: request=%d response=%d", len(withoutRaw.RequestBytes), len(withoutRaw.ResponseBytes))
	}
	if len(withoutRaw.AuthRoles) != 1 {
		t.Fatalf("auth role count = %d, want 1", len(withoutRaw.AuthRoles))
	}
	if role := withoutRaw.AuthRoles[0]; role.Request != "" || role.Response != "" || len(role.RequestBytes) != 0 || len(role.ResponseBytes) != 0 {
		t.Fatalf("SaveRaw=false retained auth-role raw data: request=%d response=%d", len(role.RequestBytes), len(role.ResponseBytes))
	}

	withRaw := run(t, true)
	if withRaw.Request == "" || withRaw.Response == "" || len(withRaw.RequestBytes) == 0 || len(withRaw.ResponseBytes) == 0 {
		t.Fatal("SaveRaw=true did not retain primary raw data")
	}
	if len(withRaw.AuthRoles) != 1 {
		t.Fatalf("auth role count = %d, want 1", len(withRaw.AuthRoles))
	}
	if role := withRaw.AuthRoles[0]; role.Request == "" || role.Response == "" || len(role.RequestBytes) == 0 || len(role.ResponseBytes) == 0 {
		t.Fatal("SaveRaw=true did not retain auth-role raw data")
	}
}

func TestAntiBotFallbackDefaultsToExplicitOptIn(t *testing.T) {
	if DefaultAntiBotFallback {
		t.Fatal("DefaultAntiBotFallback = true, want explicit opt-in")
	}
	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.Config.RLock()
	enabled := eng.Config.AntiBotFallback
	eng.Config.RUnlock()
	if enabled {
		t.Fatal("new engine enables browser anti-bot fallback by default")
	}
}
