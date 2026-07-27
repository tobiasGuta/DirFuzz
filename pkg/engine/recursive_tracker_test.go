package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"dirfuzz/pkg/httpclient"

	"golang.org/x/time/rate"
)

func TestWordlistPathVariantsSharedByRootAndRecursiveScans(t *testing.T) {
	extensions := []string{"php", " .bak ", ""}

	if got, want := wordlistPathVariants("", "users", extensions), []string{"users", "users.php", "users.bak"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root variants = %v, want %v", got, want)
	}
	if got, want := wordlistPathVariants("/admin/", "/users", extensions), []string{"/admin/users", "/admin/users.php", "/admin/users.bak"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recursive variants = %v, want %v", got, want)
	}
}

func TestCheckRecursiveWildcardUsesPerHostLimiter(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
	if !limiter.Allow() {
		t.Fatal("failed to consume limiter's initial token")
	}
	eng.limitersLock.Lock()
	eng.limiters[parsed.Host] = limiter
	eng.limitersLock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if !eng.checkRecursiveWildcard(ctx, "/admin") {
		t.Fatal("expected a cancelled limiter wait to fail closed")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("wildcard probe bypassed the per-host limiter and sent %d request(s)", got)
	}
}

func TestRecursiveBranchWaitsForCapacityTracksWholeTaskAndUsesExtensions(t *testing.T) {
	var wildcardRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wildcardRequests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	wordlistPath := t.TempDir() + "/recursive.txt"
	if err := os.WriteFile(wordlistPath, []byte("child\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Extensions = []string{"php", ".bak"}
	eng.Config.Methods = []string{http.MethodGet}
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		eng.Shutdown()
		t.Fatalf("SetTarget() failed: %v", err)
	}

	tracker := &engineRecursiveTracker{
		e:   eng,
		sem: make(chan struct{}, 1),
	}
	tracker.sem <- struct{}{} // occupy the sole recursion slot

	tracker.ProcessHit(
		Job{RunID: atomic.LoadInt64(&eng.RunID)},
		Result{},
		&httpclient.RawResponse{},
		"/parent",
		0,
		2,
		wordlistPath,
		false,
	)

	scannerDone := make(chan struct{})
	go func() {
		eng.scannerWg.Wait()
		close(scannerDone)
	}()

	time.Sleep(50 * time.Millisecond)
	if got := wildcardRequests.Load(); got != 0 {
		t.Errorf("wildcard probe ran before recursion admission: got %d request(s)", got)
	}
	select {
	case <-scannerDone:
		t.Error("scanner tracking completed while the recursive task was still waiting for capacity")
	default:
	}

	<-tracker.sem // release capacity; the branch must continue instead of dropping

	select {
	case <-scannerDone:
	case <-time.After(2 * time.Second):
		if sc := eng.scannerCtx.Load(); sc != nil {
			sc.cancel()
		}
		<-scannerDone
		t.Error("recursive task did not finish after capacity became available")
	}

	var paths []string
	for eng.jobs.Len() > 0 {
		job, ok, err := eng.jobs.Pop(context.Background())
		if err != nil || !ok {
			t.Fatalf("jobs.Pop() = ok %v, err %v", ok, err)
		}
		paths = append(paths, job.Path)
		eng.activeJobs.Done()
	}
	sort.Strings(paths)
	want := []string{"/parent/child", "/parent/child.bak", "/parent/child.php"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("recursive paths = %v, want %v", paths, want)
	}
	if got := wildcardRequests.Load(); got != 1 {
		t.Errorf("wildcard requests = %d, want 1", got)
	}

	eng.Shutdown()
}
