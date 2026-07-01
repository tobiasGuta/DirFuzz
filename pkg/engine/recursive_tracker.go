package engine

import (
	"bufio"
	"dirfuzz/pkg/httpclient"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

type RecursiveTracker interface {
	ProcessHit(job Job, result Result, resp *httpclient.RawResponse, payload string, depth, maxDepth int, wordlistPath string, doRecursivePrune bool) (pruned bool)
	RememberSignature(path string, sig recursiveResponseSignature)
	IsMirror(path string, sig recursiveResponseSignature) bool
	Clear()
}

type engineRecursiveTracker struct {
	e          *Engine
	sem        chan struct{}
	signatures sync.Map
}

func NewRecursiveTracker(e *Engine) RecursiveTracker {
	return &engineRecursiveTracker{
		e:   e,
		sem: make(chan struct{}, MaxConcurrentRecursions),
	}
}

func (t *engineRecursiveTracker) ProcessHit(job Job, result Result, resp *httpclient.RawResponse, payload string, depth, maxDepth int, wordlistPath string, doRecursivePrune bool) (pruned bool) {
	if doRecursivePrune {
		if prune, reason := shouldPruneRecursiveBranch(payload, result.ContentType, resp.Body); prune {
			t.e.emitLogEvent(LogLevelInfo, LogCategoryDiscovery, EventRecursivePruned, "recursive branch pruned", map[string]interface{}{
				"path":   payload,
				"reason": reason,
			})
			return true
		}
	}

	inScope := true
	if result.Redirect != "" {
		if parsedRedir, err := url.Parse(result.Redirect); err == nil && parsedRedir.Host != "" {
			t.e.targetLock.RLock()
			scopeDom := t.e.scopeDomain
			t.e.targetLock.RUnlock()
			redirHost := parsedRedir.Hostname()
			if redirHost != scopeDom && !strings.HasSuffix(redirHost, "."+scopeDom) {
				inScope = false
			}
		}
	}

	if inScope {
		go func(runID int64, basePath string, nextDepth int, wlPath string) {
			if t.e.checkRecursiveWildcard(basePath) {
				return
			}

			select {
			case t.sem <- struct{}{}:
				t.e.AddScanner()
				go func(runID int64, basePath string, nextDepth int, wlPath string) {
					defer t.e.scannerWg.Done()
					defer func() { <-t.sem }()

					snap := t.e.configSnap.Load()
					if snap == nil {
						return
					}

					f, err := os.Open(wlPath)
					if err != nil {
						return
					}
					defer f.Close()

					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						word := scanner.Text()
						if word == "" {
							continue
						}
						newPath := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(word, "/")
						if pathExcludedByRegexps(newPath, snap.ExcludePathRegexps) {
							continue
						}
						for _, method := range resolveMethodsForPath(newPath, snap.Methods, snap.SmartAPI) {
							atomic.AddInt64(&t.e.TotalLines, 1)
							t.e.Submit(Job{Path: newPath, Depth: nextDepth, Method: method, RunID: runID})
						}
					}
				}(runID, basePath, nextDepth, wlPath)
			default:
			}
		}(job.RunID, payload, depth+1, wordlistPath)
	}
	return false
}

func (t *engineRecursiveTracker) Clear() {
	t.signatures = sync.Map{}
}
