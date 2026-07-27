package engine

import (
	"bufio"
	"context"
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
		sc := t.e.scannerCtx.Load()
		if sc == nil {
			return false
		}

		// Reserve active work while the parent job is still counted. This keeps
		// Wait correct even if its initial scanner wait completed just before
		// this worker discovered the recursive branch.
		t.e.activeJobs.Add(1)

		// Register before launching so scanner cancellation and wordlist changes
		// wait for the complete task, including its wildcard probe.
		t.e.AddScanner()
		go t.scanBranch(sc.ctx, job.RunID, payload, depth+1, wordlistPath)
	}
	return false
}

func (t *engineRecursiveTracker) scanBranch(ctx context.Context, runID int64, basePath string, nextDepth int, wordlistPath string) {
	defer t.e.scannerWg.Done()
	defer t.e.activeJobs.Done()

	// Admission covers both the wildcard probe and wordlist enumeration.
	// A busy recursion pool delays work instead of silently discarding it.
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return
	}

	if t.e.checkRecursiveWildcard(ctx, basePath) {
		return
	}

	snap := t.e.configSnap.Load()
	if snap == nil {
		return
	}

	f, err := os.Open(wordlistPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		word := strings.TrimRight(scanner.Text(), "\r")
		if word == "" {
			continue
		}

		paths := wordlistPathVariants(basePath, word, snap.Extensions)
		methods := resolveMethodsForPath(paths[0], snap.Methods, snap.SmartAPI)
		for _, method := range methods {
			for _, path := range paths {
				if pathExcludedByRegexps(path, snap.ExcludePathRegexps) {
					continue
				}
				atomic.AddInt64(&t.e.TotalLines, 1)
				t.e.Submit(Job{Path: path, Depth: nextDepth, Method: method, RunID: runID})
			}
		}
	}
}

func (t *engineRecursiveTracker) Clear() {
	t.signatures = sync.Map{}
}
