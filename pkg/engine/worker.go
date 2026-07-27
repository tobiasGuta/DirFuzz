package engine

import (
	"context"
	"crypto/tls"
	"dirfuzz/pkg/httpclient"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

func (e *Engine) cleanupJob(shouldExit bool) bool {
	e.activeJobs.Done()
	return shouldExit
}

// invokeOnFindingHook calls the match plugin's optional on_finding(result) hook.
// Returns (dropped, labels, confidence). Dropped indicates the plugin requested
// handleResultWithContext attempts to send the result to the results channel.
// Returns true if the context was cancelled before the result could be emitted
// (caller should exit).
func (e *Engine) handleResultWithContext(ctx context.Context, res Result) bool {

	e.SubmitToNuclei(res.URL)
	e.processFeedbackLoop(res)

	select {
	case e.Results <- res:
		e.resultsCollected.Add(1)
		return false
	case <-ctx.Done():
		return true
	}
}

// handleResultNonBlocking attempts a non-blocking send.
// If the results channel is full the result is dropped and TUIDropped is incremented.
func (e *Engine) handleResultNonBlocking(res Result) {

	e.SubmitToNuclei(res.URL)
	e.processFeedbackLoop(res)

	select {
	case e.Results <- res:
		e.resultsCollected.Add(1)
	default:
		atomic.AddInt64(&e.TUIDropped, 1)
	}
}

func (e *Engine) processFeedbackLoop(res Result) {
	if res.DiscoveryNodeID == "" || e.DiscoveryGraph == nil || e.EvidenceExtractor == nil {
		return
	}

	ev := e.EvidenceExtractor.Extract(res)
	actions := e.DiscoveryGraph.UpdateEvidence(res.DiscoveryNodeID, ev)
	if len(actions) == 0 {
		return
	}

	runID := atomic.LoadInt64(&e.RunID)
	jobs := make([]Job, 0, len(actions))
	e.DiscoveryGraph.RLock()
	for _, a := range actions {
		node, ok := e.DiscoveryGraph.Nodes[a.NodeID]
		if !ok {
			continue
		}

		jobs = append(jobs, Job{
			Type:            JobType(a.Type),
			Path:            node.CanonicalPath,
			RunID:           runID,
			DiscoveryNodeID: a.NodeID,
			PriorityScore:   a.Priority,
			Reason:          ReasonFeedback,
			CreatedAt:       time.Now().UTC(),
		})
	}
	e.DiscoveryGraph.RUnlock()

	for _, job := range jobs {
		e.Submit(job)
	}
}

// verbTamperHeaders returns method-override headers for non-GET/HEAD methods.
// GET and HEAD are excluded by design since overriding to those verbs has no
// access-control relevance.
func verbTamperHeaders(method string) map[string]string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		return nil
	}
	return map[string]string{
		"X-HTTP-Method-Override": method,
		"X-Forwarded-Method":     method,
		"X-Method-Override":      method,
	}
}

func (e *Engine) worker(id int, ctx context.Context, control *workerControl) {
	defer func() {
		control.cancel()
		e.workerLock.Lock()
		if e.workerControls[id] == control {
			delete(e.workerControls, id)
		}
		e.workerLock.Unlock()
		e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStopped, fmt.Sprintf("worker %d stopped", id), map[string]interface{}{"worker_id": id})
		e.activeWorkers.Add(-1)
		e.wg.Done()
	}()

	for {
		job, ok, popErr := e.jobs.Pop(ctx)
		if popErr != nil || !ok {
			return
		}

		if job.RunID != atomic.LoadInt64(&e.RunID) {
			e.activeJobs.Done()
			continue
		}

		// Load immutable snapshot for this job (cheap atomic pointer load).
		snap := e.configSnap.Load()
		if snap == nil {
			// Lazily initialize if not present.
			e.buildAndStoreConfigSnapshot()
			snap = e.configSnap.Load()
			if snap == nil {
				// Fallback to original locking behavior if snapshot still missing.
				e.Config.RLock()
				local := &configSnapshot{
					MaxWorkers:           e.Config.MaxWorkers,
					IsPaused:             e.Config.IsPaused,
					UserAgent:            e.Config.UserAgent,
					Headers:              make(map[string]string, len(e.Config.Headers)),
					MatchCodes:           make(map[int]bool, len(e.Config.MatchCodes)),
					FilterSizes:          make(map[int]bool, len(e.Config.FilterSizes)),
					FilterSizeRanges:     make([]SizeRange, len(e.Config.FilterSizeRanges)),
					MatchContentTypes:    make([]string, len(e.Config.MatchContentTypes)),
					FilterContentTypes:   make([]string, len(e.Config.FilterContentTypes)),
					FollowRedirects:      e.Config.FollowRedirects,
					MaxRedirects:         e.Config.MaxRedirects,
					RequestBody:          e.Config.RequestBody,
					FilterWords:          e.Config.FilterWords,
					FilterLines:          e.Config.FilterLines,
					MatchWords:           e.Config.MatchWords,
					MatchLines:           e.Config.MatchLines,
					FilterRTMin:          e.Config.FilterRTMin,
					FilterRTMax:          e.Config.FilterRTMax,
					ProxyOut:             e.Config.ProxyOut,
					Timeout:              e.Config.Timeout,
					SaveRaw:              e.Config.SaveRaw,
					AutoFilterThreshold:  e.Config.AutoFilterThreshold,
					SimhashThreshold:     e.Config.SimhashThreshold,
					SimhashClusterLimit:  e.Config.SimhashClusterLimit,
					H2Mode:               e.Config.H2Mode,
					H2ConcurrentStreams:  e.Config.H2ConcurrentStreams,
					TimingOracle:         e.Config.TimingOracle,
					TimeOracleK:          e.Config.TimeOracleK,
					TimeOracleN:          e.Config.TimeOracleN,
					TimeTrim:             e.Config.TimeTrim,
					Harvest:              e.Config.Harvest,
					HarvestJS:            e.Config.HarvestJS,
					HarvestAPI:           e.Config.HarvestAPI,
					HarvestResponse:      e.Config.HarvestResponse,
					HarvestResponseDepth: e.Config.HarvestResponseDepth,
					HarvestResponseFetch: e.Config.HarvestResponseFetch,
					HarvestSourceMaps:    e.Config.HarvestSourceMaps,
					ParamWordlist:        append([]string(nil), e.Config.ParamWordlist...),
					EvasionLimit:         e.Config.EvasionLimit,
					Mutate:               e.Config.Mutate,
					Recursive:            e.Config.Recursive,
					RecursivePrune:       e.Config.RecursivePrune,
					MaxDepth:             e.Config.MaxDepth,
					WordlistPath:         e.Config.WordlistPath,
					WAFEvasion:           e.Config.WAFEvasion,
					VerbTamper:           e.Config.VerbTamper,
					FourOhThreeBypass:    e.Config.FourOhThreeBypass,
					Spidering:            e.Config.Spidering,
					AuthMatrix:           make(map[string][]string, len(e.Config.AuthMatrix)),
				}
				ua := local.UserAgent
				for k, v := range e.Config.Headers {
					if strings.EqualFold(k, "User-Agent") {
						ua = normalizeUserAgent(v)
						continue
					}
					local.Headers[k] = v
				}
				local.UserAgent = ua
				for k, v := range e.Config.MatchCodes {
					local.MatchCodes[k] = v
				}
				for k, v := range e.Config.FilterSizes {
					local.FilterSizes[k] = v
				}
				copy(local.FilterSizeRanges, e.Config.FilterSizeRanges)
				copy(local.MatchContentTypes, e.Config.MatchContentTypes)
				copy(local.FilterContentTypes, e.Config.FilterContentTypes)
				for role, hdrs := range e.Config.AuthMatrix {
					local.AuthMatrix[role] = append([]string(nil), hdrs...)
				}
				e.Config.RUnlock()
				snap = local
			}
		}
		// Copy snapshot values into local variables used below.
		paused := snap.IsPaused
		ua := snap.UserAgent
		headers := snap.Headers
		matchCodes := snap.MatchCodes
		filterSizes := snap.FilterSizes
		filterSizeRanges := snap.FilterSizeRanges
		matchContentTypes := snap.MatchContentTypes
		filterContentTypes := snap.FilterContentTypes
		followRedirects := snap.FollowRedirects
		maxRedirects := snap.MaxRedirects
		requestBody := snap.RequestBody
		filterWords := snap.FilterWords
		filterLines := snap.FilterLines
		matchWords := snap.MatchWords
		matchLines := snap.MatchLines
		filterRTMin := snap.FilterRTMin
		filterRTMax := snap.FilterRTMax
		proxyOut := snap.ProxyOut
		requestTimeout := snap.Timeout
		if requestTimeout <= 0 {
			requestTimeout = DefaultHTTPTimeout
		}
		saveRaw := snap.SaveRaw
		authMatrix := snap.AuthMatrix
		autoFilterThreshold := snap.AutoFilterThreshold
		doMutate := snap.Mutate
		doRecurse := snap.Recursive
		doRecursivePrune := snap.RecursivePrune
		maxDepth := snap.MaxDepth
		wordlistPath := snap.WordlistPath
		wafEvasion := snap.WAFEvasion
		verbTamper := snap.VerbTamper
		spidering := snap.Spidering
		harvestSourceMaps := snap.HarvestSourceMaps

		shouldExit := id >= snap.MaxWorkers

		sc := e.scannerCtx.Load()
		if sc == nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}
		localCtx := sc.ctx

		// Pause loop — re-check the immutable snapshot to avoid frequent
		// locking on the hot path. Fall back to the config lock if the
		// snapshot is temporarily unavailable.
		for paused {
			select {
			case <-localCtx.Done():
				e.activeJobs.Done()
				return
			case <-time.After(100 * time.Millisecond):
			}
			if s := e.configSnap.Load(); s != nil {
				paused = s.IsPaused
			} else {
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()
			}
		}

		payload := job.Path
		depth := job.Depth

		e.targetLock.RLock()
		currentBaseURL := e.baseURL
		e.targetLock.RUnlock()

		// Build full URL. If the body contains a payload placeholder and
		// the target URL does not, keep the URL fixed and fuzz only the body.
		fullURL := fullURLForPayload(currentBaseURL, payload, requestBody)

		parsedURL, errURL := url.Parse(fullURL)
		if errURL != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		reqHost := parsedURL.Host
		reqHostname := parsedURL.Hostname()

		// Per-host rate limiter.
		limiter := e.getLimiter(reqHost)
		waitStart := time.Now()
		if err := limiter.Wait(localCtx); err != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		} else if waited := time.Since(waitStart); waited > time.Millisecond {
			e.emitLogEvent(LogLevelInfo, LogCategoryNetwork, EventRateLimitHit, fmt.Sprintf("rate limiter delayed request by %s", waited.Round(time.Millisecond)), map[string]interface{}{
				"host":    reqHost,
				"wait_ms": waited.Milliseconds(),
				"path":    job.Path,
				"method":  job.Method,
				"run_id":  job.RunID,
			})
		}

		reqPath := parsedURL.Path
		if parsedURL.RawQuery != "" {
			reqPath += "?" + parsedURL.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		// Inject payload into User-Agent.
		ua = normalizeUserAgent(strings.ReplaceAll(ua, "{PAYLOAD}", payload))
		if ua == "" {
			ua = "DirFuzz/2.0"
		}

		var reqHeaders map[string]string
		var headersStr string
		headerSafePayload := sanitizeHeaderToken(payload)

		if len(job.ExtraHeaders) == 0 && !verbTamper && !strings.Contains(snap.HeadersTemplate, "{PAYLOAD}") {
			// Fast path: zero allocation for headers block
			reqHeaders = headers // read-only reference
			headersStr = snap.HeadersTemplate
		} else {
			// Merge base + per-job headers into a local map, then render once.
			// Keep user-provided header precedence by only adding auto verb
			// tamper headers when they are not already present.
			reqHeaders = make(map[string]string, len(headers)+len(job.ExtraHeaders)+3)
			for k, v := range headers {
				reqHeaders[k] = v
			}
			for k, v := range job.ExtraHeaders {
				reqHeaders[k] = v
			}
			if verbTamper {
				if overrideHdrs := verbTamperHeaders(job.Method); overrideHdrs != nil {
					for k, v := range overrideHdrs {
						if _, exists := reqHeaders[k]; !exists {
							reqHeaders[k] = v
						}
					}
				}
			}

			for k, v := range reqHeaders {
				reqHeaders[k] = strings.ReplaceAll(v, "{PAYLOAD}", headerSafePayload)
			}

			var reqHdrKeys []string
			for k := range reqHeaders {
				reqHdrKeys = append(reqHdrKeys, k)
			}
			sort.Strings(reqHdrKeys)
			var headersBuilder strings.Builder
			for _, k := range reqHdrKeys {
				safeK := sanitizeHeaderToken(k)
				safeV := sanitizeHeaderToken(reqHeaders[k])
				headersBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", safeK, safeV))
			}
			headersStr = headersBuilder.String()
		}
		headers = reqHeaders

		var pluginBody string
		if requestBody != "" {
			pluginBody = strings.ReplaceAll(requestBody, "{PAYLOAD}", payload)
		}
		pluginMethod := job.Method
		if pluginMethod == "" {
			pluginMethod = "GET"
		}

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		// ── Execute request ────────────────────────────────────────────────
		var resp *httpclient.RawResponse
		var err error
		var successfulMethod string
		var rawRequest []byte
		var authFinding *AuthMatrixFinding
		var bodyContent string
		var timingMedian time.Duration
		var timingOracleHit bool
		var timingOracleZ float64
		var samples []time.Duration
		var oracleErr error
		var allAuthRoles []authMatrixRoleResponse
		oracleEnabled := snap.TimingOracle && e.timingOracle != nil

		if len(authMatrix) > 0 {
			successfulMethod = job.Method
			if successfulMethod == "" {
				successfulMethod = "GET"
			}
			resp, rawRequest, successfulMethod, authFinding, allAuthRoles, err = e.executeAuthMatrixRequests(
				localCtx,
				currentBaseURL,
				reqPath,
				reqHost,
				ua,
				successfulMethod,
				reqHeaders,
				requestTimeout,
				proxyAddr,
				authMatrix,
			)
			atomic.AddInt64(&e.ProcessedLines, 1)
		} else {
			if job.Method == "" {
				bodyFilterActive := e.matchRe.Load() != nil || e.filterRe.Load() != nil ||
					filterWords >= 0 || filterLines >= 0 || matchWords >= 0 || matchLines >= 0 ||
					len(matchContentTypes) > 0 || len(filterContentTypes) > 0

				if bodyFilterActive || e.isHeadRejected(reqHost) || followRedirects || oracleEnabled {
					successfulMethod = "GET"
					rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, pluginBody)
				} else {
					successfulMethod = "HEAD"
					rawRequest = buildRequest("HEAD", reqPath, reqHost, ua, headersStr, pluginBody)
				}

				if oracleEnabled {
					resp, samples, oracleErr = e.executeTimingOracleRequests(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
					if oracleErr != nil {
						err = oracleErr
					} else if e.timingOracle != nil {
						timingMedian = e.timingOracle.Median(samples)
						timingOracleHit = e.timingOracle.IsAnomaly(timingMedian)
						timingOracleZ = e.timingOracle.ZScore(timingMedian)
					}
				} else {
					resp, err = e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
					if err == nil && successfulMethod == "HEAD" && (resp.StatusCode == 405 || resp.StatusCode == 501) {
						e.markHeadRejected(reqHost)
						successfulMethod = "GET"
						rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, pluginBody)
						if fbResp, fbErr := e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr); fbErr == nil {
							resp = fbResp
						} else {
							successfulMethod = "HEAD"
						}
					}
				}
				atomic.AddInt64(&e.ProcessedLines, 1)
			} else {
				successfulMethod = job.Method
				bodyContent = ""
				var methodHdrBuf strings.Builder
				methodHdrBuf.WriteString(headersStr)

				hasContentType := false
				for k := range headers {
					if strings.EqualFold(k, "Content-Type") {
						hasContentType = true
						break
					}
				}

				bodyContent = pluginBody
				if bodyContent != "" && (job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH") {
					methodHdrBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(bodyContent)))
					if !hasContentType {
						methodHdrBuf.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
					}
				} else if job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH" || job.Method == "DELETE" {
					methodHdrBuf.WriteString("Content-Length: 0\r\n")
				}
				rawRequest = buildRequest(job.Method, reqPath, reqHost, ua, methodHdrBuf.String(), bodyContent)
				if oracleEnabled {
					resp, samples, oracleErr = e.executeTimingOracleRequests(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
					if oracleErr != nil {
						err = oracleErr
					} else if e.timingOracle != nil {
						timingMedian = e.timingOracle.Median(samples)
						timingOracleHit = e.timingOracle.IsAnomaly(timingMedian)
						timingOracleZ = e.timingOracle.ZScore(timingMedian)
					}
				} else {
					resp, err = e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
				}
				atomic.AddInt64(&e.ProcessedLines, 1)
			}
		}

		if err != nil {
			if !isContextDoneError(localCtx, err) {
				atomic.AddInt64(&e.CountConnErr, 1)
			}
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// Follow redirects.
		var finalRedirectURL string
		if followRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp, finalRedirectURL = e.followRedirectChain(localCtx, resp, fullURL, reqHost, ua, headers, maxRedirects, proxyAddr, requestTimeout)
		}

		// Update stats counters.
		switch {
		case resp.StatusCode == 200:
			atomic.AddInt64(&e.Count200, 1)
		case resp.StatusCode == 403:
			atomic.AddInt64(&e.Count403, 1)
		case resp.StatusCode == 404:
			atomic.AddInt64(&e.Count404, 1)
		case resp.StatusCode == 429:
			atomic.AddInt64(&e.Count429, 1)
			e.autoThrottleCheck()
		case resp.StatusCode >= 500:
			atomic.AddInt64(&e.Count500, 1)
		}

		bodySize, wordCount, lineCount, contentType, bodyHash := computeResponseMetrics(resp, successfulMethod)

		// ─── Passive Tech Fingerprinting ──────────────────────────────────────────
		// Runs on every 2xx/3xx response. Uses resp.HeaderMap (already allocated by
		// the HTTP client for source-map harvesting) so zero extra allocation cost.
		// Deduplication via detectedTech sync.Map prevents log flooding.
		var detectedTechs []string
		if resp.StatusCode >= 200 && resp.StatusCode < 400 && len(resp.Body) > 0 {
			cookies := parseCookiesFromRawHeaders(resp.Headers)
			detectedTechs = e.fingerprinter.Detect(resp.HeaderMap, cookies, resp.Body)
			for _, tech := range detectedTechs {
				dedupeKey := reqHostname + ":" + tech
				if _, loaded := e.detectedTech.LoadOrStore(dedupeKey, true); !loaded {
					// Emit once per host per scan to the TUI and Monitor
					e.emitLogEvent(LogLevelSuccess, LogCategoryDiscovery, "TechDetected",
						fmt.Sprintf("Identified tech stack %q on %s", tech, reqHostname),
						map[string]interface{}{"host": reqHostname, "tech": tech})
				}
			}
		}
		// [FUTURE] Tech-aware wordlist injection:
		// e.queueTechWordlist(tech) — loads wordlists/spring-boot.txt etc into the scan queue

		skipRTFilters := timingOracleHit

		// Validation is operational work, not a display decision. Schedule it
		// before any status/size/regex/timing/content/SimHash filtering.
		if snap.FourOhThreeBypass && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized) && bodySize >= 0 {
			bypassCtx := context.WithValue(localCtx, bypassBaselineSizeKey{}, bodySize)
			e.schedule403BypassTask(bypassCtx, fullURL, reqPath, successfulMethod, headers, snap)
		}

		// 403 classification.
		forbidden403Type := ""
		var bypassTechniqueLabel string
		if resp.StatusCode == 403 {
			classifyBody := resp.Body
			classifyHeaders := resp.Headers
			if successfulMethod == "HEAD" {
				followupReq := buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
				if followupResp, followupErr := e.executeRequestWithRetry(localCtx, currentBaseURL, followupReq, 3*time.Second, proxyAddr); followupErr == nil {
					classifyBody = followupResp.Body
					classifyHeaders = followupResp.Headers
				}
			}
			forbidden403Type = Classify403(classifyBody, classifyHeaders)

			if wafEvasion {
				detectedWAFVendor := "unknown"
				wafRes := FingerprintWAF(classifyBody, classifyHeaders, resp.StatusCode, int64(resp.Duration.Milliseconds()))
				if wafRes.Detected {
					detectedWAFVendor = wafRes.Vendor
				}
				e.setWAFState(wafRes.Detected, detectedWAFVendor)

				evasionLimit := snap.EvasionLimit
				if evasionLimit < 1 {
					evasionLimit = DefaultEvasionLimit
				}

				techniques := EvasionStrategiesFor(detectedWAFVendor)
				if len(techniques) > 0 && e.EvasionScoreboard != nil {
					tried := 0
					for _, technique := range techniques {
						if tried >= evasionLimit {
							break
						}
						if e.evasionTechniqueSeen(payload, technique.Name) {
							continue
						}
						e.markEvasionTechnique(payload, technique.Name)
						tried++
						e.logWAFBypassAttempt(detectedWAFVendor, technique.Name, payload, tried)

						bypassPath, bypassHeaders := technique.ModifyRequest(payload, headers, successfulMethod)
						reqHeaders := make(map[string]string, len(headers)+len(bypassHeaders)+3)
						for k, v := range headers {
							reqHeaders[k] = v
						}
						for k, v := range bypassHeaders {
							reqHeaders[k] = v
						}
						var reqHdrKeys []string
						for k := range reqHeaders {
							reqHdrKeys = append(reqHdrKeys, k)
						}
						sort.Strings(reqHdrKeys)
						var bypassHdrBuf strings.Builder
						headerSafePayload := sanitizeHeaderToken(payload)
						for _, k := range reqHdrKeys {
							safeK := sanitizeHeaderToken(k)
							safeV := sanitizeHeaderToken(strings.ReplaceAll(reqHeaders[k], "{PAYLOAD}", headerSafePayload))
							bypassHdrBuf.WriteString(fmt.Sprintf("%s: %s\r\n", safeK, safeV))
						}
						bypassReq := buildRequest(successfulMethod, bypassPath, reqHost, ua, bypassHdrBuf.String(), bodyContent)
						bypassResp, bypassErr := e.executeRequestWithRetry(localCtx, currentBaseURL, bypassReq, requestTimeout, proxyAddr)
						if bypassErr != nil {
							e.EvasionScoreboard.Record(technique.Name, false)
							e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, false, 0)
							continue
						}
						if !isMeaningfulBypassResponse(resp, bypassResp) {
							e.EvasionScoreboard.Record(technique.Name, false)
							e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, false, bypassResp.StatusCode)
							continue
						}

						e.EvasionScoreboard.Record(technique.Name, true)
						e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, true, bypassResp.StatusCode)
						resp = bypassResp
						rawRequest = bypassReq
						bodySize, wordCount, lineCount, contentType, bodyHash = computeResponseMetrics(resp, successfulMethod)
						if strings.Contains(currentBaseURL, "{PAYLOAD}") {
							fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", bypassPath, 1)
						} else {
							bypassURLPath := bypassPath
							if !strings.HasPrefix(bypassURLPath, "/") {
								bypassURLPath = "/" + bypassURLPath
							}
							fullURL = strings.TrimRight(currentBaseURL, "/") + bypassURLPath
						}
						bypassTechniqueLabel = "BYPASS:" + technique.Name
						break
					}
				}
			}
			if bypassTechniqueLabel != "" && resp.StatusCode != 403 {
				atomic.AddInt64(&e.Count403, -1)
				switch {
				case resp.StatusCode == 200:
					atomic.AddInt64(&e.Count200, 1)
				case resp.StatusCode == 404:
					atomic.AddInt64(&e.Count404, 1)
				case resp.StatusCode >= 500:
					atomic.AddInt64(&e.Count500, 1)
				}
			}
		}

		// Display filtering happens only after configured validation and inline
		// WAF bypass work have had a chance to inspect the blocked response.
		if !e.applyFilters(resp, successfulMethod, bodySize, wordCount, lineCount, bodyHash, contentType,
			timingOracleHit,
			filterSizes, filterSizeRanges, matchCodes,
			filterWords, filterLines, matchWords, matchLines,
			matchContentTypes, filterContentTypes,
			filterRTMin, filterRTMax,
			skipRTFilters) {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		if harvestSourceMaps && resp.StatusCode >= 200 && resp.StatusCode < 300 && e.shouldHarvestSourceMap(parsedURL.Path, contentType) {
			sourceMapURL := ExtractSourceMapURL(resp.HeaderMap, resp.Body)
			if sourceMapURL != "" {
				baseURL := fullURL
				if finalRedirectURL != "" {
					baseURL = finalRedirectURL
				}
				e.scheduleSourceMapHarvest(localCtx, baseURL, sourceMapURL, snap, job.RunID, job.HarvestDepth+1)
			}
		}

		// Smart Filter.
		if bodySize != -1 && (resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403) {
			fpKey := makeAutoFilterFingerprint(resp.StatusCode, bodySize, contentType, bodyHash, forbidden403Type)

			e.fpMutex.Lock()
			e.fpCounts[fpKey]++
			count := e.fpCounts[fpKey]
			e.fpMutex.Unlock()

			threshold := autoFilterThreshold
			if threshold > 0 && count == threshold {
				e.emitLogEvent(LogLevelSuccess, LogCategoryFilter, EventAutoFilterTriggered, fmt.Sprintf("auto-filter triggered for repetitive response fingerprint at size %d", bodySize), map[string]interface{}{
					"body_size":    bodySize,
					"body_hash":    fmt.Sprintf("%016x", bodyHash),
					"content_type": contentType,
					"status":       resp.StatusCode,
					"count":        count,
					"threshold":    threshold,
				})
				select {
				case e.Results <- Result{
					Path:         "AUTO-FILTER",
					Method:       successfulMethod,
					StatusCode:   resp.StatusCode,
					Size:         bodySize,
					Headers:      map[string]string{"Msg": fmt.Sprintf("Auto-filtered repetitive response fingerprint at size: %d", bodySize)},
					IsAutoFilter: true,
				}:
					e.resultsCollected.Add(1)
				default:
				}
			}
			if threshold > 0 && count >= threshold {
				atomic.AddInt64(&e.AutoFilterSuppressed, 1)
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}
		}

		// Capture interesting headers.
		capturedHeaders := make(map[string]string)
		interesting := map[string]string{
			"server":                      "Server",
			"x-powered-by":                "X-Powered-By",
			"cf-ray":                      "Cf-Ray",
			"content-security-policy":     "Content-Security-Policy",
			"strict-transport-security":   "Strict-Transport-Security",
			"x-frame-options":             "X-Frame-Options",
			"x-content-type-options":      "X-Content-Type-Options",
			"referrer-policy":             "Referrer-Policy",
			"permissions-policy":          "Permissions-Policy",
			"access-control-allow-origin": "Access-Control-Allow-Origin",
		}
		for lowerKey, mappedKey := range interesting {
			if val, ok := resp.HeaderMap[lowerKey]; ok {
				capturedHeaders[mappedKey] = val
			}
		}

		result := Result{
			Path:            payload,
			DiscoveryNodeID: job.DiscoveryNodeID,
			Method:          successfulMethod,
			StatusCode:      resp.StatusCode,
			Size:            bodySize,
			Words:           wordCount,
			Lines:           lineCount,
			ContentType:     contentType,
			Duration:        resp.Duration,
			Headers:         capturedHeaders,
			URL:             fullURL,
		}
		if timingOracleHit {
			result.Duration = timingMedian
		}

		if saveRaw {
			result.Request = string(rawRequest)
			result.Response = string(resp.Raw)
			result.RequestBytes = append([]byte(nil), rawRequest...)
			result.ResponseBytes = append([]byte(nil), resp.Raw...)
		}

		if len(allAuthRoles) > 0 {
			for _, ar := range allAuthRoles {
				if ar.resp == nil {
					continue
				}
				arSize, arWords, arLines, arContentType, _ := computeResponseMetrics(ar.resp, successfulMethod)

				arCapturedHeaders := make(map[string]string)
				for lowerKey, mappedKey := range interesting {
					if val, ok := ar.resp.HeaderMap[lowerKey]; ok {
						arCapturedHeaders[mappedKey] = val
					}
				}

				dt := AuthRoleDetail{
					Role:        ar.role,
					StatusCode:  ar.resp.StatusCode,
					Size:        arSize,
					Words:       arWords,
					Lines:       arLines,
					Duration:    ar.resp.Duration,
					ContentType: arContentType,
					Headers:     arCapturedHeaders,
				}
				if saveRaw {
					dt.Request = string(ar.rawRequest)
					dt.Response = string(ar.resp.Raw)
					dt.RequestBytes = append([]byte(nil), ar.rawRequest...)
					dt.ResponseBytes = append([]byte(nil), ar.resp.Raw...)
				}
				result.AuthRoles = append(result.AuthRoles, dt)
			}
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && !followRedirects {
			result.Redirect = resp.GetHeader("Location")
		}
		if finalRedirectURL != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.Redirect = finalRedirectURL
		}
		if resp.StatusCode == 403 {
			result.Forbidden403Type = forbidden403Type
		}
		if bypassTechniqueLabel != "" {
			result.Labels = append(result.Labels, bypassTechniqueLabel)
		}

		// Append tech detections — immortalizes findings in the immutable Event Ledger
		// Format: "TECH:nginx", "TECH:PHP" etc. Survives time-travel replay natively.
		for _, tech := range detectedTechs {
			result.Labels = append(result.Labels, "TECH:"+tech)
		}

		// Eagle mode compares the current hit against the previous JSONL baseline.
		e.applyEagleDrift(&result, eagleBodyHash(resp.Body))

		if timingOracleHit {
			result.Labels = append(result.Labels, "TIMING-ORACLE")
			oracleConfidence := fmt.Sprintf("z=%.1f", timingOracleZ)
			if result.Confidence == "" {
				result.Confidence = oracleConfidence
			} else {
				result.Confidence = result.Confidence + ";" + oracleConfidence
			}
		}

		if authFinding != nil {
			if result.Headers == nil {
				result.Headers = make(map[string]string)
			}
			result.Labels = append(result.Labels, authFinding.Labels...)
			if authFinding.Confidence != "" {
				if result.Confidence == "" {
					result.Confidence = authFinding.Confidence
				} else {
					result.Confidence = result.Confidence + ";" + authFinding.Confidence
				}
			}
			if authFinding.Summary != "" {
				result.Headers["Auth-Matrix"] = authFinding.Summary
			}
		}

		if !strings.EqualFold(successfulMethod, "HEAD") {
			recSig := makeRecursiveResponseSignature(resp.StatusCode, bodySize, wordCount, lineCount, contentType, bodyHash)
			if job.Depth > 0 && e.recursiveTracker.IsMirror(payload, recSig) {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}
			e.recursiveTracker.RememberSignature(payload, recSig)
		}

		paramFuzzURL := fullURL
		if finalRedirectURL != "" {
			paramFuzzURL = finalRedirectURL
		}
		e.queueParamFuzzFromResult(result, paramFuzzURL, bodySize, bodyHash, contentType, resp.Body)
		e.queueResponseHarvestFromResult(job, fullURL, finalRedirectURL, contentType, resp.Body)

		// Spidering / dynamic link extraction
		if spidering && len(resp.Body) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			matches := linkRegex.FindAllStringSubmatch(string(resp.Body), -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				link := strings.TrimSpace(match[1])
				lowerLink := strings.ToLower(link)
				if strings.HasPrefix(lowerLink, "javascript:") || strings.HasPrefix(lowerLink, "mailto:") || strings.HasPrefix(lowerLink, "data:") || strings.HasPrefix(lowerLink, "#") {
					continue
				}

				parsedLink, errL := url.Parse(link)
				if errL != nil {
					continue
				}

				if !isSameSpiderScopeHost(reqHostname, parsedLink) {
					continue
				}

				newPath := parsedLink.Path
				if parsedLink.RawQuery != "" {
					newPath += "?" + parsedLink.RawQuery
				}
				if newPath == "" {
					newPath = "/"
				}

				// Submit will run Bloom filter check
				e.Submit(spiderChildJob(job, newPath))
			}
		}

		if e.handleResultWithContext(localCtx, result) {
			e.activeJobs.Done()
			return
		}

		// Outbound proxy replay via bounded queue.
		if proxyOut != "" {
			select {
			case e.replayCh <- replayTask{
				proxyAddr:   proxyOut,
				fullURL:     fullURL,
				method:      successfulMethod,
				ua:          ua,
				headers:     headers,
				requestBody: requestBody,
				payload:     payload,
			}:
			default:
				// Drop if queue is full — don't block workers.
			}
		}

		// Smart Mutation — applies to ALL paths (not just dotted ones).
		if doMutate && (resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301) {
			mutations := []string{".bak", ".old", ".save", "~", ".swp", ".orig", ".tmp"}
			for _, m := range mutations {
				e.Submit(Job{Path: payload + m, Depth: depth, Method: job.Method, RunID: job.RunID})
			}
		}

		// Recursive scanning with bounded concurrency.
		if doRecurse && depth < maxDepth {
			if pruned := e.recursiveTracker.ProcessHit(job, result, resp, payload, depth, maxDepth, wordlistPath, doRecursivePrune); pruned {
				e.activeJobs.Done()
				if shouldExit {
					return
				}
				continue
			}
		}

		e.activeJobs.Done()
		if shouldExit {
			return
		}
	}
}

// ─── Proxy replay (bounded) ───────────────────────────────────────────────────

// execReplay forwards a hit through an HTTP proxy (e.g. Burp Suite).
func (e *Engine) execReplay(task replayTask) {
	client := e.getReplayClient(task.proxyAddr)
	if client == nil {
		return
	}

	method := task.method
	if method == "" || method == "HEAD" {
		method = "GET"
	}

	var body io.Reader
	if task.requestBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		body = strings.NewReader(strings.ReplaceAll(task.requestBody, "{PAYLOAD}", task.payload))
	}

	req, err := http.NewRequest(method, task.fullURL, body)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", strings.ReplaceAll(task.ua, "{PAYLOAD}", task.payload))
	for k, v := range task.headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{PAYLOAD}", task.payload))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// getReplayClient returns a reusable *http.Client for the given proxy address.
// If the proxy address is invalid or empty this returns nil. Clients are
// cached in a sync.Map to avoid repeatedly allocating transports and to
// enable connection/TLS session reuse with the proxy.
func (e *Engine) getReplayClient(proxyAddr string) *http.Client {
	if proxyAddr == "" {
		return nil
	}
	if v, ok := e.replayClients.Load(proxyAddr); ok {
		return v.(*http.Client)
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil
	}

	e.Config.RLock()
	insecure := e.Config.Insecure
	e.Config.RUnlock()

	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	actual, loaded := e.replayClients.LoadOrStore(proxyAddr, client)
	if loaded {
		// Another goroutine stored a client first; close our idle conns.
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return actual.(*http.Client)
	}
	return client
}

// ─── Job submission ───────────────────────────────────────────────────────────

// Submit adds a payload to the queue if it passes the Bloom filter check.
func (e *Engine) Submit(job Job) {
	if job.RunID != atomic.LoadInt64(&e.RunID) {
		return
	}
	if e.shouldExcludePath(job.Path) {
		return
	}

	filterKey := job.Path
	if job.Method != "" {
		filterKey = job.Method + ":" + job.Path
	}

	if e.shardedFilter.TestAndAddString(filterKey) {
		atomic.AddInt64(&e.ProcessedLines, 1)
		return
	}

	e.activeJobs.Add(1)
	sc := e.scannerCtx.Load()
	if sc == nil {
		e.activeJobs.Done()
		return
	}
	if err := e.jobs.Push(sc.ctx, job); err != nil {
		e.activeJobs.Done()
	}
}

// SubmitHarvestPath adds a harvested path to the active scan and counts it in
// the progress metrics so harvested discoveries show up as part of the run.
func (e *Engine) SubmitHarvestPath(path string, runID int64, harvestDepth int, parentID, sourceType string, evidence DiscoveryEvidence) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if e.shouldExcludePath(path) {
		return
	}

	atomic.AddInt64(&e.TotalLines, 1)
	atomic.AddInt64(&e.HarvestedPaths, 1)

	var nodeID string
	var actions []DiscoveryAction
	if e.DiscoveryGraph != nil {
		nodeID, actions = e.DiscoveryGraph.AddPathNode(parentID, path, path, sourceType, evidence)
	}

	e.Submit(Job{
		Type:            JobTypeDiscovery,
		Path:            path,
		Depth:           0,
		HarvestDepth:    harvestDepth,
		Method:          http.MethodGet,
		RunID:           runID,
		DiscoveryNodeID: nodeID,
	})

	for _, action := range actions {
		e.Submit(Job{
			Type:            JobType(action.Type),
			Path:            path,
			Depth:           0,
			HarvestDepth:    harvestDepth,
			Method:          http.MethodGet,
			RunID:           runID,
			DiscoveryNodeID: nodeID,
			PriorityScore:   action.Priority,
			CreatedAt:       action.CreatedAt,
		})
	}
}

// parseCookiesFromRawHeaders extracts cookie names from raw HTTP response headers
// without relying on net/http parsing which requires a non-nil Request pointer.
// Returns a map of cookie name -> "true" suitable for fingerprint.Detect().
func parseCookiesFromRawHeaders(rawHeaders string) map[string]string {
	cookies := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(rawHeaders, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			parts := strings.SplitN(line[11:], "=", 2)
			if len(parts) == 2 {
				cookies[strings.TrimSpace(parts[0])] = "true"
			}
		}
	}
	return cookies
}
