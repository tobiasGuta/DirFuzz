package engine

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// scheduleBuildSnapshot debounces config snapshot rebuilds to prevent high
// GC pressure when applying multiple configuration changes in sequence.
func (e *Engine) scheduleBuildSnapshot() {
	if flag.Lookup("test.v") != nil {
		e.buildAndStoreConfigSnapshot()
		return
	}

	e.configSnapMu.Lock()
	defer e.configSnapMu.Unlock()
	
	if e.configSnapTimer != nil {
		e.configSnapTimer.Stop()
	}
	e.configSnapTimer = time.AfterFunc(10*time.Millisecond, func() {
		e.buildAndStoreConfigSnapshot()
	})
}

// buildAndStoreConfigSnapshot creates an immutable snapshot of the fields
func (e *Engine) buildAndStoreConfigSnapshot() {
	e.Config.RLock()
	s := &configSnapshot{
		MaxWorkers:           e.Config.MaxWorkers,
		IsPaused:             e.Config.IsPaused,
		UserAgent:            e.Config.UserAgent,
		Headers:              make(map[string]string, len(e.Config.Headers)),
		MatchCodes:           make(map[int]bool, len(e.Config.MatchCodes)),
		FilterSizes:          make(map[int]bool, len(e.Config.FilterSizes)),
		ExcludePathRegexps:   make([]*regexp.Regexp, 0, len(e.Config.ExcludePathPatterns)),
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
		AntiBotFallback:      e.Config.AntiBotFallback,
		AuthMatrix:           make(map[string][]string, len(e.Config.AuthMatrix)),
		Methods:              make([]string, len(e.Config.Methods)),
		SmartAPI:             e.Config.SmartAPI,
		Extensions:           make([]string, len(e.Config.Extensions)),
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
		HarvestPassive:       e.Config.HarvestPassive,
		HarvestSourceMaps:    e.Config.HarvestSourceMaps,
		HarvestResponseDepth: e.Config.HarvestResponseDepth,
		HarvestResponseFetch: e.Config.HarvestResponseFetch,
		HarvestOTXKey:        e.Config.HarvestOTXKey,
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
	}
	// Honor User-Agent header override: worker formerly extracted UA from
	// headers if present and removed it from the header map.
	ua := s.UserAgent
	for k, v := range e.Config.Headers {
		if strings.EqualFold(k, "User-Agent") {
			ua = normalizeUserAgent(v)
			continue
		}
		s.Headers[k] = v
	}
	s.UserAgent = ua

	// Pre-build a headers template string so workers don't reconstruct the
	// header block on every job. Use a deterministic key order to keep
	// output stable.
	var hdrKeys []string
	for k := range s.Headers {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	var hb strings.Builder
	for _, k := range hdrKeys {
		v := s.Headers[k]
		hb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	s.HeadersTemplate = hb.String()

	for k, v := range e.Config.MatchCodes {
		s.MatchCodes[k] = v
	}
	for k, v := range e.Config.FilterSizes {
		s.FilterSizes[k] = v
	}
	for _, pattern := range e.Config.ExcludePathPatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if re, err := regexp.Compile(pattern); err == nil {
			s.ExcludePathRegexps = append(s.ExcludePathRegexps, re)
		}
	}
	copy(s.FilterSizeRanges, e.Config.FilterSizeRanges)
	copy(s.MatchContentTypes, e.Config.MatchContentTypes)
	for i, ct := range s.MatchContentTypes {
		s.MatchContentTypes[i] = strings.ToLower(ct)
	}
	copy(s.FilterContentTypes, e.Config.FilterContentTypes)
	for i, ct := range s.FilterContentTypes {
		s.FilterContentTypes[i] = strings.ToLower(ct)
	}
	for role, headers := range e.Config.AuthMatrix {
		s.AuthMatrix[role] = append([]string(nil), headers...)
	}
	copy(s.Methods, e.Config.Methods)
	copy(s.Extensions, e.Config.Extensions)
	s.ParamWordlist = append(s.ParamWordlist, e.Config.ParamWordlist...)
	e.Config.RUnlock()
	e.simhashTracker.Threshold = s.SimhashThreshold
	e.simhashTracker.ClusterLimit = s.SimhashClusterLimit

	e.configSnap.Store(s)
}

// RefreshConfigSnapshot publishes direct Config edits to workers. Prefer the
// Engine setter methods when possible; this exists for grouped config updates.
func (e *Engine) RefreshConfigSnapshot() {
	e.buildAndStoreConfigSnapshot()
}

// UpdateConfig applies grouped configuration edits under the Config lock and
// publishes the updated immutable snapshot to workers.
func (e *Engine) UpdateConfig(fn func(*Config)) {
	e.Config.Lock()
	fn(e.Config)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

// ConfigureFilters sets the matching status codes and filtering sizes.
func (e *Engine) ConfigureFilters(mc []int, fs []int) {
	e.Config.Lock()
	for _, code := range mc {
		e.Config.MatchCodes[code] = true
	}
	for _, size := range fs {
		e.Config.FilterSizes[size] = true
		e.manualFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) SetMatchRegex(pattern string) error {
	if pattern == "" {
		e.matchRe.Store(nil)
		e.Config.Lock()
		e.Config.MatchRegex = ""
		e.Config.Unlock()
		e.scheduleBuildSnapshot()
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.matchRe.Store(re)
	e.Config.Lock()
	e.Config.MatchRegex = pattern
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
	return nil
}

func (e *Engine) SetFilterRegex(pattern string) error {
	if pattern == "" {
		e.filterRe.Store(nil)
		e.Config.Lock()
		e.Config.FilterRegex = ""
		e.Config.Unlock()
		e.scheduleBuildSnapshot()
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.filterRe.Store(re)
	e.Config.Lock()
	e.Config.FilterRegex = pattern
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
	return nil
}

func (e *Engine) UpdateUserAgent(ua string) {
	e.Config.Lock()
	normalized := normalizeUserAgent(ua)
	if normalized == "" {
		normalized = "DirFuzz/2.0"
	}
	e.Config.UserAgent = normalized
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func normalizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	const prefix = "User-Agent:"
	if len(ua) >= len(prefix) && strings.EqualFold(ua[:len(prefix)], prefix) {
		ua = strings.TrimSpace(ua[len(prefix):])
	}
	return ua
}

func (e *Engine) SetDelay(d time.Duration) {
	e.Config.Lock()
	e.Config.Delay = d
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
	e.UpdateRateLimiterFromDelay()
}

func (e *Engine) AddHeader(key, val string) {
	e.Config.Lock()
	if strings.EqualFold(strings.TrimSpace(key), "User-Agent") {
		e.Config.UserAgent = normalizeUserAgent(val)
		if e.Config.UserAgent == "" {
			e.Config.UserAgent = "DirFuzz/2.0"
		}
		for hk := range e.Config.Headers {
			if strings.EqualFold(hk, "User-Agent") {
				delete(e.Config.Headers, hk)
			}
		}
		e.Config.Unlock()
		e.scheduleBuildSnapshot()
		return
	}
	e.Config.Headers[key] = val
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) RemoveHeader(key string) {
	e.Config.Lock()
	delete(e.Config.Headers, key)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) ConfigSnapshot() (ua string, filters []int, headers map[string]string, delay time.Duration, exts []string, follow bool) {
	e.Config.RLock()
	defer e.Config.RUnlock()
	ua = e.Config.UserAgent
	delay = e.Config.Delay
	for size := range e.Config.FilterSizes {
		filters = append(filters, size)
	}
	headers = make(map[string]string)
	for k, v := range e.Config.Headers {
		headers[k] = v
	}
	exts = make([]string, len(e.Config.Extensions))
	copy(exts, e.Config.Extensions)
	follow = e.Config.FollowRedirects
	return
}

func (e *Engine) AddFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	e.manualFilterSizes[size] = true
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) AddAutoFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	if !e.manualFilterSizes[size] {
		e.autoFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) RemoveFilterSize(size int) {
	e.Config.Lock()
	delete(e.Config.FilterSizes, size)
	delete(e.manualFilterSizes, size)
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) clearAutoFilterSizes() {
	e.Config.Lock()
	for size := range e.autoFilterSizes {
		if !e.manualFilterSizes[size] {
			delete(e.Config.FilterSizes, size)
		}
	}
	e.autoFilterSizes = make(map[int]bool)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) AddMatchCode(code int) {
	e.Config.Lock()
	e.Config.MatchCodes[code] = true
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) RemoveMatchCode(code int) {
	e.Config.Lock()
	delete(e.Config.MatchCodes, code)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) AddExtension(ext string) {
	e.Config.Lock()
	for _, x := range e.Config.Extensions {
		if x == ext {
			e.Config.Unlock()
			return
		}
	}
	e.Config.Extensions = append(e.Config.Extensions, ext)
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) RemoveExtension(ext string) {
	e.Config.Lock()
	var newExts []string
	for _, x := range e.Config.Extensions {
		if x != ext {
			newExts = append(newExts, x)
		}
	}
	e.Config.Extensions = newExts
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) SetMutation(active bool) {
	e.Config.Lock()
	e.Config.Mutate = active
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) SetPaused(paused bool) {
	e.Config.Lock()
	e.Config.IsPaused = paused
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}

func (e *Engine) SetFollowRedirects(follow bool) {
	e.Config.Lock()
	e.Config.FollowRedirects = follow
	e.Config.Unlock()
	e.scheduleBuildSnapshot()
}
