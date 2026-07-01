package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
)

func (e *Engine) saveResumeState(wordlist string, lineNum int64, persistBloom bool) {
	if e.ResumeFile == "" {
		return
	}
	state := map[string]interface{}{
		"wordlist":  wordlist,
		"line":      lineNum,
		"processed": atomic.LoadInt64(&e.ProcessedLines),
		"total":     atomic.LoadInt64(&e.TotalLines),
		"target":    e.BaseURL(),
		"graph":     e.DiscoveryGraph,
	}
	data, err := json.Marshal(state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal resume state: %v\n", err)
		return
	}
	if err := os.WriteFile(e.ResumeFile, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write resume file: %v\n", err)
	}
	if persistBloom {
		if err := e.saveBloomResumeState(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write bloom resume state: %v\n", err)
		}
	}
}

func (e *Engine) bloomResumePath() string {
	if e.ResumeFile == "" {
		return ""
	}
	return e.ResumeFile + ".bloom"
}

func (e *Engine) saveBloomResumeState() error {
	path := e.bloomResumePath()
	if path == "" {
		return nil
	}
	data, err := e.shardedFilter.marshalBinary()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (e *Engine) loadBloomResumeState() error {
	path := e.bloomResumePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return e.shardedFilter.unmarshalBinary(data)
}

func (e *Engine) LoadResumeState(path string) (string, int64, error) {
	if e.ResumeFile == "" {
		e.ResumeFile = path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	type resumeState struct {
		Wordlist  string          `json:"wordlist"`
		Line      float64         `json:"line"`
		Processed float64         `json:"processed"`
		Total     float64         `json:"total"`
		Target    string          `json:"target"`
		Graph     *DiscoveryGraph `json:"graph"`
	}
	var state resumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return "", 0, err
	}

	if state.Graph != nil {
		e.DiscoveryGraph = state.Graph
	}

	wordlist := state.Wordlist
	lineF := state.Line
	if err := e.loadBloomResumeState(); err != nil {
		return "", 0, fmt.Errorf("loading bloom resume state: %w", err)
	}
	return wordlist, int64(lineF), nil
}
