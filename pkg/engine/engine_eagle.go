package engine

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"os"
	"strings"
)

const maxPreviousScanLineBytes = 16 * 1024 * 1024


type previousScanRow struct {
	Result
	BodyHash string `json:"body_hash,omitempty"`
}

func previousScanKey(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return path
	}
	return method + "\x00" + path
}

func extractStoredResponseBody(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[idx+2:]
	}
	return raw
}

func eagleBodyHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func previousBodyHashFromRow(row previousScanRow) string {
	if row.BodyHash != "" {
		return row.BodyHash
	}
	if len(row.ResponseBytes) > 0 {
		return eagleBodyHash(extractStoredResponseBody(row.ResponseBytes))
	}
	if row.Response != "" {
		return eagleBodyHash(extractStoredResponseBody([]byte(row.Response)))
	}
	return ""
}

func previousResponseBytesFromRow(row previousScanRow) []byte {
	if len(row.ResponseBytes) > 0 {
		return append([]byte(nil), row.ResponseBytes...)
	}
	if row.Response != "" {
		return []byte(row.Response)
	}
	return nil
}

func (e *Engine) lookupPreviousScan(method, path string) (previousScanEntry, bool) {
	e.eagleLock.RLock()
	defer e.eagleLock.RUnlock()
	if e.PreviousState == nil {
		return previousScanEntry{}, false
	}
	if prev, ok := e.PreviousState[previousScanKey(method, path)]; ok {
		return prev, true
	}
	prev, ok := e.PreviousState[path]
	return prev, ok
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (e *Engine) applyEagleDrift(result *Result, bodyHash string) {
	prev, exists := e.lookupPreviousScan(result.Method, result.Path)
	if !exists {
		result.IsEagleAlert = true
		result.IsEagleNewEndpoint = true
		return
	}
	if prev.StatusCode != result.StatusCode {
		result.IsEagleAlert = true
		result.StatusDrift = true
		result.OldStatusCode = prev.StatusCode
	}
	if prev.Size >= 0 && result.Size >= 0 && prev.Size != result.Size {
		result.IsEagleAlert = true
		result.SizeDrift = true
		result.OldSize = prev.Size
		result.DriftDeltaBytes = absInt(result.Size - prev.Size)
	}
	if prev.BodyHash != "" && bodyHash != "" && prev.BodyHash != bodyHash {
		result.IsEagleAlert = true
		result.ContentDrift = true
		if result.OldSize == 0 && prev.Size != 0 {
			result.OldSize = prev.Size
		}
		result.OldWords = prev.Words
	}
	if result.IsEagleAlert && len(prev.ResponseBytes) > 0 {
		result.PreviousResponseBytes = append([]byte(nil), prev.ResponseBytes...)
	}
}

// LoadPreviousScan loads a previous JSONL scan file for differential scanning.
func (e *Engine) LoadPreviousScan(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	e.eagleLock.Lock()
	defer e.eagleLock.Unlock()

	if e.PreviousState == nil {
		e.PreviousState = make(map[string]previousScanEntry)
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxPreviousScanLineBytes)
	for scanner.Scan() {
		var row previousScanRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			continue
		}
		e.PreviousState[previousScanKey(row.Method, row.Path)] = previousScanEntry{
			StatusCode:    row.StatusCode,
			Size:          row.Size,
			Words:         row.Words,
			BodyHash:      previousBodyHashFromRow(row),
			ResponseBytes: previousResponseBytesFromRow(row),
		}
	}
	return scanner.Err()
}
