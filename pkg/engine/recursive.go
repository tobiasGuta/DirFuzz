package engine

import (
	"strings"
)

type recursiveResponseSignature struct {
	statusCode  int
	size        int
	words       int
	lines       int
	contentType string
	bodyHash    uint64
}

func makeRecursiveResponseSignature(statusCode, size, words, lines int, contentType string, bodyHash uint64) recursiveResponseSignature {
	return recursiveResponseSignature{
		statusCode:  statusCode,
		size:        size,
		words:       words,
		lines:       lines,
		contentType: strings.ToLower(strings.TrimSpace(contentType)),
		bodyHash:    bodyHash,
	}
}

func normalizeRecursiveSignaturePath(path string) string {
	path = strings.TrimSpace(path)
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/'
	})
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/")
}

func recursiveMirrorReferencePaths(path string) []string {
	normalized := normalizeRecursiveSignaturePath(path)
	if normalized == "" {
		return nil
	}
	segments := strings.Split(normalized, "/")
	if len(segments) < 2 {
		return nil
	}

	seen := make(map[string]struct{})
	refs := make([]string, 0, len(segments)*2)
	add := func(ref string) {
		if ref == "" || ref == normalized {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}

	for i := len(segments) - 1; i >= 1; i-- {
		add(strings.Join(segments[:i], "/"))
	}
	for i := 1; i < len(segments); i++ {
		if !strings.EqualFold(segments[i-1], segments[i]) {
			continue
		}
		collapsed := make([]string, 0, len(segments)-1)
		collapsed = append(collapsed, segments[:i]...)
		collapsed = append(collapsed, segments[i+1:]...)
		add(strings.Join(collapsed, "/"))
	}
	return refs
}

func (t *engineRecursiveTracker) RememberSignature(path string, sig recursiveResponseSignature) {
	normalized := normalizeRecursiveSignaturePath(path)
	if normalized == "" {
		return
	}
	t.signatures.Store(normalized, sig)
}

func (t *engineRecursiveTracker) IsMirror(path string, sig recursiveResponseSignature) bool {
	for _, ref := range recursiveMirrorReferencePaths(path) {
		if prev, ok := t.signatures.Load(ref); ok && prev == sig {
			return true
		}
	}
	return false
}

func shouldPruneRecursiveBranch(path, contentType string, body []byte) (bool, string) {
	terminal := recursiveTerminalSegment(path)
	if terminal == "" {
		return false, ""
	}
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	if isStaticContentType(contentType) {
		return true, "static content type"
	}
	if isLowValueStaticSegment(terminal) {
		if bodyContainsInterestingRecursiveToken(body) {
			return false, ""
		}
		if terminal == "fonts" || terminal == "font" {
			return true, "font asset directory"
		}
		if bodyLooksLikeStaticDirectoryListing(body) {
			return true, "static directory listing"
		}
	}
	if bodyLooksLikeStaticDirectoryListing(body) && !bodyContainsInterestingRecursiveToken(body) {
		return true, "mostly static directory listing"
	}
	return false, ""
}

func recursiveTerminalSegment(path string) string {
	normalized := normalizeRecursiveSignaturePath(path)
	if normalized == "" {
		return ""
	}
	segments := strings.Split(normalized, "/")
	return strings.ToLower(strings.TrimSpace(segments[len(segments)-1]))
}

func isStaticContentType(contentType string) bool {
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return true
	case strings.HasPrefix(contentType, "font/"):
		return true
	case contentType == "text/css":
		return true
	case contentType == "application/font-woff" || contentType == "application/font-woff2":
		return true
	case contentType == "application/vnd.ms-fontobject":
		return true
	}
	return false
}

func isLowValueStaticSegment(segment string) bool {
	switch strings.ToLower(strings.TrimSpace(segment)) {
	case "font", "fonts", "icon", "icons", "image", "images", "img", "imgs", "css", "styles", "style":
		return true
	default:
		return false
	}
}

func bodyLooksLikeStaticDirectoryListing(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	staticCount := 0
	for _, token := range []string{".woff", ".woff2", ".ttf", ".otf", ".eot", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".css", ".map"} {
		staticCount += strings.Count(lower, token)
	}
	if staticCount < 3 {
		return false
	}
	return strings.Contains(lower, "<a ") || strings.Contains(lower, "index of") || strings.Contains(lower, "directory")
}

func bodyContainsInterestingRecursiveToken(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	for _, token := range []string{
		"admin", "api", "auth", "backup", ".bak", ".old", ".orig", ".save", ".sql", ".sqlite",
		"config", "debug", "dev", ".env", "private", "secret", "test", "upload", "user",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}
