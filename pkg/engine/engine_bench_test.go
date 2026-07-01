package engine

import (


	"testing"

	"dirfuzz/pkg/httpclient"
)

func BenchmarkBuildRequest(b *testing.B) {
	headers := "Accept: application/json\r\nAuthorization: Bearer token123"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildRequest("GET", "/api/v1/users", "example.com", "Dirfuzz/2.0", headers, "")
	}
}

func BenchmarkBloomTestAndAdd(b *testing.B) {
	sbf := newShardedBloomFilter(16, 100000, 0.001)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Use a string formatting or just a constant? 
		// Real world is different paths, but benchmark can just reuse strings 
		// though Bloom filter will just return true after first add.
		// That's fine for testing the hash and lookup speed.
		sbf.TestAndAddString("GET:/some/path")
	}
}

func BenchmarkComputeResponseMetrics(b *testing.B) {
	resp := &httpclient.RawResponse{
		StatusCode: 200,
		HeaderMap: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		Body: []byte("<html><body><h1>Hello World</h1><p>Some text here.</p></body></html>"),
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		computeResponseMetrics(resp, "GET")
	}
}

func BenchmarkConfigSnapshot(b *testing.B) {
	eng := NewEngine(10, 1000, 0.001)
	eng.Config.Lock()
	eng.Config.Headers["X-Test"] = "1"
	eng.Config.MatchCodes[200] = true
	eng.Config.FilterSizes[123] = true
	eng.Config.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.buildAndStoreConfigSnapshot()
	}
}

func BenchmarkSimhashBody(b *testing.B) {
	// A sample HTML body.
	body := []byte(`
<!DOCTYPE html>
<html>
<head>
    <title>Sample Page</title>
</head>
<body>
    <h1>Hello World</h1>
    <p>This is a sample paragraph with some text to be hashed.</p>
    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
    </ul>
    <footer>Copyright 2026</footer>
</body>
</html>
`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		simhashBody(body)
	}
}
