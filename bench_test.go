package domainfront

import (
	"context"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func BenchmarkFrontPoolTakeReturn(b *testing.B) {
	pool := newFrontPool(0)
	f := newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
	f.markSucceeded()
	pool.addReady(f)

	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		got, _ := pool.Take(ctx)
		pool.ReturnSuccess(got)
	}
}

func BenchmarkFrontPoolCandidates(b *testing.B) {
	pool := newFrontPool(0)
	fronts := make([]*front, 5000)
	for i := range fronts {
		fronts[i] = newFront(&Masquerade{
			Domain:    "cdn.example.com",
			IpAddress: "1.2.3." + string(rune('0'+i%10)),
		}, "test")
		if i%3 == 0 {
			fronts[i].markSucceeded()
		}
	}
	pool.Replace(fronts)

	b.ResetTimer()
	for b.Loop() {
		_ = pool.candidates()
	}
}

func BenchmarkRewriteRequest(b *testing.B) {
	req, _ := http.NewRequest(http.MethodGet, "https://config.example.com/api/data", nil)
	req.Header.Set("X-Custom", "value")
	b.ResetTimer()
	for b.Loop() {
		_ = rewriteRequest(req, "d1234.cloudfront.net", nil)
	}
}

func BenchmarkParseConfigYAML(b *testing.B) {
	yml := []byte(`
trustedcas:
  - commonname: "Test CA"
    cert: "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh1iGg\n-----END CERTIFICATE-----\n"
providers:
  cloudfront:
    hostaliases:
      config.example.com: d1234.cloudfront.net
    testurl: https://test.example.com/ping
    masquerades:
      - domain: cdn.example.com
        ipaddress: "1.2.3.4"
      - domain: cdn2.example.com
        ipaddress: "5.6.7.8"
`)
	b.ResetTimer()
	for b.Loop() {
		_, _ = ParseConfigYAML(yml)
	}
}

func BenchmarkProviderLookup(b *testing.B) {
	p := &Provider{
		HostAliases: map[string]string{
			"api.example.com":    "api.cdn.example.com",
			"config.example.com": "config.cdn.example.com",
			"www.example.com":    "www.cdn.example.com",
		},
		PassthroughPatterns: []string{"*.cloudfront.net", "*.akamai.net"},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = p.Lookup("config.example.com")
	}
}

func BenchmarkProviderLookupPassthrough(b *testing.B) {
	p := &Provider{
		HostAliases:         map[string]string{"api.example.com": "api.cdn.com"},
		PassthroughPatterns: []string{"*.cloudfront.net"},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = p.Lookup("d1234.cloudfront.net")
	}
}

func BenchmarkGenerateSNI(b *testing.B) {
	cfg := &SNIConfig{
		UseArbitrarySNIs: true,
		ArbitrarySNIs:    []string{"a.com", "b.com", "c.com", "d.com", "e.com"},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = GenerateSNI(cfg, "10.0.0.1")
	}
}

func BenchmarkFrontsToCache(b *testing.B) {
	fronts := make([]*front, 1000)
	for i := range fronts {
		fronts[i] = newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
		fronts[i].markSucceeded()
	}
	b.ResetTimer()
	for b.Loop() {
		_ = frontsToCache(fronts, 1000)
	}
}

// BenchmarkFrontsToCacheRealistic simulates a typical pool where only ~10%
// of fronts have been tested and succeeded — the common case on mobile.
func BenchmarkFrontsToCacheRealistic(b *testing.B) {
	fronts := make([]*front, 1000)
	for i := range fronts {
		fronts[i] = newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
		if i < 100 { // only 10% succeeded
			fronts[i].markSucceeded()
		}
	}
	b.ResetTimer()
	for b.Loop() {
		_ = frontsToCache(fronts, 1000)
	}
}

func BenchmarkGoroutineCount(b *testing.B) {
	// Measure goroutine overhead of creating and closing a client
	config := &Config{
		Providers: map[string]*Provider{
			"test": {
				HostAliases: map[string]string{"a.com": "b.com"},
				Masquerades: []*Masquerade{{Domain: "cdn.com", IpAddress: "1.2.3.4"}},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		before := runtime.NumGoroutine()
		ctx, cancel := context.WithCancel(context.Background())
		client, _ := New(ctx, config)
		after := runtime.NumGoroutine()
		_ = after - before // goroutines added
		client.Close()
		cancel()
	}
}

func TestGoroutineCount(t *testing.T) {
	config := &Config{
		Providers: map[string]*Provider{
			"test": {
				HostAliases: map[string]string{"a.com": "b.com"},
				Masquerades: []*Masquerade{{Domain: "cdn.com", IpAddress: "1.2.3.4"}},
			},
		},
	}

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	client, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let goroutines stabilize
	during := runtime.NumGoroutine()
	client.Close()
	cancel()
	time.Sleep(100 * time.Millisecond) // let goroutines wind down
	after := runtime.NumGoroutine()

	t.Logf("Goroutines: before=%d during=%d after=%d (added=%d leaked=%d)",
		before, during, after, during-before, after-before)
}

