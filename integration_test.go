//go:build integration

package domainfront

import (
	"context"
	"embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fronted.yaml.gz
var embeddedConfig embed.FS

func loadEmbeddedConfig(t *testing.T) *Config {
	t.Helper()
	data, err := embeddedConfig.ReadFile("fronted.yaml.gz")
	require.NoError(t, err)
	cfg, err := ParseConfig(data)
	require.NoError(t, err)
	return cfg
}

// TestIntegration_CloudFrontPing verifies that domain fronting works end-to-end
// with the real fronted.yaml.gz configuration and real CloudFront infrastructure.
// It fetches the CloudFront ping endpoint through domain fronting.
//
// Run with: go test -tags integration -run TestIntegration -timeout 120s -v
func TestIntegration_CloudFrontPing(t *testing.T) {
	cfg := loadEmbeddedConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cacheFile := filepath.Join(t.TempDir(), "cache.json")
	client, err := New(ctx, cfg,
		WithCacheFile(cacheFile),
		WithDefaultProviderID("cloudfront"),
	)
	require.NoError(t, err)
	defer client.Close()

	// Wait for at least one working front
	require.Eventually(t, func() bool {
		return client.pool.readyCount() > 0
	}, 30*time.Second, 200*time.Millisecond, "should find at least one working front")

	t.Logf("Found %d ready fronts", client.pool.readyCount())

	// Fetch a real resource through CloudFront domain fronting.
	// borda.lantern.io is mapped to d157vud77ygy87.cloudfront.net in the config.
	rt := client.RoundTripper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://borda.lantern.io/ping", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "round trip through CloudFront should succeed")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: status=%d bodyLen=%d", resp.StatusCode, len(body))
	// The request reached the origin via domain fronting. We accept any
	// non-server-error status — the important thing is the CDN didn't
	// reject us (400/403) and we successfully tunneled through.
	assert.Less(t, resp.StatusCode, 500, "should not get a server error")
	assert.NotEqual(t, 400, resp.StatusCode, "should not get CDN 'invalid URL' error")
	assert.NotEqual(t, 403, resp.StatusCode, "should not get CDN rejection")
}

// TestIntegration_AkamaiPing verifies domain fronting through Akamai.
// Skipped in CI because Akamai endpoints are often unreliable from CI runners.
func TestIntegration_AkamaiPing(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("Skipping Akamai integration test in CI: real Akamai endpoints are unreliable from CI runners")
	}

	cfg := loadEmbeddedConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := New(ctx, cfg,
		WithDefaultProviderID("akamai"),
	)
	require.NoError(t, err)
	defer client.Close()

	require.Eventually(t, func() bool {
		return client.pool.readyCount() > 0
	}, 30*time.Second, 200*time.Millisecond, "should find at least one working Akamai front")

	t.Logf("Found %d ready fronts", client.pool.readyCount())

	rt := client.RoundTripper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://borda.lantern.io/ping", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "round trip through Akamai should succeed")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: status=%d bodyLen=%d", resp.StatusCode, len(body))
	assert.Less(t, resp.StatusCode, 500, "should not get a server error")
	assert.NotEqual(t, 400, resp.StatusCode, "should not get CDN 'invalid URL' error")
	assert.NotEqual(t, 403, resp.StatusCode, "should not get CDN rejection")
}

// TestIntegration_CachePersistence verifies that working fronts survive
// across client restarts via the cache file.
func TestIntegration_CachePersistence(t *testing.T) {
	cfg := loadEmbeddedConfig(t)

	cacheFile := filepath.Join(t.TempDir(), "cache.json")

	// First run: discover working fronts
	ctx1, cancel1 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel1()

	client1, err := New(ctx1, cfg,
		WithCacheFile(cacheFile),
		WithDefaultProviderID("cloudfront"),
	)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return client1.pool.readyCount() > 0
	}, 30*time.Second, 200*time.Millisecond)

	client1.Close()

	// Verify cache file was written
	data, err := os.ReadFile(cacheFile)
	require.NoError(t, err)
	assert.Greater(t, len(data), 10, "cache file should have content")
	t.Logf("Cache file size: %d bytes", len(data))

	// Second run: should start faster thanks to cache
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()

	start := time.Now()
	client2, err := New(ctx2, cfg,
		WithCacheFile(cacheFile),
		WithDefaultProviderID("cloudfront"),
	)
	require.NoError(t, err)
	defer client2.Close()

	require.Eventually(t, func() bool {
		return client2.pool.readyCount() > 0
	}, 30*time.Second, 200*time.Millisecond)

	elapsed := time.Since(start)
	t.Logf("Second startup with cache: %v to first working front", elapsed)
}

// TestIntegration_NewConnectedRoundTripper verifies that NewConnectedRoundTripper
// blocks until a front is actually dialed (TLS handshake complete) and that
// the returned one-shot RoundTripper can satisfy a real domain-fronted request.
func TestIntegration_NewConnectedRoundTripper(t *testing.T) {
	cfg := loadEmbeddedConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := New(ctx, cfg,
		WithCacheFile(filepath.Join(t.TempDir(), "cache.json")),
		WithDefaultProviderID("cloudfront"),
	)
	require.NoError(t, err)
	defer client.Close()

	rt, err := client.NewConnectedRoundTripper(ctx, "")
	require.NoError(t, err, "NewConnectedRoundTripper should block until a front is dialed")
	require.NotNil(t, rt)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://borda.lantern.io/ping", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "round trip on pre-connected RT should succeed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading response body should succeed")
	t.Logf("Response: status=%d bodyLen=%d", resp.StatusCode, len(body))
	assert.Less(t, resp.StatusCode, 500)
	assert.NotEqual(t, 400, resp.StatusCode)
	assert.NotEqual(t, 403, resp.StatusCode)
}
