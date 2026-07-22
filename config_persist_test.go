package domainfront

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noDialer fails every dial so New's background crawler does no real network
// I/O; these tests only care about which config was applied at construction.
type noDialer struct{}

func (noDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dialing disabled in test")
}

// gzConfig builds a minimal valid gzipped fronted config with one provider.
func gzConfig(t *testing.T, provider string) []byte {
	t.Helper()
	yaml := fmt.Sprintf(
		"providers:\n  %s:\n    testurl: https://example.com/ping\n    masquerades:\n      - domain: cdn.example.com\n        ipaddress: \"1.2.3.4\"\n",
		provider,
	)
	data, err := CompressConfig([]byte(yaml))
	require.NoError(t, err)
	return data
}

func seedConfig(provider string) *Config {
	return &Config{Providers: map[string]*Provider{
		provider: {
			TestURL:     "https://example.com/ping",
			Masquerades: []*Masquerade{{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}},
		},
	}}
}

func hasProvider(c *Client, id string) bool {
	c.providersMu.RLock()
	defer c.providersMu.RUnlock()
	_, ok := c.providers[id]
	return ok
}

func TestPersistAndLoadConfig_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fronted_config.yaml.gz")
	c := &Client{log: slog.Default(), configCachePath: path}

	c.persistConfig(gzConfig(t, "roundtripprovider"))

	got := c.loadPersistedConfig()
	require.NotNil(t, got)
	assert.Contains(t, got.Providers, "roundtripprovider")
}

func TestLoadPersistedConfig_Absent(t *testing.T) {
	// No path configured.
	assert.Nil(t, (&Client{log: slog.Default()}).loadPersistedConfig())
	// Path configured but file missing.
	c := &Client{log: slog.Default(), configCachePath: filepath.Join(t.TempDir(), "absent.yaml.gz")}
	assert.Nil(t, c.loadPersistedConfig())
}

func TestLoadPersistedConfig_Corrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fronted_config.yaml.gz")
	require.NoError(t, os.WriteFile(path, []byte("not a gzip config"), 0o600))
	c := &Client{log: slog.Default(), configCachePath: path}
	assert.Nil(t, c.loadPersistedConfig(), "a corrupt cache must be ignored, not returned")
}

func TestNew_PrefersPersistedConfigOverSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fronted_config.yaml.gz")
	require.NoError(t, os.WriteFile(path, gzConfig(t, "persistedprovider"), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, seedConfig("seedprovider"), WithConfigCacheFile(path), WithDialer(noDialer{}))
	require.NoError(t, err)
	defer c.Close()

	assert.True(t, hasProvider(c, "persistedprovider"), "persisted config should be used")
	assert.False(t, hasProvider(c, "seedprovider"), "seed should be overridden by the persisted config")
}

func TestNew_FallsBackToSeedWhenNoCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, seedConfig("seedprovider"),
		WithConfigCacheFile(filepath.Join(t.TempDir(), "absent.yaml.gz")), WithDialer(noDialer{}))
	require.NoError(t, err)
	defer c.Close()

	assert.True(t, hasProvider(c, "seedprovider"), "seed config should be used when no cache exists")
}

// TestFetchAndApplyConfig_PersistsOnSuccess exercises the full path: the
// startup fetch (configUpdater) applies the config to the pool AND writes it to
// the config cache, so the invariant "a successful fetch warms the cache" is
// covered end-to-end, not just persistConfig in isolation.
func TestFetchAndApplyConfig_PersistsOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzConfig(t, "fetchedprovider"))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "fronted_config.yaml.gz")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, seedConfig("seedprovider"),
		WithConfigURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithConfigCacheFile(path),
		WithDialer(noDialer{}),
	)
	require.NoError(t, err)
	defer c.Close()

	// configUpdater fetches on startup; wait for the cache to be written.
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(path)
		return statErr == nil
	}, 3*time.Second, 20*time.Millisecond, "a successful fetch should persist the config")

	got := c.loadPersistedConfig()
	require.NotNil(t, got)
	assert.Contains(t, got.Providers, "fetchedprovider")
}

func TestNew_IgnoresCorruptCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fronted_config.yaml.gz")
	require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := New(ctx, seedConfig("seedprovider"), WithConfigCacheFile(path), WithDialer(noDialer{}))
	require.NoError(t, err, "a corrupt cache must not fail construction")
	defer c.Close()

	assert.True(t, hasProvider(c, "seedprovider"), "seed config should be used when the cache is corrupt")
}
