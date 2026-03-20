package domainfront

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	cache := &FileCache{Path: path}

	// Initially empty
	loaded, err := cache.Load()
	require.NoError(t, err)
	assert.Nil(t, loaded)

	// Save some fronts
	fronts := []*CachedFront{
		{Domain: "a.com", IpAddress: "1.1.1.1", ProviderID: "p1", LastSucceeded: time.Now()},
		{Domain: "b.com", IpAddress: "2.2.2.2", ProviderID: "p2", LastSucceeded: time.Now()},
	}
	require.NoError(t, cache.Save(fronts))

	// Load back
	loaded, err = cache.Load()
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	assert.Equal(t, "a.com", loaded[0].Domain)
	assert.Equal(t, "b.com", loaded[1].Domain)
}

func TestFileCache_MissingFile(t *testing.T) {
	cache := &FileCache{Path: "/nonexistent/path/cache.json"}
	loaded, err := cache.Load()
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestNopCache(t *testing.T) {
	cache := NopCache{}
	loaded, err := cache.Load()
	assert.NoError(t, err)
	assert.Nil(t, loaded)
	assert.NoError(t, cache.Save([]*CachedFront{}))
}

func TestApplyCachedState(t *testing.T) {
	now := time.Now()
	fronts := []*front{
		newFront(&Masquerade{Domain: "a.com", IpAddress: "1.1.1.1"}, "p1"),
		newFront(&Masquerade{Domain: "b.com", IpAddress: "2.2.2.2"}, "p2"),
	}

	cached := []*CachedFront{
		{Domain: "a.com", IpAddress: "1.1.1.1", ProviderID: "p1", LastSucceeded: now.Add(-1 * time.Hour)},
		{Domain: "b.com", IpAddress: "2.2.2.2", ProviderID: "p2", LastSucceeded: now.Add(-25 * time.Hour)}, // stale
	}

	applyCachedState(fronts, cached, 24*time.Hour)
	assert.True(t, fronts[0].isSucceeding(), "fresh cached state should be applied")
	assert.False(t, fronts[1].isSucceeding(), "stale cached state should not be applied")
}

func TestFrontsToCache(t *testing.T) {
	fronts := []*front{
		newFront(&Masquerade{Domain: "a.com", IpAddress: "1.1.1.1"}, "p1"),
		newFront(&Masquerade{Domain: "b.com", IpAddress: "2.2.2.2"}, "p2"),
		newFront(&Masquerade{Domain: "c.com", IpAddress: "3.3.3.3"}, "p3"),
	}

	cached := frontsToCache(fronts, 2)
	assert.Len(t, cached, 2)
}

func TestFileCache_CreatesDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "cache.json")
	cache := &FileCache{Path: path}

	fronts := []*CachedFront{{Domain: "a.com"}}
	require.NoError(t, cache.Save(fronts))

	_, err := os.Stat(path)
	assert.NoError(t, err)
}
