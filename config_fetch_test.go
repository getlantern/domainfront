package domainfront

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func refreshClient(t *testing.T, urls ...string) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c := &Client{ctx: ctx, log: slog.Default(), httpClient: http.DefaultClient, pool: newFrontPool(10), gate: newPauseGate(), configURLs: urls}
	require.NoError(t, c.applyConfig(seedConfig("seed")))
	return c
}

func receiveConfigHeader(t *testing.T, headers <-chan http.Header) http.Header {
	t.Helper()
	select {
	case h := <-headers:
		return h
	case <-time.After(time.Second):
		t.Fatal("config request did not arrive")
		return nil
	}
}

func TestConditionalConfigPreservesReadyPool(t *testing.T) {
	for _, mode := range []string{"etag", "last-modified", "identical-200"} {
		t.Run(mode, func(t *testing.T) {
			payload := gzConfig(t, "cached")
			headers := make(chan http.Header, 4)
			var requests atomic.Int32
			modified := "Mon, 14 Sep 2026 00:00:00 GMT"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers <- r.Header.Clone()
				n := requests.Add(1)
				w.Header().Set("Last-Modified", modified)
				if mode != "last-modified" {
					w.Header().Set("ETag", `W/"version-one"`)
				}
				if n > 1 && mode != "identical-200" {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			c := refreshClient(t, server.URL)
			c.configCachePath = filepath.Join(t.TempDir(), "fronted.yaml.gz")
			c.fetchAndApplyConfig()
			initial := receiveConfigHeader(t, headers)
			assert.Empty(t, initial.Get("If-None-Match"))
			assert.Empty(t, initial.Get("If-Modified-Since"))
			require.True(t, hasProvider(c, "cached"))
			ready := seedReadyFront(t, c)
			c.gate.pause()
			oldTime := time.Unix(100000, 0)
			require.NoError(t, os.Chtimes(c.configCachePath, oldTime, oldTime))
			done := make(chan struct{})
			go func() { c.fetchAndApplyConfig(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("unchanged refresh waited for resume")
			}
			next := receiveConfigHeader(t, headers)
			if mode == "last-modified" {
				assert.Empty(t, next.Get("If-None-Match"))
				assert.Equal(t, modified, next.Get("If-Modified-Since"))
			} else {
				assert.Equal(t, `W/"version-one"`, next.Get("If-None-Match"))
				assert.Empty(t, next.Get("If-Modified-Since"), "ETag takes precedence")
			}
			assert.Same(t, ready, c.pool.candidates()[0])
			assert.Equal(t, 1, c.pool.readyCount())
			info, err := os.Stat(c.configCachePath)
			require.NoError(t, err)
			assert.Equal(t, oldTime, info.ModTime(), "unchanged payload must not be rewritten")
		})
	}
}

func TestConfig304DoesNotCancelChangedSource(t *testing.T) {
	old := gzConfig(t, "old")
	updated := gzConfig(t, "updated")
	var phase atomic.Int32
	mirrorReturned := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+r.URL.Path+`"`)
		if phase.Load() == 0 {
			_, _ = w.Write(old)
			return
		}
		if r.URL.Path == "/mirror" {
			assert.Equal(t, `"/mirror"`, r.Header.Get("If-None-Match"))
			w.WriteHeader(http.StatusNotModified)
			w.(http.Flusher).Flush()
			mirrorReturned <- struct{}{}
			return
		}
		assert.Equal(t, `"/primary"`, r.Header.Get("If-None-Match"))
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("ETag", `"new-primary"`)
		_, _ = w.Write(updated)
	}))
	defer server.Close()
	c := refreshClient(t, server.URL+"/primary")
	c.fetchAndApplyConfig()
	c.configURLs = []string{server.URL + "/mirror"}
	c.fetchAndApplyConfig()
	c.configURLs = []string{server.URL + "/mirror", server.URL + "/primary"}
	phase.Store(1)
	done := make(chan struct{})
	go func() { c.fetchAndApplyConfig(); close(done) }()
	select {
	case <-mirrorReturned:
	case <-time.After(time.Second):
		t.Fatal("mirror did not respond")
	}
	select {
	case <-done:
		t.Fatal("304 canceled the changed source")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updated config did not apply")
	}
	assert.True(t, hasProvider(c, "updated"))
	assert.NotContains(t, c.configValidators, server.URL+"/mirror", "old-payload validators must be discarded")
	assert.Equal(t, `"new-primary"`, c.configValidators[server.URL+"/primary"].ETag)
}

func TestConfigValidatorsStayScopedToURL(t *testing.T) {
	payload := gzConfig(t, "shared")
	headers := make(chan http.Header, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		tag := `"` + r.URL.Path + `"`
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	c := refreshClient(t, server.URL+"/one")
	c.fetchAndApplyConfig()
	assert.Empty(t, receiveConfigHeader(t, headers).Get("If-None-Match"))
	c.configURLs = []string{server.URL + "/two"}
	c.fetchAndApplyConfig()
	assert.Empty(t, receiveConfigHeader(t, headers).Get("If-None-Match"), "do not reuse another URL's ETag")
	c.configURLs = []string{server.URL + "/one", server.URL + "/two"}
	c.fetchAndApplyConfig()
	tags := []string{receiveConfigHeader(t, headers).Get("If-None-Match"), receiveConfigHeader(t, headers).Get("If-None-Match")}
	assert.ElementsMatch(t, []string{`"/one"`, `"/two"`}, tags)
}

func TestConfigValidatorsFollowSuccessfulResponses(t *testing.T) {
	good := gzConfig(t, "good")
	invalidCA, err := CompressConfig([]byte("trustedcas:\n  - commonname: invalid\n    cert: broken\nproviders:\n  bad:\n    masquerades: []\n"))
	require.NoError(t, err)
	for _, failure := range []string{"bad-gzip", "bad-cert", "http-error"} {
		t.Run(failure, func(t *testing.T) {
			var requests atomic.Int32
			headers := make(chan http.Header, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers <- r.Header.Clone()
				if requests.Add(1) == 1 {
					w.Header().Set("ETag", `"good"`)
					_, _ = w.Write(good)
					return
				}
				w.Header().Set("ETag", `"bad"`)
				switch failure {
				case "bad-gzip":
					_, _ = w.Write([]byte("broken"))
				case "bad-cert":
					_, _ = w.Write(invalidCA)
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()
			c := refreshClient(t, server.URL)
			c.fetchAndApplyConfig()
			receiveConfigHeader(t, headers)
			ready := seedReadyFront(t, c)
			c.fetchAndApplyConfig()
			assert.Equal(t, `"good"`, receiveConfigHeader(t, headers).Get("If-None-Match"))
			assert.True(t, hasProvider(c, "good"))
			assert.False(t, hasProvider(c, "bad"), "failed apply must not replace active provider state")
			assert.Same(t, ready, c.pool.candidates()[0])
			assert.Equal(t, `"good"`, c.configValidators[server.URL].ETag)
		})
	}
}

func TestConfigMetadataRequiresMatchingUsablePayload(t *testing.T) {
	payload := gzConfig(t, "persisted")
	invalid, err := CompressConfig([]byte("providers: {}\n"))
	require.NoError(t, err)
	for _, mode := range []string{"valid", "no-metadata", "bad-metadata", "wrong-hash", "changed-payload", "no-payload", "invalid-payload", "oversized-metadata"} {
		t.Run(mode, func(t *testing.T) {
			headers := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers <- r.Header.Clone()
				w.WriteHeader(http.StatusNotModified)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "fronted.yaml.gz")
			data := payload
			if mode == "changed-payload" {
				data = gzConfig(t, "changed")
			}
			if mode == "invalid-payload" {
				data = invalid
			}
			if mode != "no-payload" {
				require.NoError(t, os.WriteFile(path, data, 0600))
			}
			hash := configDigest(payload)
			if mode == "wrong-hash" {
				hash = "not-the-payload"
			}
			if mode == "invalid-payload" {
				hash = configDigest(data)
			}
			metadata, err := json.Marshal(configMetadata{SHA256: hash, Validators: map[string]configValidator{server.URL: {ETag: `"persisted"`}}})
			require.NoError(t, err)
			if mode == "bad-metadata" {
				metadata = []byte("invalid json")
			}
			if mode == "oversized-metadata" {
				metadata = append(metadata, []byte(strings.Repeat(" ", 64<<10))...)
			}
			if mode != "no-metadata" {
				require.NoError(t, os.WriteFile(path+".http.json", metadata, 0600))
			}
			c, err := New(context.Background(), seedConfig("seed"), WithConfigCacheFile(path), WithConfigURL(server.URL), WithDialer(noDialer{}))
			require.NoError(t, err)
			h := receiveConfigHeader(t, headers)
			c.Close()
			if mode == "valid" {
				assert.Equal(t, `"persisted"`, h.Get("If-None-Match"))
			} else {
				assert.Empty(t, h.Get("If-None-Match"))
			}
			if mode == "no-payload" || mode == "invalid-payload" {
				assert.True(t, hasProvider(c, "seed"))
			}
		})
	}
}

func TestConfigValidatorsPersistAcrossRestart(t *testing.T) {
	payload := gzConfig(t, "cached")
	headers := make(chan http.Header, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		w.Header().Set("ETag", `W/"persisted"`)
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	c := refreshClient(t, server.URL)
	c.configCachePath = filepath.Join(t.TempDir(), "fronted.yaml.gz")
	c.fetchAndApplyConfig()
	receiveConfigHeader(t, headers)
	restarted, err := New(context.Background(), seedConfig("seed"), WithConfigCacheFile(c.configCachePath), WithConfigURL(server.URL), WithDialer(noDialer{}))
	require.NoError(t, err)
	defer restarted.Close()
	assert.Equal(t, `W/"persisted"`, receiveConfigHeader(t, headers).Get("If-None-Match"))
	assert.True(t, hasProvider(restarted, "cached"))
}

func TestUnsolicited304IsIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"unknown"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	c := refreshClient(t, server.URL)
	c.fetchAndApplyConfig()
	assert.True(t, hasProvider(c, "seed"))
	assert.Empty(t, c.configHash)
	assert.Empty(t, c.configValidators)
}

func TestConfigRefreshCancellation(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	c := refreshClient(t, server.URL)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	c.ctx = ctx
	done := make(chan struct{})
	go func() { c.fetchAndApplyConfig(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled refresh did not stop")
	}
	assert.Empty(t, c.configValidators)
}

func TestConfigResponseRefreshesOrClearsValidators(t *testing.T) {
	payload := gzConfig(t, "cached")
	var requests atomic.Int32
	headers := make(chan http.Header, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		switch requests.Add(1) {
		case 1:
			w.Header().Set("ETag", `"first"`)
		case 2:
			w.Header().Set("ETag", `"second"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	c := refreshClient(t, server.URL)
	for _, want := range []string{"", `"first"`, `"second"`, ""} {
		c.fetchAndApplyConfig()
		assert.Equal(t, want, receiveConfigHeader(t, headers).Get("If-None-Match"))
	}
	assert.Empty(t, c.configValidators)
}

func BenchmarkConfigRefresh(b *testing.B) {
	payload, err := os.ReadFile("fronted.yaml.gz")
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"full-refresh", "identical-200", "not-modified-304"} {
		b.Run(mode, func(b *testing.B) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"benchmark"`)
				if mode == "not-modified-304" && r.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			c := &Client{ctx: context.Background(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), httpClient: server.Client(), pool: newFrontPool(10), gate: newPauseGate(), configURLs: []string{server.URL}}
			c.fetchAndApplyConfig()
			if c.configHash == "" {
				b.Fatal("initial fetch failed")
			}
			b.ReportAllocs()
			for b.Loop() {
				if mode == "full-refresh" {
					// Forget the active payload to measure parsing and rebuilding every time.
					c.configHash = ""
					c.configValidators = nil
				}
				c.fetchAndApplyConfig()
			}
		})
	}
}
