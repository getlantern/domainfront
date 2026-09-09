package domainfront

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPauseGate(t *testing.T) {
	t.Run("resumed by default", func(t *testing.T) {
		g := newPauseGate()
		assert.False(t, g.isPaused())
		assert.True(t, g.wait(context.Background()))
	})

	t.Run("wait blocks until resume", func(t *testing.T) {
		g := newPauseGate()
		g.pause()
		require.True(t, g.isPaused())

		released := make(chan bool, 1)
		go func() { released <- g.wait(context.Background()) }()

		select {
		case <-released:
			t.Fatal("wait returned while paused")
		case <-time.After(50 * time.Millisecond):
		}

		g.resume()
		select {
		case ok := <-released:
			assert.True(t, ok)
		case <-time.After(time.Second):
			t.Fatal("wait did not return after resume")
		}
		assert.False(t, g.isPaused())
	})

	t.Run("wait returns false when ctx ends", func(t *testing.T) {
		g := newPauseGate()
		g.pause()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.False(t, g.wait(ctx))
	})

	t.Run("repeated calls are idempotent", func(t *testing.T) {
		g := newPauseGate()
		g.pause()
		g.pause()
		assert.True(t, g.isPaused())
		g.resume()
		assert.False(t, g.isPaused())
		g.resume()
		assert.False(t, g.isPaused())
		assert.True(t, g.wait(context.Background()))
	})
}

// blockingDialer holds every dial open until release is closed, so a test can
// pause a client with a crawl already in flight.
type blockingDialer struct {
	dials   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func newBlockingDialer() *blockingDialer {
	return &blockingDialer{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

func (d *blockingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.dials.Add(1)
	select {
	case d.entered <- struct{}{}:
	default:
	}
	select {
	case <-d.release:
	case <-ctx.Done():
	}
	return nil, errors.New("dial refused")
}

func manyFrontsConfig(n int) *Config {
	masquerades := make([]*Masquerade, n)
	for i := range masquerades {
		masquerades[i] = &Masquerade{
			Domain:    "cdn.example.com",
			IpAddress: fmt.Sprintf("192.0.2.%d:443", i+1),
		}
	}
	return &Config{
		Providers: map[string]*Provider{
			"test": {
				HostAliases: map[string]string{"origin.example.com": "cdn.example.com"},
				TestURL:     "https://cdn.example.com/ping",
				Masquerades: masquerades,
			},
		},
	}
}

func TestClient_PauseStopsCrawling(t *testing.T) {
	dialer := newBlockingDialer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, manyFrontsConfig(20),
		WithDialer(dialer),
		WithCrawlerConcurrency(1),
		withCrawlInterval(100*time.Millisecond),
	)
	require.NoError(t, err)
	defer client.Close()

	// Pause with the first dial in flight, so the crawl is mid-pass rather than
	// between passes: the candidates behind it must not be dialed.
	select {
	case <-dialer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("crawler never dialed")
	}
	client.Pause()
	close(dialer.release)

	require.Never(t, func() bool {
		return dialer.dials.Load() > 1
	}, 500*time.Millisecond, 20*time.Millisecond, "paused crawler kept dialing")

	client.Resume()
	require.Eventually(t, func() bool {
		return dialer.dials.Load() > 1
	}, 5*time.Second, 20*time.Millisecond, "crawler did not resume")
}

type countingCache struct {
	saves atomic.Int32
}

func (c *countingCache) Load() ([]*CachedFront, error) { return nil, nil }

func (c *countingCache) Save([]*CachedFront) error {
	c.saves.Add(1)
	return nil
}

func TestClient_PauseStopsCacheSaver(t *testing.T) {
	cache := &countingCache{}
	dialer := newBlockingDialer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, manyFrontsConfig(1),
		WithDialer(dialer),
		WithCache(cache),
		WithCacheSaveInterval(10*time.Millisecond),
	)
	require.NoError(t, err)
	defer client.Close()

	client.notifyCacheDirty()
	require.Eventually(t, func() bool {
		return cache.saves.Load() > 0
	}, 2*time.Second, 10*time.Millisecond, "cache saver never ran")

	client.Pause()
	// The saver may be past its gate on the tick already in flight, so let the
	// count settle before sampling the value it must then hold at.
	paused := waitForStableCount(t, cache.saves.Load)

	client.notifyCacheDirty()
	require.Never(t, func() bool {
		return cache.saves.Load() > paused
	}, 300*time.Millisecond, 10*time.Millisecond, "paused cache saver kept saving")

	client.Resume()
	client.notifyCacheDirty()
	require.Eventually(t, func() bool {
		return cache.saves.Load() > paused
	}, 2*time.Second, 10*time.Millisecond, "cache saver did not resume")
}

func TestClient_CloseWhilePaused(t *testing.T) {
	dialer := newBlockingDialer()
	defer close(dialer.release)

	client, err := New(context.Background(), manyFrontsConfig(5),
		WithDialer(dialer),
		WithCacheSaveInterval(10*time.Millisecond),
		// Starts the config updater; refused immediately so no real fetch runs.
		WithConfigURL("http://127.0.0.1:1/config.yaml.gz"),
	)
	require.NoError(t, err)

	client.Pause()

	done := make(chan struct{})
	go func() {
		client.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close() timed out while paused")
	}
}

func TestClient_PausedClientStillRoundTrips(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert := newTestLeafCert(t, caCert, caKey, "cdn.example.com")
	addr, cleanup := mockCDN(t, leafCert)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)

	config := &Config{
		TrustedCAs: []*CA{{CommonName: "Test CA", Cert: string(pemEncodeCert(caCert))}},
		Providers: map[string]*Provider{
			"testprovider": {
				HostAliases: map[string]string{"origin.example.com": "cdn.example.com"},
				TestURL:     fmt.Sprintf("https://cdn.example.com:%s/ping", port),
				Masquerades: []*Masquerade{
					{Domain: "cdn.example.com", IpAddress: "127.0.0.1:" + port},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, config,
		WithClientHelloID(utlsHelloGolang()),
		WithMaxRetries(3),
		WithCrawlerConcurrency(2),
	)
	require.NoError(t, err)
	defer client.Close()

	require.Eventually(t, func() bool {
		return client.pool.readyCount() > 0
	}, 10*time.Second, 100*time.Millisecond, "should find working fronts")

	client.Pause()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://origin.example.com/hello", nil)
	resp, err := client.RoundTripper().RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "hello from CDN")
}

// waitForStableCount polls until count holds steady across consecutive samples,
// so a test can read a paused loop's final tally without assuming how long the
// cycle already in flight takes to land.
func waitForStableCount(t *testing.T, count func() int32) int32 {
	t.Helper()
	last := count()
	steady := 0
	for range 200 {
		time.Sleep(10 * time.Millisecond)
		got := count()
		if got != last {
			last, steady = got, 0
			continue
		}
		if steady++; steady == 3 {
			return got
		}
	}
	t.Fatal("count never stabilized")
	return 0
}

// seedReadyFront puts one known-good front into the ready queue and returns it,
// standing in for a front an earlier crawl had vetted.
func seedReadyFront(t *testing.T, client *Client) *front {
	t.Helper()
	candidates := client.pool.candidates()
	require.NotEmpty(t, candidates)
	f := candidates[0]
	f.markSucceeded()
	client.pool.addReady(f)
	return f
}

// failingCountDialer fails every dial and counts them, so a test can wait for a
// crawl pass to quiesce before touching the pool it vets.
type failingCountDialer struct{ dials atomic.Int32 }

func (d *failingCountDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("dial refused")
}

func TestClient_PausedDialFailureKeepsFrontInRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := &failingCountDialer{}
	client, err := New(ctx, manyFrontsConfig(1),
		WithDialer(dialer),
		WithMaxRetries(3),
	)
	require.NoError(t, err)
	defer client.Close()

	client.Pause()
	// Let the crawler's in-flight first pass settle before seeding, so its
	// markFailed can't race the front we seed as succeeding.
	waitForStableCount(t, dialer.dials.Load)
	f := seedReadyFront(t, client)

	reqCtx, reqCancel := context.WithTimeout(ctx, time.Second)
	defer reqCancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://origin.example.com/", nil)
	_, err = client.RoundTripper().RoundTrip(req)
	require.Error(t, err, "every dial fails, so the round trip cannot succeed")

	assert.True(t, f.isSucceeding(), "a dial failure while paused must not drop the front")
	assert.Equal(t, 1, client.pool.readyCount(), "the front should be back in the ready queue")
}

func TestClient_DialFailureDropsFrontWhenRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := &failingCountDialer{}
	client, err := New(ctx, manyFrontsConfig(1),
		WithDialer(dialer),
		WithMaxRetries(3),
		withCrawlInterval(time.Hour),
	)
	require.NoError(t, err)
	defer client.Close()

	// Let the crawler's first pass settle before seeding, so its markFailed
	// can't be what drops the front instead of returnAfterDialFailure.
	waitForStableCount(t, dialer.dials.Load)
	f := seedReadyFront(t, client)

	// Once the front is dropped, the second retry's Take blocks on an empty
	// queue, so a short deadline ends the round trip without waiting it out.
	reqCtx, reqCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer reqCancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://origin.example.com/", nil)
	_, err = client.RoundTripper().RoundTrip(req)
	require.Error(t, err)

	assert.False(t, f.isSucceeding(), "an unpaused dial failure should still drop the front")
}

// observedWaitContext lets a test order resume/pause before a waiter wakes.
// Done is evaluated after wait snapshots the gate channel.
type observedWaitContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	proceed chan struct{}
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.entered)
		<-c.proceed
	})
	return c.Context.Done()
}

func TestPauseGate_ResumeThenPauseBeforeWaiterWakes(t *testing.T) {
	g := newPauseGate()
	g.pause()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedWaitContext{Context: base, entered: make(chan struct{}), proceed: make(chan struct{})}
	released := make(chan bool, 1)
	go func() { released <- g.wait(ctx) }()
	<-ctx.entered
	g.resume()
	g.pause()
	close(ctx.proceed)
	select {
	case <-released:
		t.Fatal("wait returned through a previous resume while paused again")
	case <-time.After(50 * time.Millisecond):
	}
	g.resume()
	select {
	case ok := <-released:
		require.True(t, ok)
	case <-time.After(time.Second):
		t.Fatal("wait did not return after the final resume")
	}
}

func TestPauseGate_CanceledWhileRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, newPauseGate().wait(ctx))
}
