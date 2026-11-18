package domainfront

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refusingDialer fails every dial at once, like a network that drops
// connections to every front.
type refusingDialer struct {
	dials atomic.Int32
}

func (d *refusingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("dial refused")
}

func TestNextCrawlDelay_BacksOffOnEmptyPasses(t *testing.T) {
	c := &Client{crawlInterval: time.Second}
	assert.Equal(t, time.Second, c.nextCrawlDelay())

	c.emptyPasses.Store(1)
	assert.Equal(t, 2*time.Second, c.nextCrawlDelay())

	c.emptyPasses.Store(3)
	assert.Equal(t, 8*time.Second, c.nextCrawlDelay())

	c.emptyPasses.Store(100)
	assert.Equal(t, 32*time.Second, c.nextCrawlDelay())
}

func TestClient_CrawlerBacksOffWhenEveryFrontFails(t *testing.T) {
	const fronts = 5
	dialer := &refusingDialer{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, manyFrontsConfig(fronts),
		WithDialer(dialer),
		withCrawlInterval(20*time.Millisecond),
	)
	require.NoError(t, err)
	defer client.Close()

	// At a flat 20ms a second holds about 50 passes. Doubling leaves room for 6.
	time.Sleep(time.Second)
	assert.LessOrEqual(t, dialer.dials.Load(), int32(8*fronts), "crawler kept redialing every front")
	assert.GreaterOrEqual(t, dialer.dials.Load(), int32(2*fronts), "crawler stopped retrying")

	// Let the backoff reach its cap of 640ms between passes.
	time.Sleep(time.Second)

	// A resume means the network may have changed, so passes start over at
	// the short delay: several fit where the capped backoff allows one.
	client.Pause()
	before := dialer.dials.Load()
	client.Resume()
	require.Eventually(t, func() bool {
		return dialer.dials.Load()-before >= 2*fronts
	}, 500*time.Millisecond, 10*time.Millisecond, "resume did not reset the crawl backoff")
}

func TestClient_CrawlerBacksOffAfterFirstEmptyPass(t *testing.T) {
	const fronts = 5
	dialer := &refusingDialer{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// New queues a wake-up before the first pass. That pass must use it up,
	// so the 400ms wait after it still applies.
	client, err := New(ctx, manyFrontsConfig(fronts),
		WithDialer(dialer),
		withCrawlInterval(200*time.Millisecond),
	)
	require.NoError(t, err)
	defer client.Close()

	require.Eventually(t, func() bool {
		return dialer.dials.Load() >= fronts
	}, time.Second, 5*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(fronts), dialer.dials.Load(), "second pass skipped the backoff")
}
