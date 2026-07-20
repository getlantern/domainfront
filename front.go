package domainfront

import (
	"cmp"
	"context"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// front is a single domain front candidate with its runtime state.
type front struct {
	Masquerade
	LastSucceeded time.Time `json:"LastSucceeded"`
	ProviderID    string    `json:"ProviderID"`
	mu            sync.RWMutex
}

func newFront(m *Masquerade, providerID string) *front {
	return &front{
		Masquerade: *m,
		ProviderID: providerID,
	}
}

func (f *front) lastSucceededTime() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.LastSucceeded
}

func (f *front) setLastSucceeded(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastSucceeded = t
}

func (f *front) markSucceeded() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastSucceeded = time.Now()
}

func (f *front) markFailed() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastSucceeded = time.Time{}
}

func (f *front) isSucceeding() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return !f.LastSucceeded.IsZero()
}

// frontKey identifies a front by its provider, domain, and IP.
type frontKey struct{ provider, domain, ip string }

func (f *front) key() frontKey {
	return frontKey{f.ProviderID, f.Domain, f.IpAddress}
}

// frontPool manages a pool of domain front candidates. Goroutine-safe.
// Take blocks until a front is available or ctx is cancelled.
// Return puts a front back after use. Replace atomically swaps the set.
type frontPool struct {
	mu     sync.Mutex
	fronts []*front
	ready  chan *front
	closed chan struct{}
}

func newFrontPool(readySize int) *frontPool {
	if readySize <= 0 {
		readySize = 500
	}
	return &frontPool{
		ready:  make(chan *front, readySize),
		closed: make(chan struct{}),
	}
}

// Replace atomically swaps the candidate set. Fronts that were previously
// known to be working (matched by providerID+domain+IP) retain their state.
func (p *frontPool) Replace(fronts []*front) {
	p.mu.Lock()
	defer p.mu.Unlock()

	old := make(map[frontKey]*front, len(p.fronts))
	for _, f := range p.fronts {
		old[f.key()] = f
	}

	for _, f := range fronts {
		if prev, ok := old[f.key()]; ok {
			f.setLastSucceeded(prev.lastSucceededTime())
		}
	}

	p.fronts = fronts
	// Drain the ready channel; the crawler will repopulate it
	for {
		select {
		case <-p.ready:
		default:
			return
		}
	}
}

// addReady marks a front as ready (working) and makes it available for Take.
func (p *frontPool) addReady(f *front) {
	select {
	case p.ready <- f:
	default:
		// ready channel full, drop
	}
}

// readyCount returns the number of fronts in the ready queue.
func (p *frontPool) readyCount() int {
	return len(p.ready)
}

// Take returns a working front, blocking until one is available or ctx is cancelled.
func (p *frontPool) Take(ctx context.Context) (*front, error) {
	select {
	case f := <-p.ready:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.closed:
		return nil, context.Canceled
	}
}

// maxProviderScan bounds how many ready fronts TakePreferringUntried will pull
// while hunting for an untried provider, so a ready queue dominated by one
// provider can't turn a single take into a large drain-and-requeue.
const maxProviderScan = 8

// TakePreferringUntried returns a working front, preferring one whose ProviderID
// is not present in tried. It blocks (like Take) until at least one front is
// available, then scans a bounded number of additional ready fronts without
// blocking; every front it pulls but doesn't select is returned to the ready
// queue. If no untried provider is immediately available it falls back to the
// first front taken, so it never blocks longer than Take. A nil/empty tried map
// makes it behave exactly like Take.
func (p *frontPool) TakePreferringUntried(ctx context.Context, tried map[string]struct{}) (*front, error) {
	first, err := p.Take(ctx)
	if err != nil {
		return nil, err
	}
	if _, seen := tried[first.ProviderID]; !seen {
		return first, nil
	}

	skipped := []*front{first}
	selected := first
	scan := min(p.readyCount(), maxProviderScan)
	for i := 0; i < scan; i++ {
		f, ok := p.tryTakeReady()
		if !ok {
			break // nothing more ready right now
		}
		if _, seen := tried[f.ProviderID]; !seen {
			selected = f
			break
		}
		skipped = append(skipped, f)
	}
	for _, s := range skipped {
		if s != selected {
			p.addReady(s)
		}
	}
	return selected, nil
}

// tryTakeReady returns a ready front without blocking, or ok=false when none is
// immediately available.
func (p *frontPool) tryTakeReady() (*front, bool) {
	select {
	case f := <-p.ready:
		return f, true
	default:
		return nil, false
	}
}

// Return puts a front back into the ready queue without updating its success
// timestamp. Use this when the front should be kept in rotation but no real
// round trip occurred (e.g. provider mapping miss). Pass requeue=false to
// mark the front as failed and remove it from rotation.
func (p *frontPool) Return(f *front, requeue bool) {
	if requeue {
		p.addReady(f)
	} else {
		f.markFailed()
	}
}

// ReturnSuccess records a real successful round trip and puts the front back
// into the ready queue.
func (p *frontPool) ReturnSuccess(f *front) {
	f.markSucceeded()
	p.addReady(f)
}

// Close shuts down the pool, unblocking any pending Take calls.
func (p *frontPool) Close() {
	select {
	case <-p.closed:
		// already closed
	default:
		close(p.closed)
	}
}

// candidates returns a copy of all known fronts, with recently-succeeded
// fronts first and the rest shuffled.
func (p *frontPool) candidates() []*front {
	p.mu.Lock()
	n := len(p.fronts)
	if n == 0 {
		p.mu.Unlock()
		return nil
	}

	// Pack pointer + int64 timestamp together (16 bytes vs 32 for time.Time).
	// This halves the working-set size and makes sort comparisons cheaper
	// (plain int64 compare vs time.Time.After with monotonic-clock logic).
	type item struct {
		f  *front
		ts int64 // UnixNano; 0 = never succeeded
	}
	items := make([]item, n)
	for i, f := range p.fronts {
		items[i].f = f
	}
	p.mu.Unlock()

	// Snapshot timestamps outside the pool lock
	for i := range items {
		if t := items[i].f.lastSucceededTime(); !t.IsZero() {
			items[i].ts = t.UnixNano()
		}
	}

	// pdqsort via slices.SortFunc: faster than sort.Slice, no interface boxing
	slices.SortFunc(items, func(a, b item) int {
		if c := cmp.Compare(b.ts, a.ts); c != 0 {
			return c // descending: most recent first
		}
		return cmp.Compare(a.f.IpAddress, b.f.IpAddress)
	})

	// Shuffle the non-succeeded tail
	tail := 0
	for tail < n && items[tail].ts != 0 {
		tail++
	}
	rest := items[tail:]
	rand.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })

	c := make([]*front, n)
	for i := range items {
		c[i] = items[i].f
	}
	return c
}
