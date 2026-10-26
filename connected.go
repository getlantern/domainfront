package domainfront

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"time"
)

// NewConnectedRoundTripper returns an http.RoundTripper whose underlying TLS
// connection to a working front is already established. Blocks until a front
// is dialed or ctx is cancelled, so callers that race multiple transports can
// see the connection ready/fail signal on the actual wire, not on a cached
// wrapper.
//
// It races every provider that has a mapping for addr's host, dialing one of
// each provider's fronts at a time (up to maxRetries per provider; see
// connectVia), and the first front to connect wins. Providers without a mapping are skipped: a
// front of theirs could connect but never carry the request. If no provider
// maps the host, it fails at once. An addr without a host races every
// provider.
//
// The returned value is also an io.Closer. Callers that obtain a connected
// RT they end up not using (e.g. a lost race) should call Close() so the
// front is returned to the pool and the TLS connection is released instead
// of leaking until GC.
//
// The returned RoundTripper is single-use: after RoundTrip is called once,
// subsequent RoundTrip calls return ErrRoundTripperUsed.
func (c *Client) NewConnectedRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error) {
	host := hostOf(addr)
	pids := c.providersMapping(host)
	if len(pids) == 0 {
		return nil, fmt.Errorf("no domain fronting mapping for '%s' on any provider", host)
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan laneResult, len(pids))
	for _, pid := range pids {
		go func() { results <- c.connectVia(raceCtx, pid, host) }()
	}
	// release closes the fronts that connect after the race is decided: the
	// lanes stop once cancelled, but a front mid-handshake can still connect.
	release := func(n int) {
		go func() {
			for range n {
				if r := <-results; r.rt != nil {
					r.rt.Close()
				}
			}
		}()
	}

	var errs []error
	for remaining := len(pids); remaining > 0; remaining-- {
		var r laneResult
		select {
		case r = <-results:
		case <-ctx.Done():
			// The TLS handshake doesn't watch ctx, so don't wait it out.
			cancel()
			release(remaining)
			return nil, fmt.Errorf("ctx done before any front connected: %w", errors.Join(append(errs, ctx.Err())...))
		}
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		cancel()
		release(remaining - 1)
		return r.rt, nil
	}
	cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ctx done before any front connected: %w", errors.Join(append(errs, err)...))
	}
	return nil, fmt.Errorf("could not connect to any front: %w", errors.Join(errs...))
}

// laneResult is one provider's outcome in NewConnectedRoundTripper's race.
type laneResult struct {
	rt  *connectedRoundTripper
	err error
}

// connectVia dials pid's fronts one at a time until one connects, up to
// maxRetries of them. It prefers fronts the crawler has vetted (the ready
// queue). When none of pid's are ready it vets and dials pid's other fronts
// itself (see dialUnvetted), most recently successful first, rather than
// waiting for the crawler: the
// crawler fills the ready queue for all providers together, so it can stop
// with every ready front belonging to providers that can't serve this host.
func (c *Client) connectVia(ctx context.Context, pid, host string) laneResult {
	var lastErr error
	var candidates []*front
	loaded := false
	// A front that failed is still among the candidates, so skip the ones
	// already dialed rather than spend the budget on them twice.
	tried := make(map[*front]struct{})
	for range c.maxRetries {
		f, ready := c.pool.tryTakeFrom(func(f *front) bool {
			_, seen := tried[f]
			return !seen && c.providerIDOf(f) == pid
		})
		if !ready {
			if !loaded {
				for _, cf := range c.pool.candidates() {
					if c.providerIDOf(cf) == pid {
						candidates = append(candidates, cf)
					}
				}
				loaded = true
			}
			for len(candidates) > 0 {
				if _, seen := tried[candidates[0]]; !seen {
					break
				}
				candidates = candidates[1:]
			}
			if len(candidates) == 0 {
				break
			}
			f, candidates = candidates[0], candidates[1:]
		}
		tried[f] = struct{}{}
		provider := c.providerFor(f)
		if provider == nil {
			if ready {
				c.pool.Return(f, true)
			}
			lastErr = fmt.Errorf("no provider for front %s/%s", f.ProviderID, f.Domain)
			continue
		}
		if host != "" && provider.Lookup(host) == "" {
			// A config update dropped the mapping since the race began.
			if ready {
				c.pool.Return(f, true)
			}
			return laneResult{err: fmt.Errorf("provider %s: no longer maps '%s'", pid, host)}
		}
		if !ready && provider.TestURL == "" {
			// Without a test URL no fallback front can be vetted, and that
			// says nothing about the fronts.
			return laneResult{err: fmt.Errorf("provider %s: no ready fronts and no test URL to vet others", pid)}
		}
		var result dialResult
		if ready {
			result = dialFront(ctx, f, c.certPool(), c.clientHelloID, c.dialer)
		} else {
			result = c.dialUnvetted(ctx, f, provider)
		}
		if result.err != nil {
			if ctx.Err() != nil {
				// Cancelled (another provider won, or the caller gave up):
				// that says nothing about this front.
				if ready {
					c.pool.Return(f, true)
				}
				return laneResult{err: fmt.Errorf("provider %s: %w", pid, ctx.Err())}
			}
			if ready {
				c.returnAfterDialFailure(f)
			} else if !c.gate.isPaused() {
				f.markFailed()
				c.notifyCacheDirty()
			}
			lastErr = fmt.Errorf("dial front %s: %w", f.Domain, result.err)
			continue
		}
		return laneResult{rt: &connectedRoundTripper{
			client:   c,
			front:    f,
			provider: provider,
			conn:     result.conn,
		}}
	}
	if lastErr == nil {
		return laneResult{err: fmt.Errorf("provider %s: no fronts", pid)}
	}
	return laneResult{err: fmt.Errorf("provider %s: %w", pid, lastErr)}
}

// dialUnvetted dials f, a front the crawler hasn't vetted (or has rejected),
// for connectVia. A front can complete TLS yet refuse to forward, and a front
// that wins the race carries the request with no retry, so f must first pass
// the crawler's check: a POST to the provider's test URL. That spends the
// connection, so f is dialed again for the caller.
func (c *Client) dialUnvetted(ctx context.Context, f *front, provider *Provider) dialResult {
	result := dialFront(ctx, f, c.certPool(), c.clientHelloID, c.dialer)
	if result.err != nil {
		return result
	}
	// verifyWithPost doesn't take a ctx, so bound it with the conn instead.
	stop := context.AfterFunc(ctx, func() { result.conn.Close() })
	result.conn.SetDeadline(time.Now().Add(dialTimeout))
	ok := c.verifyWithPost(result.conn, provider.TestURL)
	stop()
	result.conn.Close()
	if err := ctx.Err(); err != nil {
		return dialResult{err: err}
	}
	if !ok {
		return dialResult{err: fmt.Errorf("front %s failed vetting", f.Domain)}
	}
	f.markSucceeded()
	return dialFront(ctx, f, c.certPool(), c.clientHelloID, c.dialer)
}

// providersMapping returns, sorted, the IDs of the providers with a mapping
// for host, or of every provider when host is empty.
func (c *Client) providersMapping(host string) []string {
	c.providersMu.RLock()
	defer c.providersMu.RUnlock()
	var pids []string
	for pid, p := range c.providers {
		if host == "" || p.Lookup(host) != "" {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// providerIDOf returns the ID of the provider f belongs to, as providerFor
// resolves it.
func (c *Client) providerIDOf(f *front) string {
	if f.ProviderID == "" {
		return c.defaultPID
	}
	return f.ProviderID
}

// hostOf returns addr's host, without a port.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// ErrRoundTripperUsed is returned if RoundTrip is called on a connected
// RoundTripper that has already been used (or closed). The caller should
// request a fresh one via NewConnectedRoundTripper.
var ErrRoundTripperUsed = errors.New("domainfront: connected round-tripper already used")

// connectedRoundTripper is a single-use http.RoundTripper bound to a
// pre-dialed TLS connection.
type connectedRoundTripper struct {
	client   *Client
	front    *front
	provider *Provider
	conn     net.Conn
	used     atomic.Bool
}

// RoundTrip sends req over the pre-dialed connection. It may be called at
// most once per RT — subsequent calls return ErrRoundTripperUsed. Whether
// the request succeeds or fails, the front is reported back to the pool and
// the connection is released.
func (rt *connectedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !rt.used.CompareAndSwap(false, true) {
		return nil, ErrRoundTripperUsed
	}

	originHost := req.URL.Hostname()
	frontedHost := rt.provider.Lookup(originHost)
	if frontedHost == "" {
		// Not the front's fault — requeue it without marking failure, but
		// still close the dialed conn since we won't use it.
		rt.client.pool.Return(rt.front, true)
		rt.conn.Close()
		return nil, fmt.Errorf("no domain fronting mapping for '%s' on provider %s", originHost, rt.front.ProviderID)
	}

	bodyFactory, err := getBodyFactory(req)
	if err != nil {
		rt.client.pool.Return(rt.front, true)
		rt.conn.Close()
		return nil, fmt.Errorf("buffer body: %w", err)
	}
	body, err := bodyFactory()
	if err != nil {
		rt.client.pool.Return(rt.front, true)
		rt.conn.Close()
		return nil, fmt.Errorf("get body: %w", err)
	}

	inner := &roundTripper{client: rt.client}
	resp, err := inner.doRequest(req, rt.conn, frontedHost, rt.front.ProviderID, body)
	if err != nil {
		rt.client.pool.Return(rt.front, false)
		rt.client.notifyCacheDirty()
		rt.conn.Close()
		return nil, err
	}
	rt.client.pool.ReturnSuccess(rt.front)
	rt.client.notifyCacheDirty()
	return resp, nil
}

// Close releases the pre-dialed connection and returns the front to the
// pool if RoundTrip hasn't been called. Safe to call multiple times; any
// call after RoundTrip has run is a no-op. Call this when a caller (e.g.
// a race transport that has already picked a winner) has obtained a
// connected RT it doesn't intend to use.
func (rt *connectedRoundTripper) Close() error {
	if !rt.used.CompareAndSwap(false, true) {
		return nil
	}
	rt.client.pool.Return(rt.front, true)
	return rt.conn.Close()
}
