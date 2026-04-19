package domainfront

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

// NewConnectedRoundTripper returns an http.RoundTripper whose underlying TLS
// connection to a working front is already established. Blocks until a front
// is dialed or ctx is cancelled, so callers that race multiple transports can
// see the connection ready/fail signal on the actual wire, not on a cached
// wrapper.
//
// The returned value is also an io.Closer. Callers that obtain a connected
// RT they end up not using (e.g. a lost race) should call Close() so the
// front is returned to the pool and the TLS connection is released instead
// of leaking until GC.
//
// The returned RoundTripper is single-use: after RoundTrip is called once,
// subsequent RoundTrip calls return ErrRoundTripperUsed. addr is accepted for
// parity with other "connect to addr" transports but is ignored — the front
// (and therefore the dialed destination) is chosen by the pool.
func (c *Client) NewConnectedRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error) {
	var lastErr error
	for i := 0; i < c.maxRetries; i++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("ctx done after %d dial attempts (last err: %w): %w", i, lastErr, err)
			}
			return nil, err
		}
		f, err := c.pool.Take(ctx)
		if err != nil {
			lastErr = fmt.Errorf("take front: %w", err)
			return nil, lastErr
		}

		provider := c.providerFor(f)
		if provider == nil {
			c.pool.Return(f, true)
			lastErr = fmt.Errorf("no provider for front %s/%s", f.ProviderID, f.Domain)
			continue
		}

		result := dialFront(ctx, f, c.certPool(), c.clientHelloID, c.dialer)
		if result.err != nil {
			c.pool.Return(f, false)
			c.notifyCacheDirty()
			lastErr = fmt.Errorf("dial front %s: %w", f.Domain, result.err)
			continue
		}

		return &connectedRoundTripper{
			client:   c,
			front:    f,
			provider: provider,
			conn:     result.conn,
		}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("could not connect to any front after %d attempts: %w", c.maxRetries, lastErr)
	}
	return nil, fmt.Errorf("could not connect to any front after %d attempts", c.maxRetries)
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
	resp, err := inner.doRequest(req, rt.conn, frontedHost, body)
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
