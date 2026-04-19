package domainfront

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

// NewConnectedRoundTripper returns an http.RoundTripper whose underlying TLS
// connection to a working front is already established. Blocks until a front
// is dialed or ctx is cancelled, so callers that race multiple transports can
// see the connection ready/fail signal on the actual wire, not on a cached
// wrapper.
//
// The returned RoundTripper is one-shot: it is bound to one front, one
// provider's host mapping, and one TLS connection. A subsequent call should
// request a new connected RoundTripper. addr is accepted for parity with
// other "connect to addr" transports but is ignored — the front (and
// therefore the dialed destination) is chosen by the pool.
func (c *Client) NewConnectedRoundTripper(ctx context.Context, addr string) (http.RoundTripper, error) {
	for range c.maxRetries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := c.pool.Take(ctx)
		if err != nil {
			return nil, fmt.Errorf("take front: %w", err)
		}

		provider := c.providerFor(f)
		if provider == nil {
			c.pool.Return(f, true)
			continue
		}

		result := dialFront(ctx, f, c.certPool(), c.clientHelloID, c.dialer)
		if result.err != nil {
			c.pool.Return(f, false)
			c.notifyCacheDirty()
			continue
		}

		return &connectedRoundTripper{
			client:   c,
			front:    f,
			provider: provider,
			conn:     result.conn,
		}, nil
	}
	return nil, errors.New("could not connect to any front")
}

// connectedRoundTripper is a single-use http.RoundTripper bound to a
// pre-dialed TLS connection. Reusing it is not supported — a new connected
// RT should be obtained for each request.
type connectedRoundTripper struct {
	client   *Client
	front    *front
	provider *Provider
	conn     net.Conn
}

func (rt *connectedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	originHost := req.URL.Hostname()
	frontedHost := rt.provider.Lookup(originHost)
	if frontedHost == "" {
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
