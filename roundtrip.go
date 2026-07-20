package domainfront

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

// errH2UpgradeUnsupported is returned when a connection-upgrade request (e.g.
// WebSocket) lands on a front whose ALPN negotiated HTTP/2. h2 has no h1-style
// Upgrade mechanism, so RoundTrip treats this as "wrong front for this request"
// rather than a front failure and retries onto another (ideally http/1.1) front.
var errH2UpgradeUnsupported = errors.New("connection upgrade not supported over HTTP/2 front")

// retryableStatusError signals that a fronted request completed but returned a
// status the client treats as a front failure (see Client.retryableResponse).
// RoundTrip fails the front and retries the request on another one.
type retryableStatusError struct{ status int }

func (e *retryableStatusError) Error() string {
	return fmt.Sprintf("front returned retryable status %d", e.status)
}

// defaultRetryableResponse reports whether a fronted response should be treated
// as a front failure and retried on another front rather than returned to the
// caller. A front (a CDN edge / fronting provider) that connects and completes a
// request but answers 403 or 5xx is very likely rejecting or failing to forward
// the fronted request — when other fronts succeed for the same origin the origin
// isn't the problem — so we fail this front and retry, ideally onto a different
// provider. Callers can override this via WithRetryableResponse.
func defaultRetryableResponse(resp *http.Response) bool {
	return resp.StatusCode == http.StatusForbidden || resp.StatusCode >= 500
}

// roundTripper is an http.RoundTripper that sends requests via domain fronting.
// It takes a front from the pool, checks the provider mapping, dials TLS,
// rewrites the request, and retries on failure.
type roundTripper struct {
	client *Client
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	originHost := req.URL.Hostname()

	// Buffer the body for retries if GetBody is available or body is small enough.
	bodyFactory, err := getBodyFactory(req)
	if err != nil {
		return nil, fmt.Errorf("failed to buffer request body: %w", err)
	}

	// Track which providers we've already attempted this round so retries prefer
	// a different fronting provider — a provider that connects but won't forward
	// (e.g. an edge that answers 403/5xx) is escaped by trying another provider,
	// not just another of its own fronts.
	tried := make(map[string]struct{})
	var lastErr error
	for range rt.client.maxRetries {
		f, err := rt.client.pool.TakePreferringUntried(ctx, tried)
		if err != nil {
			return nil, fmt.Errorf("failed to get front: %w", err)
		}

		provider := rt.client.providerFor(f)
		if provider == nil {
			rt.client.pool.Return(f, true) // not front's fault, requeue
			lastErr = fmt.Errorf("no provider for %s", f.ProviderID)
			continue
		}

		frontedHost := provider.Lookup(originHost)
		if frontedHost == "" {
			rt.client.pool.Return(f, true) // not front's fault, requeue
			lastErr = fmt.Errorf("no domain fronting mapping for '%s' on provider %s", originHost, f.ProviderID)
			continue
		}

		result := dialFront(ctx, f, rt.client.certPool(), rt.client.clientHelloID, rt.client.dialer)
		if result.err != nil {
			// Dial failures should never be treated as successful fronts. The
			// front is removed from rotation (markFailed), so retries naturally
			// move on without needing the provider-diversity hint below — mark
			// tried only once we actually send a request over this provider.
			rt.client.pool.Return(f, false)
			rt.client.notifyCacheDirty()
			lastErr = result.err
			continue
		}

		body, bodyErr := bodyFactory()
		if bodyErr != nil {
			result.conn.Close()
			rt.client.pool.Return(f, true)
			return nil, fmt.Errorf("failed to get request body: %w", bodyErr)
		}

		resp, err := rt.doRequest(req, result.conn, frontedHost, f.ProviderID, body)
		if err != nil {
			// An upgrade landing on an h2 front isn't the front's fault, so
			// requeue it as healthy and retry — ideally onto an http/1.1 front
			// that can carry the upgrade. Leave the provider untried in that case
			// so retries may reuse it for such a front. All other errors fail the
			// front and mark its provider tried so the next retry prefers a
			// different provider (a provider that connects but won't forward is
			// escaped by switching providers, not just fronts).
			isUpgrade := errors.Is(err, errH2UpgradeUnsupported)
			if !isUpgrade {
				tried[f.ProviderID] = struct{}{}
			}
			rt.client.pool.Return(f, isUpgrade)
			rt.client.notifyCacheDirty()
			result.conn.Close()
			lastErr = err
			continue
		}

		rt.client.pool.ReturnSuccess(f)
		rt.client.notifyCacheDirty()
		return resp, nil
	}

	return nil, fmt.Errorf("domain fronting failed after %d attempts: %w", rt.client.maxRetries, lastErr)
}

func (rt *roundTripper) doRequest(req *http.Request, conn net.Conn, frontedHost, providerID string, body io.ReadCloser) (*http.Response, error) {
	fronted := rewriteRequest(req, frontedHost, body)

	// Label which fronting provider carried this request so the origin can
	// attribute fronted traffic per-provider (read server-side from the
	// X-Lantern-Fronted-Via header). Only set it when absent so an
	// edge-injected value (e.g. Akamai's) still takes precedence. Validate the
	// value first: ProviderID comes from config, so a malformed one (control
	// chars/CRLF) must not make the request unwritable or inject a header —
	// skip labeling in that case rather than fail the request.
	if providerID != "" && httpguts.ValidHeaderFieldValue(providerID) &&
		fronted.Header.Get("X-Lantern-Fronted-Via") == "" {
		fronted.Header.Set("X-Lantern-Fronted-Via", providerID)
	}

	// One connection per request, so HTTP/1.1 keep-alives are disabled — unless
	// this is a protocol upgrade (e.g. WebSocket), which needs the connection
	// left intact for hijacking.
	resp, err := sendOverConn(conn, fronted, !hasConnectionUpgrade(req))
	if err != nil {
		return nil, err
	}

	// A front that connects and answers but returns a rejection/failure status
	// (default: 403 or 5xx) is very likely refusing to forward the fronted
	// request rather than the origin failing. Return a retryable error so
	// RoundTrip fails this front and retries on another — ideally from a
	// different provider. Resolve the predicate nil-safely: tests construct a
	// roundTripper with no client.
	retryable := defaultRetryableResponse
	if rt.client != nil && rt.client.retryableResponse != nil {
		retryable = rt.client.retryableResponse
	}
	if retryable(resp) {
		// Just close — don't drain. This transport is one connection per request
		// (h1 keep-alives disabled; h2 conn torn down on body close), so draining
		// buys no connection reuse and a huge or never-ending error body could
		// stall the retry.
		resp.Body.Close()
		return nil, &retryableStatusError{status: resp.StatusCode}
	}

	return resp, nil
}

// sendOverConn sends req over the already-established TLS conn, framing it to
// match the protocol negotiated via ALPN: HTTP/2 when the edge selected "h2"
// (CloudFront, Aliyun, ...), HTTP/1.1 otherwise. Every caller that speaks over
// a dialed front — request round-trips and front vetting alike — must go
// through here so the wire framing stays consistent with the negotiated ALPN;
// unconditionally speaking HTTP/1.1 over an h2 connection yields a "malformed
// HTTP response" on the first h2 frame.
func sendOverConn(conn net.Conn, req *http.Request, disableKeepAlives bool) (*http.Response, error) {
	if negotiatedProtocol(conn) == "h2" {
		// An h1-style upgrade can't be carried over h2 (it needs Extended
		// CONNECT, which this single-shot transport doesn't set up), and
		// x/net/http2 rejects the Upgrade header outright. Signal it so
		// RoundTrip can retry onto an http/1.1 front instead of silently
		// degrading the upgrade to a plain request.
		if hasConnectionUpgrade(req) {
			return nil, errH2UpgradeUnsupported
		}
		// Strip the connection-specific headers HTTP/2 forbids (RFC 7540
		// §8.1.2.2). x/net/http2 errors on e.g. Transfer-Encoding or a
		// Connection token other than close/keep-alive, so they must be removed
		// before framing — they're meaningless on a multiplexed h2 stream anyway.
		stripConnHeaders(req)
		// Restore "https" so the :scheme/:authority pseudo-headers match what a
		// browser sends over TLS; roundTripH2 frames over the existing conn.
		req.URL.Scheme = "https"
		return roundTripH2(conn, req)
	}
	// TLS is already established on conn, so "http" avoids a second handshake.
	req.URL.Scheme = "http"
	return newConnTransport(conn, disableKeepAlives).RoundTrip(req)
}

// negotiatedProtocol reports the ALPN protocol settled during the TLS
// handshake ("h2", "http/1.1", or "" when none was negotiated). In production
// conn is always the utls client connection from dialFront.
func negotiatedProtocol(conn net.Conn) string {
	if c, ok := conn.(*utls.UConn); ok {
		return c.ConnectionState().NegotiatedProtocol
	}
	return ""
}

// hasConnectionUpgrade reports whether the request's Connection header lists an
// "upgrade" token. Connection is a comma-separated token list, so a plain
// equality check would miss common values like "keep-alive, Upgrade".
func hasConnectionUpgrade(req *http.Request) bool {
	for _, v := range req.Header.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// stripConnHeaders removes the connection-specific header fields HTTP/2 forbids
// (RFC 7540 §8.1.2.2). Any field named in the Connection header is itself
// connection-specific and removed too. Without this, x/net/http2 rejects a
// request carrying e.g. Transfer-Encoding or a non-close/keep-alive Connection
// token. It mutates req's headers in place; both callers pass a request they
// own (doRequest the fronted copy from rewriteRequest, verifyWithPost a freshly
// built vetting request), so no shared or caller-owned request is affected.
func stripConnHeaders(req *http.Request) {
	for _, v := range req.Header.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			if name := strings.TrimSpace(tok); name != "" {
				req.Header.Del(name)
			}
		}
	}
	for _, h := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade"} {
		req.Header.Del(h)
	}
}

// roundTripH2 sends req over conn using HTTP/2 framing. The library dials a
// fresh connection per request and never reuses it, so the h2 ClientConn is
// single-shot: closing the response body tears down the connection (and the
// frame-reader goroutine) instead of leaving it for h2's idle pool.
func roundTripH2(conn net.Conn, req *http.Request) (*http.Response, error) {
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		cc.Close()
		return nil, err
	}
	resp.Body = &h2Body{ReadCloser: resp.Body, cc: cc}
	return resp, nil
}

// h2Body closes the underlying HTTP/2 connection when the response body is
// closed, since each connection serves exactly one request. cc is an io.Closer
// (a *http2.ClientConn in practice) so the teardown logic stays unit-testable.
type h2Body struct {
	io.ReadCloser
	cc   io.Closer
	once sync.Once
}

func (b *h2Body) Close() error {
	bodyErr := b.ReadCloser.Close()
	var ccErr error
	b.once.Do(func() { ccErr = b.cc.Close() })
	if bodyErr != nil {
		return bodyErr
	}
	return ccErr
}

// newConnTransport creates an http.RoundTripper that sends requests over a
// pre-established connection. The request URL scheme must already be "http"
// (set by rewriteRequest) since TLS is already established.
func newConnTransport(conn net.Conn, disableKeepAlives bool) http.RoundTripper {
	return &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		TLSHandshakeTimeout: 20 * time.Second,
		DisableKeepAlives:   disableKeepAlives,
		IdleConnTimeout:     70 * time.Second,
	}
}

// rewriteRequest creates a domain-fronted copy of req.
// It builds the URL directly (no string→parse round-trip) and shares header
// value slices with the original request to avoid per-header allocations.
// The scheme is set to "http" since TLS is already established on the
// underlying connection, eliminating the need for a separate schemeRewriter.
func rewriteRequest(req *http.Request, frontedHost string, body io.ReadCloser) *http.Request {
	// Shallow-copy the URL, override host and scheme.
	u := *req.URL
	u.Host = frontedHost
	u.Scheme = "http" // TLS already established; avoids double-wrap

	// Build the request struct, then attach the caller's context.
	// WithContext returns a shallow copy with the context set — this is the
	// only way to set the unexported ctx field on http.Request.
	r := (&http.Request{
		Method:        req.Method,
		URL:           &u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          body,
		ContentLength: req.ContentLength,
		Header:        make(http.Header, len(req.Header)),
	}).WithContext(req.Context())

	// Clone header value slices to decouple from the caller's request.
	// Sharing slices can cause data races if the original request is reused.
	for k, vs := range req.Header {
		if !strings.EqualFold(k, "Host") {
			cp := make([]string, len(vs))
			copy(cp, vs)
			r.Header[k] = cp
		}
	}
	return r
}

// getBodyFactory returns a function that produces a fresh body reader for each
// retry attempt. If the request has GetBody, it uses that. If the body is nil,
// it returns a nil-body factory. Otherwise, it buffers the body once.
func getBodyFactory(req *http.Request) (func() (io.ReadCloser, error), error) {
	if req.Body == nil {
		return func() (io.ReadCloser, error) { return nil, nil }, nil
	}
	if req.GetBody != nil {
		return req.GetBody, nil
	}
	// Buffer the body for retries
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}, nil
}
