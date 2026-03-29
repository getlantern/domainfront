package domainfront

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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

	var lastErr error
	for range rt.client.maxRetries {
		f, err := rt.client.pool.Take(ctx)
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
			// Dial failures should never be treated as successful fronts.
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

		resp, err := rt.doRequest(req, result.conn, frontedHost, body)
		if err != nil {
			rt.client.pool.Return(f, false)
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

func (rt *roundTripper) doRequest(req *http.Request, conn net.Conn, frontedHost string, body io.ReadCloser) (*http.Response, error) {
	fronted := rewriteRequest(req, frontedHost, body)

	disableKeepAlives := true
	if strings.EqualFold(req.Header.Get("Connection"), "upgrade") {
		disableKeepAlives = false
	}

	tr := newConnTransport(conn, disableKeepAlives)
	resp, err := tr.RoundTrip(fronted)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 403 {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("CDN rejected request (403)")
	}

	return resp, nil
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
