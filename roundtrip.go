package domainfront

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

		resp, err := rt.doRequest(req, result.conn, frontedHost, originHost, body)
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

func (rt *roundTripper) doRequest(req *http.Request, conn net.Conn, frontedHost, originHost string, body io.ReadCloser) (*http.Response, error) {
	fronted, err := rewriteRequest(req, frontedHost, originHost, body)
	if err != nil {
		return nil, err
	}

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
// pre-established connection, rewriting https:// to http://.
func newConnTransport(conn net.Conn, disableKeepAlives bool) http.RoundTripper {
	return &schemeRewriter{
		Transport: http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSHandshakeTimeout: 20 * time.Second,
			DisableKeepAlives:   disableKeepAlives,
			IdleConnTimeout:     70 * time.Second,
		},
	}
}

// schemeRewriter rewrites https:// to http:// since TLS is already established.
type schemeRewriter struct {
	http.Transport
}

func (sr *schemeRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	norm := new(http.Request)
	*norm = *req
	norm.URL = new(url.URL)
	*norm.URL = *req.URL
	norm.URL.Scheme = "http"
	return sr.Transport.RoundTrip(norm)
}

func rewriteRequest(req *http.Request, frontedHost, originHost string, body io.ReadCloser) (*http.Request, error) {
	urlCopy := *req.URL
	urlCopy.Host = frontedHost
	r, err := http.NewRequestWithContext(req.Context(), req.Method, urlCopy.String(), body)
	if err != nil {
		return nil, err
	}
	// Set Host header to the original origin so the CDN routes to the
	// correct backend. The URL.Host is the fronted domain for the TLS
	// connection, but Host header must carry the real destination.
	r.Host = originHost
	r.ContentLength = req.ContentLength
	for k, vs := range req.Header {
		if !strings.EqualFold(k, "Host") {
			v := make([]string, len(vs))
			copy(v, vs)
			r.Header[k] = v
		}
	}
	return r, nil
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
