package domainfront

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// dialPipeH2 stands up an HTTP/2 server on one end of a net.Pipe (TLS with
// ALPN "h2") and returns a handshaken utls client connection to it — the same
// connection type dialFront produces in production. No real network is used.
func dialPipeH2(t *testing.T, handler http.Handler) *utls.UConn {
	t.Helper()
	ca, caKey := newTestCA(t)
	leaf := newTestLeafCert(t, ca, caKey, "cdn.example.com")
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// Bound both handshakes so a broken pairing fails fast on the deadline
	// rather than hanging until the `go test` timeout. net.Pipe honors
	// deadlines, so HandshakeContext can interrupt a stalled handshake.
	// Cancel at test end (not on return): the returned conn is used after this
	// helper returns, and cancelling the handshake context while the conn is
	// still in use poisons it (sets a past deadline) on some Go versions.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	clientRaw, serverRaw := net.Pipe()
	go func() {
		srv := stdtls.Server(serverRaw, &stdtls.Config{
			Certificates: []stdtls.Certificate{leaf},
			NextProtos:   []string{"h2"},
		})
		if err := srv.HandshakeContext(ctx); err != nil {
			serverRaw.Close()
			return
		}
		(&http2.Server{}).ServeConn(srv, &http2.ServeConnOpts{Handler: handler})
	}()

	uconn := utls.UClient(clientRaw, &utls.Config{
		RootCAs:    roots,
		ServerName: "cdn.example.com",
		NextProtos: []string{"h2"},
	}, utls.HelloGolang)
	require.NoError(t, uconn.HandshakeContext(ctx))
	require.Equal(t, "h2", negotiatedProtocol(uconn), "handshake should negotiate h2")
	// Close the conn at test end so the server goroutine's ServeConn unblocks
	// (it otherwise reads the pipe until close). Tests that complete a request
	// already tear the conn down via resp.Body.Close; this also covers tests
	// that never send one (e.g. an upgrade rejected before any round-trip).
	t.Cleanup(func() { _ = uconn.Close(); _ = serverRaw.Close() })
	return uconn
}

// TestDoRequest_HTTP2 verifies that when the TLS handshake negotiates h2,
// doRequest frames the fronted request as HTTP/2 and the fronted host lands in
// the :authority pseudo-header (the h2 equivalent of the Host header that drives
// CDN routing).
func TestDoRequest_HTTP2(t *testing.T) {
	type observed struct {
		authority, path, hdr, frontedVia string
		proto                            int
	}
	seen := make(chan observed, 1)
	conn := dialPipeH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.URL.Path, r.Header.Get("X-Probe"), r.Header.Get("X-Lantern-Fronted-Via"), r.ProtoMajor}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "h2-fronted-ok")
	}))

	req, err := http.NewRequest(http.MethodGet, "https://config.example.com/api/data", nil)
	require.NoError(t, err)
	req.Header.Set("X-Probe", "carried")

	resp, err := (&roundTripper{}).doRequest(req, conn, "cdn.example.com", "cloudfront", nil)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close()) // tears down the h2 conn

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor, "response should be HTTP/2")
	assert.Equal(t, "h2-fronted-ok", string(body))

	got := <-seen
	assert.Equal(t, "cdn.example.com", got.authority, ":authority must be the fronted host, not the origin")
	assert.Equal(t, "/api/data", got.path, "path must be preserved from the original request")
	assert.Equal(t, 2, got.proto, "server must see an HTTP/2 request")
	assert.Equal(t, "carried", got.hdr, "caller headers must propagate")
	assert.Equal(t, "cloudfront", got.frontedVia, "provider must be labeled to the origin via X-Lantern-Fronted-Via")
}

// TestVerifyWithPost_HTTP2 covers the front-vetting path over an h2 connection.
// Vetting gates whether a front becomes usable, so it must speak h2 just like
// request traffic — otherwise every h2 edge (CloudFront, Aliyun) fails to vet.
func TestVerifyWithPost_HTTP2(t *testing.T) {
	gotMethod := make(chan string, 1)
	conn := dialPipeH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod <- r.Method
		w.WriteHeader(http.StatusAccepted) // 202: the contract verifyWithPost checks
	}))

	c := &Client{log: slog.Default()}
	ok := c.verifyWithPost(conn, "https://cdn.example.com/ping")

	assert.True(t, ok, "a 202 over h2 should vet successfully")
	assert.Equal(t, http.MethodPost, <-gotMethod)
}

// TestStripConnHeaders verifies the RFC 7540 §8.1.2.2 transformation: the
// connection-specific headers and any header named in Connection are removed,
// while ordinary headers are preserved.
func TestStripConnHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://x/y", nil)
	require.NoError(t, err)
	req.Header.Set("Connection", "keep-alive, X-Hop")
	req.Header.Set("X-Hop", "drop") // named in Connection
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("X-Keep", "stay")

	stripConnHeaders(req)

	for _, h := range []string{"Connection", "X-Hop", "Keep-Alive", "Transfer-Encoding", "Upgrade"} {
		assert.Emptyf(t, req.Header.Get(h), "%s must be stripped", h)
	}
	assert.Equal(t, "stay", req.Header.Get("X-Keep"), "non-connection headers must remain")
}

// TestSendOverConn_H2_RejectsUpgrade verifies an upgrade request over an h2
// front is rejected with errH2UpgradeUnsupported (so RoundTrip can retry onto
// an http/1.1 front) and never reaches the server.
func TestSendOverConn_H2_RejectsUpgrade(t *testing.T) {
	reached := make(chan struct{}, 1)
	conn := dialPipeH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	req, err := http.NewRequest(http.MethodGet, "https://cdn.example.com/ws", nil)
	require.NoError(t, err)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	_, err = sendOverConn(conn, req, false)
	require.ErrorIs(t, err, errH2UpgradeUnsupported)
	select {
	case <-reached:
		t.Fatal("server must not be reached for an upgrade rejected over h2")
	default:
	}
}

// TestSendOverConn_H2_StripsForbiddenHeaders verifies that connection-specific
// headers (which x/net/http2 would otherwise reject) are stripped before h2
// framing, so an otherwise-valid request still succeeds.
func TestSendOverConn_H2_StripsForbiddenHeaders(t *testing.T) {
	gotHop := make(chan string, 1)
	conn := dialPipeH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHop <- r.Header.Get("X-Hop")
		w.WriteHeader(http.StatusOK)
	}))
	req, err := http.NewRequest(http.MethodGet, "https://cdn.example.com/x", nil)
	require.NoError(t, err)
	// Transfer-Encoding: gzip and a non-close/keep-alive Connection token both
	// make x/net/http2 reject the request unless stripped first.
	req.Header.Set("Transfer-Encoding", "gzip")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "should-be-stripped")

	resp, err := sendOverConn(conn, req, true)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, <-gotHop, "Connection-named header must be stripped before h2")
}

// errCloser is a test io.Closer that records call count and returns a fixed err.
type errCloser struct {
	err   error
	calls int
}

func (c *errCloser) Close() error { c.calls++; return c.err }

// TestH2Body_Close covers the connection-teardown semantics: the underlying h2
// connection is closed exactly once, its error surfaces when the body close
// itself succeeds, and a body-close error takes precedence.
func TestH2Body_Close(t *testing.T) {
	t.Run("propagates cc error when body close ok", func(t *testing.T) {
		cc := &errCloser{err: assert.AnError}
		b := &h2Body{ReadCloser: io.NopCloser(nil), cc: cc}
		assert.Equal(t, assert.AnError, b.Close())
		assert.Equal(t, 1, cc.calls)
	})

	t.Run("body error takes precedence over cc error", func(t *testing.T) {
		bodyErr := errors.New("body boom")
		cc := &errCloser{err: assert.AnError}
		b := &h2Body{ReadCloser: errReadCloser{bodyErr}, cc: cc}
		assert.Equal(t, bodyErr, b.Close())
		assert.Equal(t, 1, cc.calls, "cc still closed even when body close fails")
	})

	t.Run("closes the connection only once", func(t *testing.T) {
		cc := &errCloser{}
		b := &h2Body{ReadCloser: io.NopCloser(nil), cc: cc}
		assert.NoError(t, b.Close())
		assert.NoError(t, b.Close())
		assert.Equal(t, 1, cc.calls)
	})
}

type errReadCloser struct{ err error }

func (e errReadCloser) Read([]byte) (int, error) { return 0, e.err }
func (e errReadCloser) Close() error             { return e.err }

func TestHasConnectionUpgrade(t *testing.T) {
	mk := func(vals ...string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "https://x/", nil)
		for _, v := range vals {
			r.Header.Add("Connection", v)
		}
		return r
	}
	assert.True(t, hasConnectionUpgrade(mk("upgrade")))
	assert.True(t, hasConnectionUpgrade(mk("keep-alive, Upgrade")), "token in a comma list")
	assert.True(t, hasConnectionUpgrade(mk("keep-alive", "Upgrade")), "multiple header values")
	assert.False(t, hasConnectionUpgrade(mk("keep-alive")))
	assert.False(t, hasConnectionUpgrade(mk()))
}
