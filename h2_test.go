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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
	return uconn
}

// TestDoRequest_HTTP2 verifies that when the TLS handshake negotiates h2,
// doRequest frames the fronted request as HTTP/2 and the fronted host lands in
// the :authority pseudo-header (the h2 equivalent of the Host header that drives
// CDN routing).
func TestDoRequest_HTTP2(t *testing.T) {
	type observed struct {
		authority, path, hdr string
		proto                int
	}
	seen := make(chan observed, 1)
	conn := dialPipeH2(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.URL.Path, r.Header.Get("X-Probe"), r.ProtoMajor}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "h2-fronted-ok")
	}))

	req, err := http.NewRequest(http.MethodGet, "https://config.example.com/api/data", nil)
	require.NoError(t, err)
	req.Header.Set("X-Probe", "carried")

	resp, err := (&roundTripper{}).doRequest(req, conn, "cdn.example.com", nil)
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
