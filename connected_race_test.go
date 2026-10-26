package domainfront

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRaceClient returns a Client for providers whose ready queue holds exactly
// the fronts the test adds, with no crawler running.
func newRaceClient(t *testing.T, caCert *x509.Certificate, providers map[string]*Provider) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &Client{
		ctx:           ctx,
		cancel:        cancel,
		log:           slog.Default(),
		pool:          newFrontPool(16),
		maxRetries:    2,
		cacheDirty:    make(chan struct{}, 1),
		providers:     providers,
		gate:          newPauseGate(),
		dialer:        NetDialer{},
		clientHelloID: utlsHelloGolang(),
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	c.certPoolValue.Store(roots)
	return c
}

func cdnFront(provider, addr string) *front {
	return newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: addr}, provider)
}

// pingURL is mockCDN's vetting endpoint, which answers a POST with 202.
const pingURL = "https://cdn.example.com/ping"

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// A front of a provider with no mapping for the host can connect but never
// carry the request, so connecting must skip it rather than hand it back.
func TestNewConnectedRoundTripper_SkipsProvidersWithoutMapping(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"nomap":  {HostAliases: map[string]string{"other.example.com": "cdn.example.com"}},
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}},
	})
	c.pool.addReady(cdnFront("nomap", addr)) // first in line
	c.pool.addReady(cdnFront("mapped", addr))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.NoError(t, err)
	assert.Equal(t, "mapped", rt.(*connectedRoundTripper).front.ProviderID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://origin.example.com/hello", nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "hello from CDN")
}

func TestNewConnectedRoundTripper_FailsAtOnceWhenNoProviderMapsTheHost(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"nomap": {HostAliases: map[string]string{"other.example.com": "cdn.example.com"}},
	})
	c.pool.addReady(cdnFront("nomap", addr))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no domain fronting mapping for 'origin.example.com'")
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, 1, c.pool.readyCount(), "the unmapped provider's front stays ready")
}

// Every mapped provider races: one whose fronts fail to dial, or that has no
// ready front at all, doesn't stop another from connecting.
func TestNewConnectedRoundTripper_RacesEveryMappedProvider(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	mapping := map[string]string{"origin.example.com": "cdn.example.com"}
	c := newRaceClient(t, caCert, map[string]*Provider{
		"dead":  {HostAliases: mapping},
		"empty": {HostAliases: mapping},
		"live":  {HostAliases: mapping},
	})
	c.pool.addReady(cdnFront("dead", closedAddr(t)))
	c.pool.addReady(cdnFront("dead", closedAddr(t)))
	c.pool.addReady(cdnFront("live", addr))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.NoError(t, err)
	assert.Equal(t, "live", rt.(*connectedRoundTripper).front.ProviderID)
	require.NoError(t, rt.(*connectedRoundTripper).Close())
}

// The crawler stops once enough fronts are ready in total, so every ready
// front can belong to providers that can't serve the host. A provider with
// none ready must still be tried, through the fronts the crawler hasn't vetted.
func TestNewConnectedRoundTripper_DialsUnvettedFrontsWhenNoneReady(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"nomap":  {HostAliases: map[string]string{"other.example.com": "cdn.example.com"}},
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}, TestURL: pingURL},
	})
	unvetted := cdnFront("mapped", addr)
	c.pool.Replace([]*front{unvetted, cdnFront("nomap", addr), cdnFront("nomap", addr)})
	c.pool.addReady(cdnFront("nomap", addr))
	c.pool.addReady(cdnFront("nomap", addr))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	rt, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.NoError(t, err)
	assert.Same(t, unvetted, rt.(*connectedRoundTripper).front)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, 2, c.pool.readyCount(), "the other provider's ready fronts stay ready")
	require.NoError(t, rt.(*connectedRoundTripper).Close())
}

// A ready front that fails to dial is still among the provider's fronts, so
// falling back to them must not dial it again and spend the last attempt.
func TestNewConnectedRoundTripper_DoesNotRedialAFailedFront(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	for range 20 {
		c := newRaceClient(t, caCert, map[string]*Provider{
			"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}, TestURL: pingURL},
		})
		dead, live := cdnFront("mapped", closedAddr(t)), cdnFront("mapped", addr)
		c.pool.Replace([]*front{dead, live})
		c.pool.addReady(dead)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rt, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
		cancel()
		require.NoError(t, err)
		require.Same(t, live, rt.(*connectedRoundTripper).front)
		require.NoError(t, rt.(*connectedRoundTripper).Close())
	}
}

// A front can complete TLS yet refuse to forward, which is what the crawler's
// vetting catches. A front the lane dials without the crawler must pass the
// same check before it can win, since the request it carries has no retry.
func TestNewConnectedRoundTripper_VetsUnvettedFronts(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		// mockCDN answers this POST with 200, not the 202 vetting expects.
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}, TestURL: "https://cdn.example.com/refused"},
	})
	rejected := cdnFront("mapped", addr)
	rejected.markSucceeded()
	c.pool.Replace([]*front{rejected})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.ErrorContains(t, err, "failed vetting")
	assert.False(t, rejected.isSucceeding())
}

// Vetting sends a request the caller can't cancel directly, so cancelling
// the race must still stop a lane stuck waiting on the vetting response.
func TestNewConnectedRoundTripper_CancelStopsVetting(t *testing.T) {
	caCert, caKey := newTestCA(t)
	hung := make(chan struct{})
	defer close(hung)
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{newTestLeafCert(t, caCert, caKey, "cdn.example.com")},
	})
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hung })}
	go srv.Serve(ln)
	defer srv.Close()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}, TestURL: pingURL},
	})
	c.pool.Replace([]*front{cdnFront("mapped", ln.Addr().String())})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

// The TLS handshake runs on a fixed deadline rather than ctx, so the caller
// must not wait for a lane stuck in one once ctx ends.
func TestNewConnectedRoundTripper_CancelDoesNotWaitForHandshake(t *testing.T) {
	caCert, _ := newTestCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept, then never answer the ClientHello.
			t.Cleanup(func() { conn.Close() })
		}
	}()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}},
	})
	c.pool.addReady(cdnFront("mapped", ln.Addr().String()))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.NewConnectedRoundTripper(ctx, "origin.example.com:443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}

// A config update can drop a provider's mapping after the race picks it. The
// lane must stop rather than connect a front that can't carry the request.
func TestConnectVia_StopsWhenTheMappingIsGone(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"mapped": {HostAliases: map[string]string{"other.example.com": "cdn.example.com"}},
	})
	c.pool.addReady(cdnFront("mapped", addr))

	r := c.connectVia(context.Background(), "mapped", "origin.example.com")
	require.ErrorContains(t, r.err, "no longer maps")
	assert.Nil(t, r.rt)
	assert.Equal(t, 1, c.pool.readyCount(), "the front goes back to the pool")
}

// Without a test URL a fallback front can't be vetted, which is no fault of
// the front: it must not be marked failed.
func TestNewConnectedRoundTripper_NoTestURLLeavesFrontsAlone(t *testing.T) {
	caCert, caKey := newTestCA(t)
	addr, cleanup := mockCDN(t, newTestLeafCert(t, caCert, caKey, "cdn.example.com"))
	defer cleanup()

	c := newRaceClient(t, caCert, map[string]*Provider{
		"mapped": {HostAliases: map[string]string{"origin.example.com": "cdn.example.com"}},
	})
	f := cdnFront("mapped", addr)
	f.markSucceeded()
	c.pool.Replace([]*front{f})

	_, err := c.NewConnectedRoundTripper(context.Background(), "origin.example.com:443")
	require.ErrorContains(t, err, "no test URL")
	assert.True(t, f.isSucceeding())
}
