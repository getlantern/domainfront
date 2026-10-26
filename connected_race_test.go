package domainfront

import (
	"context"
	"crypto/x509"
	"io"
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
