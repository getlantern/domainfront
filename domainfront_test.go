package domainfront

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockCDN(t *testing.T, tlsCert stdtls.Certificate) (addr string, cleanup func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fronted", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "hello from CDN")
	})

	listener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{tlsCert},
	})
	require.NoError(t, err)

	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	return listener.Addr().String(), func() {
		server.Close()
	}
}

func TestClient_New(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert := newTestLeafCert(t, caCert, caKey, "cdn.example.com")
	addr, cleanup := mockCDN(t, leafCert)
	defer cleanup()

	_, port, _ := net.SplitHostPort(addr)

	config := &Config{
		TrustedCAs: []*CA{{CommonName: "Test CA", Cert: string(pemEncodeCert(caCert))}},
		Providers: map[string]*Provider{
			"testprovider": {
				HostAliases: map[string]string{
					"origin.example.com": "cdn.example.com",
				},
				TestURL: fmt.Sprintf("https://cdn.example.com:%s/ping", port),
				Masquerades: []*Masquerade{
					{Domain: "cdn.example.com", IpAddress: "127.0.0.1:" + port},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, config,
		WithClientHelloID(utlsHelloGolang()),
		WithMaxRetries(3),
		WithCrawlerConcurrency(2),
	)
	require.NoError(t, err)
	defer client.Close()

	// Wait for crawler to find working fronts
	require.Eventually(t, func() bool {
		return client.pool.readyCount() > 0
	}, 10*time.Second, 100*time.Millisecond, "should find working fronts")

	// Test RoundTripper
	rt := client.RoundTripper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://origin.example.com/hello", nil)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "hello from CDN")
}

func TestClient_NoProvider(t *testing.T) {
	config := &Config{
		Providers: map[string]*Provider{
			"test": {
				HostAliases: map[string]string{"a.com": "b.com"},
				Masquerades: []*Masquerade{{Domain: "cdn.com", IpAddress: "1.2.3.4"}},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := New(ctx, config)
	require.NoError(t, err)
	defer client.Close()

	// Request for unmapped host should fail after retries
	rt := client.RoundTripper()

	// Add a ready front manually to avoid blocking on Take
	fronts := client.pool.candidates()
	if len(fronts) > 0 {
		client.pool.addReady(fronts[0])
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, 2*time.Second)
	defer reqCancel()

	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://unmapped.example.com/", nil)
	_, err = rt.RoundTrip(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no domain fronting mapping")
}

func TestClient_Close(t *testing.T) {
	config := &Config{
		Providers: map[string]*Provider{
			"test": {
				HostAliases: map[string]string{"a.com": "b.com"},
				Masquerades: []*Masquerade{{Domain: "cdn.com", IpAddress: "1.2.3.4"}},
			},
		},
	}

	ctx := context.Background()
	client, err := New(ctx, config)
	require.NoError(t, err)

	// Close should not hang
	done := make(chan struct{})
	go func() {
		client.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() timed out")
	}
}
