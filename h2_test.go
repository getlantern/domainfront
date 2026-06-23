package domainfront

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// TestDoRequest_HTTP2 verifies that when the TLS handshake negotiates h2,
// doRequest frames the fronted request as HTTP/2 and the fronted host lands in
// the :authority pseudo-header (the h2 equivalent of the Host header that drives
// CDN routing). It uses a pipe-backed h2 server, so no real network is touched.
func TestDoRequest_HTTP2(t *testing.T) {
	ca, caKey := newTestCA(t)
	leaf := newTestLeafCert(t, ca, caKey, "cdn.example.com")
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	type observed struct {
		authority string
		path      string
		proto     int
		hdr       string
	}
	seen := make(chan observed, 1)

	clientRaw, serverRaw := net.Pipe()
	go func() {
		srv := stdtls.Server(serverRaw, &stdtls.Config{
			Certificates: []stdtls.Certificate{leaf},
			NextProtos:   []string{"h2"},
		})
		if err := srv.Handshake(); err != nil {
			serverRaw.Close()
			return
		}
		(&http2.Server{}).ServeConn(srv, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- observed{r.Host, r.URL.Path, r.ProtoMajor, r.Header.Get("X-Probe")}
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, "h2-fronted-ok")
			}),
		})
	}()

	uconn := utls.UClient(clientRaw, &utls.Config{
		RootCAs:    roots,
		ServerName: "cdn.example.com",
		NextProtos: []string{"h2"},
	}, utls.HelloGolang)
	require.NoError(t, uconn.Handshake())
	require.Equal(t, "h2", negotiatedProtocol(uconn), "handshake should negotiate h2")

	req, err := http.NewRequest(http.MethodGet, "https://config.example.com/api/data", nil)
	require.NoError(t, err)
	req.Header.Set("X-Probe", "carried")

	resp, err := (&roundTripper{}).doRequest(req, uconn, "cdn.example.com", nil)
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
