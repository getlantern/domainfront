package domainfront

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPeerCertificate(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert := newTestLeafCert(t, caCert, caKey, "test.example.com", "*.example.com")

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	leafDER := leafCert.Certificate[0]
	caDER := caCert.Raw

	t.Run("valid cert", func(t *testing.T) {
		err := verifyPeerCertificate([][]byte{leafDER, caDER}, roots, "test.example.com")
		assert.NoError(t, err)
	})

	t.Run("wrong domain", func(t *testing.T) {
		err := verifyPeerCertificate([][]byte{leafDER, caDER}, roots, "wrong.example.org")
		assert.Error(t, err)
	})

	t.Run("empty domain accepts any", func(t *testing.T) {
		err := verifyPeerCertificate([][]byte{leafDER, caDER}, roots, "")
		assert.NoError(t, err)
	})

	t.Run("no certs", func(t *testing.T) {
		err := verifyPeerCertificate([][]byte{}, roots, "test.example.com")
		assert.Error(t, err)
	})
}

func TestDialFront_WithMockServer(t *testing.T) {
	caCert, caKey := newTestCA(t)

	// Need a leaf cert with specific domains for the pipe dialer test
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cdn.example.com"},
		DNSNames:     []string{"cdn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCertParsed, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	serverTLSConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{{
			Certificate: [][]byte{leafDER, caCert.Raw},
			PrivateKey:  leafKey,
			Leaf:        leafCertParsed,
		}},
	}

	pd := &pipeDialer{serverConfig: serverTLSConfig}

	vh := "cdn.example.com"
	f := newFront(&Masquerade{
		Domain:         "cdn.example.com",
		IpAddress:      "cdn.example.com:443",
		SNI:            "cdn.example.com",
		VerifyHostname: &vh,
	}, "test")

	result := dialFront(t.Context(), f, roots, utlsHelloGolang(), pd)
	require.NoError(t, result.err, "should connect to test TLS server")
	result.conn.Close()
}

// pipeDialer creates a net.Pipe and runs a standard TLS server on one end.
type pipeDialer struct {
	serverConfig *stdtls.Config
}

func (pd *pipeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		tlsConn := stdtls.Server(serverConn, pd.serverConfig)
		if err := tlsConn.Handshake(); err != nil {
			serverConn.Close()
			return
		}
		buf := make([]byte, 1)
		tlsConn.Read(buf)
		tlsConn.Close()
	}()
	return clientConn, nil
}

func TestClassifyError(t *testing.T) {
	assert.True(t, classifyError(net.UnknownNetworkError("timeout")))
	assert.False(t, classifyError(net.UnknownNetworkError("certificate invalid")))
	assert.False(t, classifyError(net.UnknownNetworkError("handshake failure")))
}
