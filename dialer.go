package domainfront

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	tls "github.com/refraction-networking/utls"
)

const dialTimeout = 5 * time.Second

// Dialer abstracts TCP dialing for testability.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// NetDialer is the default TCP dialer.
type NetDialer struct{}

func (NetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// dialResult is the outcome of dialing a front.
type dialResult struct {
	conn      net.Conn
	retriable bool
	err       error
}

// dialFront performs a TLS connection to the given front.
// Builds the tls.Config in a single allocation (no Clone).
func dialFront(ctx context.Context, f *front, rootCAs *x509.CertPool, clientHelloID tls.ClientHelloID, dialer Dialer) dialResult {
	addr := f.IpAddress
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	defer dialCancel()

	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return dialResult{nil, classifyError(err), err}
	}

	// Build final tls.Config directly — single allocation instead of alloc + Clone.
	config := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: true,
	}

	useSNI := f.SNI != ""
	if useSNI {
		config.ServerName = f.SNI
		config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var verifyHostname string
			if f.VerifyHostname != nil {
				verifyHostname = *f.VerifyHostname
			}
			return verifyPeerCertificate(rawCerts, rootCAs, verifyHostname)
		}
	}
	// When not using SNI, ServerName stays empty so no SNI extension is sent.

	chid := clientHelloID
	if chid.Client == "" {
		chid = tls.HelloGolang
	}

	conn := tls.UClient(rawConn, config, chid)
	deadline := time.Now().Add(dialTimeout)
	rawConn.SetDeadline(deadline)

	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return dialResult{nil, classifyError(err), err}
	}
	rawConn.SetDeadline(time.Time{})

	// For non-SNI case, verify the cert manually after handshake
	if !useSNI {
		state := conn.ConnectionState()
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			rawCerts[i] = cert.Raw
		}
		if err := verifyPeerCertificate(rawCerts, rootCAs, f.Domain); err != nil {
			rawConn.Close()
			return dialResult{nil, false, err}
		}
	}

	return dialResult{conn, false, nil}
}

// verifyPeerCertificate verifies the peer certificate chain against the given roots.
func verifyPeerCertificate(rawCerts [][]byte, roots *x509.CertPool, domain string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates presented")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       domain,
		Intermediates: x509.NewCertPool(),
	}

	for i := 1; i < len(rawCerts); i++ {
		intermediate, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			return fmt.Errorf("unable to parse intermediate certificate: %w", err)
		}
		opts.Intermediates.AddCert(intermediate)
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}
	return nil
}

// classifyError returns true if the error is retriable (network issue),
// false if permanent (cert/handshake error).
func classifyError(err error) bool {
	if isNetworkUnreachable(err) {
		return true
	}
	errStr := err.Error()
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "handshake") {
		return false
	}
	return true
}

func isNetworkUnreachable(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ENETUNREACH) || errors.Is(opErr.Err, syscall.EHOSTUNREACH) {
			return true
		}
		errMsg := opErr.Err.Error()
		if strings.Contains(errMsg, "network is unreachable") ||
			strings.Contains(errMsg, "no route to host") ||
			strings.Contains(errMsg, "unreachable network") ||
			strings.Contains(errMsg, "unreachable host") {
			return true
		}
	}
	return false
}
