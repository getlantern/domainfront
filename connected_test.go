package domainfront

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingConn is a noop net.Conn that counts Close calls so tests can
// verify the connectedRoundTripper releases the underlying connection.
type countingConn struct {
	closes int
}

func (c *countingConn) Read([]byte) (int, error)    { return 0, errors.New("not implemented") }
func (c *countingConn) Write([]byte) (int, error)   { return 0, errors.New("not implemented") }
func (c *countingConn) Close() error                { c.closes++; return nil }
func (c *countingConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *countingConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (*countingConn) SetDeadline(time.Time) error   { return nil }
func (*countingConn) SetReadDeadline(time.Time) error  { return nil }
func (*countingConn) SetWriteDeadline(time.Time) error { return nil }

// newTestConnectedRT constructs a connectedRoundTripper with a minimal Client
// and a counting conn. The returned client has an empty pool so Return is a
// no-op (fronts are dropped silently when the channel is full).
func newTestConnectedRT(t *testing.T) (*connectedRoundTripper, *countingConn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := &Client{
		ctx:          ctx,
		cancel:       cancel,
		pool:         newFrontPool(1),
		maxRetries:   1,
		cacheDirty:   make(chan struct{}, 1),
		providers:    map[string]*Provider{},
		defaultPID:   "test",
	}
	f := newFront(&Masquerade{Domain: "a.example.com", IpAddress: "1.1.1.1"}, "test")
	conn := &countingConn{}
	rt := &connectedRoundTripper{
		client:   c,
		front:    f,
		provider: &Provider{HostAliases: map[string]string{}},
		conn:     conn,
	}
	return rt, conn
}

func TestConnectedRoundTripper_SecondRoundTripReturnsErrUsed(t *testing.T) {
	rt, _ := newTestConnectedRT(t)
	// Mark as used by calling Close; subsequent RoundTrip must error.
	require.NoError(t, rt.Close())

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	assert.ErrorIs(t, err, ErrRoundTripperUsed)
}

func TestConnectedRoundTripper_CloseReturnsFrontAndClosesConn(t *testing.T) {
	rt, conn := newTestConnectedRT(t)

	require.NoError(t, rt.Close())
	assert.Equal(t, 1, conn.closes, "Close should close the underlying conn")

	// Second Close is a no-op, not a double-close.
	require.NoError(t, rt.Close())
	assert.Equal(t, 1, conn.closes, "second Close should be a no-op")
}

func TestConnectedRoundTripper_UnmappedHostDoesNotDoubleReturn(t *testing.T) {
	rt, conn := newTestConnectedRT(t)

	req, err := http.NewRequest(http.MethodGet, "https://unmapped.example.com/", nil)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.Error(t, err, "should fail on unmapped host")
	assert.Contains(t, err.Error(), "no domain fronting mapping")
	assert.Equal(t, 1, conn.closes, "conn should be closed on unmapped-host failure")

	// A subsequent Close must not re-return the front or re-close the conn.
	require.NoError(t, rt.Close())
	assert.Equal(t, 1, conn.closes, "Close after RoundTrip should be a no-op")
}
