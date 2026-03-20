package domainfront

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrontPool_TakeReturn(t *testing.T) {
	pool := newFrontPool()
	f := newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
	f.markSucceeded()

	pool.Replace([]*front{f})
	pool.addReady(f)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := pool.Take(ctx)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got.IpAddress)

	pool.Return(got, true)
	assert.Equal(t, 1, pool.readyCount())
}

func TestFrontPool_TakeBlocksUntilReady(t *testing.T) {
	pool := newFrontPool()
	f := newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should timeout since no fronts are ready
	_, err := pool.Take(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	// Now add a ready front
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()

	go func() {
		time.Sleep(50 * time.Millisecond)
		pool.addReady(f)
	}()

	got, err := pool.Take(ctx2)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", got.IpAddress)
}

func TestFrontPool_Replace_PreservesState(t *testing.T) {
	pool := newFrontPool()
	f1 := newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
	f1.markSucceeded()
	pool.Replace([]*front{f1})

	// Replace with same front — state should be preserved
	f2 := newFront(&Masquerade{Domain: "cdn.example.com", IpAddress: "1.2.3.4"}, "test")
	pool.Replace([]*front{f2})

	assert.True(t, f2.isSucceeding(), "state should be preserved after Replace")
}

func TestFrontPool_Close(t *testing.T) {
	pool := newFrontPool()

	ctx := context.Background()
	go func() {
		time.Sleep(50 * time.Millisecond)
		pool.Close()
	}()

	_, err := pool.Take(ctx)
	assert.Error(t, err)
}

func TestFrontPool_Candidates(t *testing.T) {
	pool := newFrontPool()

	f1 := newFront(&Masquerade{Domain: "a.com", IpAddress: "1.1.1.1"}, "p1")
	f2 := newFront(&Masquerade{Domain: "b.com", IpAddress: "2.2.2.2"}, "p2")
	f2.markSucceeded()

	pool.Replace([]*front{f1, f2})

	candidates := pool.candidates()
	require.Len(t, candidates, 2)
	// Succeeded front should be first
	assert.Equal(t, "2.2.2.2", candidates[0].IpAddress)
}
