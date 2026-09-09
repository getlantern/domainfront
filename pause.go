package domainfront

import (
	"context"
	"sync"
)

// pauseGate suspends background loops without cancelling them. Waiters block
// while paused and are released by resume or by their context ending.
type pauseGate struct {
	mu sync.Mutex
	// resumed is closed while running and an open channel while paused. Each
	// paused stretch owns the channel its resume closes; waiters must recheck
	// the current channel in case another pause happened before they woke.
	resumed chan struct{}
}

func newPauseGate() *pauseGate {
	resumed := make(chan struct{})
	close(resumed)
	return &pauseGate{resumed: resumed}
}

func (g *pauseGate) pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.resumed:
		g.resumed = make(chan struct{})
	default:
	}
}

func (g *pauseGate) resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.resumed:
	default:
		close(g.resumed)
	}
}

func (g *pauseGate) isPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.resumed:
		return false
	default:
		return true
	}
}

// wait blocks until the gate is resumed, reporting false if ctx ended first.
func (g *pauseGate) wait(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		g.mu.Lock()
		resumed := g.resumed
		select {
		case <-resumed:
			g.mu.Unlock()
			return true
		default:
			g.mu.Unlock()
		}
		select {
		case <-resumed:
			// A later pause may have replaced this channel while we were asleep.
		case <-ctx.Done():
			return false
		}
	}
}

// Pause suspends front crawling, cache persistence, and application of fetched
// configs. Config downloads may finish, but their results wait for Resume. It
// suits stretches when background probing cannot succeed or is unwanted — no
// default route, or a sleeping device — so a whole pass of fronts isn't dialed
// and marked failed on evidence that says nothing about the fronts.
//
// Suspension is best-effort for work already running: vets in flight when Pause
// lands run to completion and may still mark their fronts failed.
//
// Round trips are not gated. A paused Client still dials and serves requests,
// and a dial that fails while paused leaves its front in rotation instead of
// dropping it. A failure after a successful dial still fails the front, since
// the connection proves reachability regardless of the pause.
//
// Pause never blocks, so it is safe to call from a callback holding a lock.
// Calls do not nest: one Resume resumes regardless of how many Pause calls
// preceded it. Close works while paused.
func (c *Client) Pause() {
	c.gate.pause()
}

// Resume restarts the background work suspended by Pause, and does nothing if
// the Client is not paused. Work that came due while paused runs when Resume
// lands.
func (c *Client) Resume() {
	c.gate.resume()
}
