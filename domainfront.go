package domainfront

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/refraction-networking/utls"
)

const (
	defaultMaxAllowedCachedAge = 24 * time.Hour
	defaultMaxCacheSize        = 1000
	defaultCacheSaveInterval   = 5 * time.Second
	defaultMaxRetries          = 6
	defaultCrawlerConcurrency  = 10
	defaultProviderID          = "cloudfront"
	maxConfigSize              = 50 << 20 // 50 MB
)

// Client is the main entry point for domain fronting. It manages a pool of
// fronts, background crawling, caching, and config updates. All state is
// contained in the Client — there is no global state.
type Client struct {
	ctx    context.Context
	cancel context.CancelFunc
	log    *slog.Logger

	pool          *frontPool
	providers     map[string]*Provider
	providersMu   sync.RWMutex
	certPoolValue atomic.Value // *x509.CertPool

	dialer        Dialer
	clientHelloID tls.ClientHelloID
	countryCode   string
	defaultPID    string
	maxRetries    int

	// retryableResponse decides whether a fronted response that completed but
	// carried a rejection/failure status should be treated as a front failure
	// and retried on another front rather than returned to the caller. See
	// defaultRetryableResponse for the default.
	retryableResponse func(*http.Response) bool

	cache             Cache
	maxCacheSize      int
	maxCachedAge      time.Duration
	cacheSaveInterval time.Duration
	cacheDirty        chan struct{}

	configURL       string
	configCachePath string
	httpClient      *http.Client

	crawlerConcurrency int
	readyQueueSize     int
	wg                 sync.WaitGroup
}

// Option configures a Client.
type Option func(*Client)

func WithLogger(l *slog.Logger) Option       { return func(c *Client) { c.log = l } }
func WithDialer(d Dialer) Option             { return func(c *Client) { c.dialer = d } }
func WithCountryCode(cc string) Option       { return func(c *Client) { c.countryCode = cc } }
func WithDefaultProviderID(id string) Option { return func(c *Client) { c.defaultPID = id } }
func WithConfigURL(url string) Option        { return func(c *Client) { c.configURL = url } }

// WithConfigCacheFile persists each successfully fetched config to path and, on
// the next start, bootstraps from it in preference to the seed config passed to
// New. This lets a client that fetched a fresher config before going offline
// keep using it across restarts instead of reverting to the (typically embedded)
// seed. Requires WithConfigURL to actually refresh the cache.
func WithConfigCacheFile(path string) Option { return func(c *Client) { c.configCachePath = path } }
func WithHTTPClient(hc *http.Client) Option  { return func(c *Client) { c.httpClient = hc } }
func WithCache(cache Cache) Option           { return func(c *Client) { c.cache = cache } }
func WithMaxRetries(n int) Option            { return func(c *Client) { c.maxRetries = n } }

// WithRetryableResponse overrides the predicate that decides whether a fronted
// response should be treated as a front failure and retried on another front
// instead of being returned to the caller. The default (defaultRetryableResponse)
// treats 403 and any 5xx as retryable. A predicate returning false leaves the
// response to be returned unchanged.
func WithRetryableResponse(fn func(*http.Response) bool) Option {
	return func(c *Client) { c.retryableResponse = fn }
}
func WithClientHelloID(id tls.ClientHelloID) Option {
	return func(c *Client) { c.clientHelloID = id }
}
func WithCrawlerConcurrency(n int) Option { return func(c *Client) { c.crawlerConcurrency = n } }

// WithReadyQueueSize sets the capacity of the ready-fronts channel.
// Smaller values save memory on constrained devices. Default is 500.
func WithReadyQueueSize(n int) Option { return func(c *Client) { c.readyQueueSize = n } }

// WithCacheSaveInterval sets how often dirty cache state is flushed to disk.
// Longer intervals reduce I/O on flash storage (e.g. Android). Default is 5s.
func WithCacheSaveInterval(d time.Duration) Option {
	return func(c *Client) { c.cacheSaveInterval = d }
}

// WithCacheFile is a convenience option that sets a FileCache at the given path.
func WithCacheFile(path string) Option {
	return func(c *Client) { c.cache = &FileCache{Path: path} }
}

// New creates a new domain fronting Client and starts background goroutines.
// The provided config is the initial (typically embedded) configuration.
// Pass a cancellable context to control the Client's lifetime, or call Close().
func New(ctx context.Context, config *Config, options ...Option) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config must not be nil")
	}

	innerCtx, cancel := context.WithCancel(ctx)
	c := &Client{
		ctx:                innerCtx,
		cancel:             cancel,
		log:                slog.Default(),
		pool:               nil, // created after options are applied
		providers:          make(map[string]*Provider),
		dialer:             NetDialer{},
		clientHelloID:      tls.HelloChrome_131,
		defaultPID:         defaultProviderID,
		maxRetries:         defaultMaxRetries,
		retryableResponse:  defaultRetryableResponse,
		cache:              NopCache{},
		maxCacheSize:       defaultMaxCacheSize,
		maxCachedAge:       defaultMaxAllowedCachedAge,
		cacheSaveInterval:  defaultCacheSaveInterval,
		cacheDirty:         make(chan struct{}, 1),
		httpClient:         http.DefaultClient,
		crawlerConcurrency: defaultCrawlerConcurrency,
	}

	for _, opt := range options {
		opt(c)
	}

	// Clamp crawler concurrency to avoid deadlock with zero-capacity semaphore
	if c.crawlerConcurrency < 1 {
		c.crawlerConcurrency = 1
	}

	// Create pool after options are applied so readyQueueSize can be set
	c.pool = newFrontPool(c.readyQueueSize)

	// Prefer a config persisted by a prior successful fetch over the seed
	// (typically embedded): a device that fetched a fresher config before going
	// offline should keep using it. The config updater refreshes it in the
	// background when configURL is reachable. A persisted config that parses but
	// won't apply (e.g. a torn write that decompresses to YAML with no providers)
	// must not fail construction — fall back to the seed, the caller's known-good
	// baseline, and only fail if that too is invalid.
	applied := false
	if persisted := c.loadPersistedConfig(); persisted != nil {
		if err := c.applyConfig(persisted); err != nil {
			c.log.Warn("Persisted config failed to apply, falling back to seed", "error", err)
		} else {
			applied = true
		}
	}
	if !applied {
		if err := c.applyConfig(config); err != nil {
			cancel()
			return nil, fmt.Errorf("invalid config: %w", err)
		}
	}

	// Load cached state
	cached, err := c.cache.Load()
	if err != nil {
		c.log.Warn("Failed to load cache", "error", err)
	} else if len(cached) > 0 {
		c.log.Debug("Loaded cached fronts", "count", len(cached))
		fronts := c.pool.candidates()
		applyCachedState(fronts, cached, c.maxCachedAge)
	}

	// Start background goroutines
	c.wg.Add(2)
	go c.crawler()
	go c.cacheSaver()

	if c.configURL != "" {
		c.wg.Add(1)
		go c.configUpdater()
	}

	return c, nil
}

// RoundTripper returns an http.RoundTripper that sends requests via domain fronting.
func (c *Client) RoundTripper() http.RoundTripper {
	return &roundTripper{client: c}
}

// Close shuts down all background goroutines and the front pool.
func (c *Client) Close() {
	c.cancel()
	c.pool.Close()
	c.wg.Wait()

	// Final cache save
	c.saveCache()
}

func (c *Client) certPool() *x509.CertPool {
	if pool, ok := c.certPoolValue.Load().(*x509.CertPool); ok && pool != nil {
		return pool
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		c.log.Warn("Failed to load system cert pool", "error", err)
		return x509.NewCertPool()
	}
	return pool
}

func (c *Client) applyConfig(cfg *Config) error {
	if len(cfg.Providers) == 0 {
		return fmt.Errorf("no providers configured")
	}

	expanded := make(map[string]*Provider, len(cfg.Providers))
	for id, p := range cfg.Providers {
		expanded[id] = ExpandedProvider(p, c.countryCode)
	}

	c.providersMu.Lock()
	c.providers = expanded
	c.providersMu.Unlock()

	certPool, err := cfg.CertPool()
	if err != nil {
		return fmt.Errorf("cert pool: %w", err)
	}
	c.certPoolValue.Store(certPool)

	var fronts []*front
	for providerID, p := range expanded {
		for _, m := range p.Masquerades {
			fronts = append(fronts, newFront(m, providerID))
		}
	}

	rand.Shuffle(len(fronts), func(i, j int) { fronts[i], fronts[j] = fronts[j], fronts[i] })

	c.pool.Replace(fronts)
	c.log.Debug("Applied config", "providers", len(expanded), "fronts", len(fronts))
	return nil
}

func (c *Client) providerFor(f *front) *Provider {
	pid := f.ProviderID
	if pid == "" {
		pid = c.defaultPID
	}
	c.providersMu.RLock()
	defer c.providersMu.RUnlock()
	return c.providers[pid]
}

func (c *Client) notifyCacheDirty() {
	select {
	case c.cacheDirty <- struct{}{}:
	default:
	}
}

func (c *Client) crawler() {
	defer c.wg.Done()

	// Use a reusable timer instead of time.After to avoid leaking timers.
	// time.After creates a new timer each iteration that isn't GC'd until it
	// fires — on memory-constrained devices this creates mounting GC pressure.
	// Initialize stopped and drain to avoid an immediate spurious wake.
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		if c.pool.readyCount() < 2 {
			c.crawlAllFronts()
		}

		timer.Reset(time.Duration(6+rand.IntN(7)) * time.Second)
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (c *Client) crawlAllFronts() {
	candidates := c.pool.candidates()
	if len(candidates) == 0 {
		return
	}

	sem := make(chan struct{}, c.crawlerConcurrency)
	var wg sync.WaitGroup

	for _, f := range candidates {
		if c.ctx.Err() != nil {
			break
		}
		if c.pool.readyCount() >= 4 {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(f *front) {
			defer wg.Done()
			defer func() { <-sem }()

			if c.ctx.Err() != nil {
				return
			}

			if c.vetFront(f) {
				f.markSucceeded()
				c.pool.addReady(f)
				c.notifyCacheDirty()
			} else {
				f.markFailed()
				c.notifyCacheDirty()
			}
		}(f)
	}

	wg.Wait()
}

func (c *Client) vetFront(f *front) bool {
	result := dialFront(c.ctx, f, c.certPool(), c.clientHelloID, c.dialer)
	if result.err != nil {
		c.log.Debug("Failed to dial front", "ip", f.IpAddress, "domain", f.Domain, "error", result.err)
		return false
	}
	defer result.conn.Close()

	provider := c.providerFor(f)
	if provider == nil || provider.TestURL == "" {
		return false
	}

	return c.verifyWithPost(result.conn, provider.TestURL)
}

// vetBody is reused across vet requests to avoid per-call allocation.
var vetBody = []byte("a")

func (c *Client) verifyWithPost(conn net.Conn, testURL string) bool {
	req, err := http.NewRequest(http.MethodPost, testURL, bytes.NewReader(vetBody))
	if err != nil {
		c.log.Debug("Error creating vet request", "error", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	// Frame the vet request to match the negotiated ALPN — the dialed front
	// may have negotiated h2, exactly like real request traffic.
	resp, err := sendOverConn(conn, req, true)
	if err != nil {
		c.log.Debug("Error vetting front", "error", err, "url", testURL)
		return false
	}
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if resp.StatusCode != http.StatusAccepted {
		c.log.Debug("Unexpected status vetting front", "expected", 202, "got", resp.StatusCode)
		return false
	}
	return true
}

func (c *Client) cacheSaver() {
	defer c.wg.Done()

	timer := time.NewTimer(c.cacheSaveInterval)
	defer timer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
			select {
			case <-c.cacheDirty:
				c.saveCache()
			default:
			}
			timer.Reset(c.cacheSaveInterval)
		}
	}
}

func (c *Client) saveCache() {
	candidates := c.pool.candidates()
	cached := frontsToCache(candidates, c.maxCacheSize)
	if err := c.cache.Save(cached); err != nil {
		c.log.Warn("Failed to save cache", "error", err)
	}
}

func (c *Client) configUpdater() {
	defer c.wg.Done()

	// Fetch immediately on startup, then every 12 hours
	c.fetchAndApplyConfig()

	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.fetchAndApplyConfig()
		}
	}
}

func (c *Client) fetchAndApplyConfig() {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.configURL, nil)
	if err != nil {
		c.log.Warn("Failed to create config request", "error", err)
		return
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Warn("Failed to fetch config", "url", c.configURL, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.log.Warn("Config fetch returned non-200 status", "status", resp.StatusCode)
		return
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigSize))
	if err != nil {
		c.log.Warn("Failed to read config response", "error", err)
		return
	}

	cfg, err := ParseConfig(data)
	if err != nil {
		c.log.Warn("Failed to parse config", "error", err)
		return
	}

	c.log.Info("Applying updated config", "providers", len(cfg.Providers))
	if err := c.applyConfig(cfg); err != nil {
		c.log.Warn("Failed to apply config update", "error", err)
		return
	}
	c.persistConfig(data)
}

// loadPersistedConfig returns the config saved by a prior successful fetch, or
// nil when none is configured/present or it can't be read or parsed. The read
// is size-bounded by ParseConfigFromReader. See WithConfigCacheFile.
func (c *Client) loadPersistedConfig() *Config {
	if c.configCachePath == "" {
		return nil
	}
	f, err := os.Open(c.configCachePath)
	if err != nil {
		// A missing cache is the normal first-run case; anything else (e.g. a
		// permission problem) is worth surfacing before falling back to the seed.
		if !os.IsNotExist(err) {
			c.log.Warn("Failed to open persisted config, using seed", "path", c.configCachePath, "error", err)
		}
		return nil
	}
	defer f.Close()
	cfg, err := ParseConfigFromReader(f)
	if err != nil {
		c.log.Warn("Ignoring unparseable persisted config", "path", c.configCachePath, "error", err)
		return nil
	}
	c.log.Debug("Bootstrapped from persisted config", "path", c.configCachePath, "providers", len(cfg.Providers))
	return cfg
}

// persistConfig writes the freshly fetched config so the next start can boot
// from it. Best-effort — a failure only means a colder next start.
func (c *Client) persistConfig(data []byte) {
	if c.configCachePath == "" {
		return
	}
	if err := writeFile(c.configCachePath, data); err != nil {
		c.log.Warn("Failed to persist config cache", "path", c.configCachePath, "error", err)
	}
}

// DefaultCacheFilePath returns the default path for the fronts cache file.
func DefaultCacheFilePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "domainfronting")
	if err := os.MkdirAll(path, 0o700); err != nil {
		// Fall through; the write will fail later with a clear error
	}
	return filepath.Join(path, "domainfront_cache.json")
}

// ParseConfigFromFile reads and parses a gzipped config from a file path.
func ParseConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfigFromReader reads gzipped YAML from a reader.
// Input is limited to maxConfigSize (50 MB) to prevent excessive memory use.
func ParseConfigFromReader(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("config size exceeds maximum of %d bytes", maxConfigSize)
	}
	return ParseConfig(data)
}

// CompressConfig gzip-compresses YAML config bytes.
func CompressConfig(yamlBytes []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(yamlBytes); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
