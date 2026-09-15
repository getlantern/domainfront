package domainfront

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type configValidator struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

type configMetadata struct {
	SHA256     string                     `json:"sha256"`
	Validators map[string]configValidator `json:"validators"`
}

type configResponse struct {
	url       string
	data      []byte
	validator configValidator
	unchanged bool
}

func configDigest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// fetchAndApplyConfig races sources for changed content. A 304 or identical 200
// keeps the current pool intact but does not cancel a potentially newer source.
func (c *Client) fetchAndApplyConfig() {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	if len(c.configURLs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, defaultConfigFetchTimeout)
	defer cancel()
	results := make(chan *configResponse, len(c.configURLs))
	for _, url := range c.configURLs {
		validator := c.configValidators[url]
		go func(url string, validator configValidator) {
			results <- c.fetchConfigFrom(ctx, url, validator)
		}(url, validator)
	}
	unchanged := false
	validatorsChanged := false
	defer func() {
		if validatorsChanged {
			c.persistConfigValidators()
		}
	}()
	for range c.configURLs {
		if c.ctx.Err() != nil {
			return
		}
		r, ok := receiveConfigResponse(ctx, results)
		if !ok {
			if !unchanged {
				c.log.Debug("Config refresh ended before a usable response", "error", ctx.Err())
			}
			return
		}
		if r == nil {
			continue
		}
		digest := ""
		if !r.unchanged {
			digest = configDigest(r.data)
		}
		if r.unchanged || (c.configHash != "" && digest == c.configHash) {
			unchanged = true
			validatorsChanged = c.rememberConfigValidator(r.url, r.validator) || validatorsChanged
			continue
		}
		// Parse only in the collector: losing sources must not allocate another
		// full YAML tree while the winning configuration is being applied.
		cfg, err := ParseConfig(r.data)
		if err != nil {
			c.log.Debug("Failed to parse config", "url", r.url, "error", err)
			continue
		}
		// Keep fetched changes pending while crawling is paused; unchanged
		// results above need no pool rebuild and can finish without resuming.
		if !c.gate.wait(c.ctx) {
			return
		}
		if err := c.applyConfig(cfg); err != nil {
			c.log.Debug("Fetched config failed to apply, trying next source", "url", r.url, "error", err)
			continue
		}
		cancel()
		c.configHash = digest
		// Validators from a previous payload must never authorize a 304 for this one.
		c.configValidators = make(map[string]configValidator)
		c.rememberConfigValidator(r.url, r.validator)
		c.persistConfig(r.data)
		validatorsChanged = true
		c.log.Info("Applied updated config", "url", r.url, "providers", len(cfg.Providers))
		return
	}
	if unchanged {
		c.log.Debug("Config unchanged")
	} else {
		c.log.Warn("No source produced a usable config", "urls", c.configURLs)
	}
}

// receiveConfigResponse stops waiting at the fetch deadline but preserves
// responses queued while the collector was parsing or waiting for resume.
func receiveConfigResponse(ctx context.Context, results <-chan *configResponse) (*configResponse, bool) {
	select {
	case r := <-results:
		return r, true
	case <-ctx.Done():
		select {
		case r := <-results:
			return r, true
		default:
			return nil, false
		}
	}
}

func (c *Client) fetchConfigFrom(ctx context.Context, url string, validator configValidator) *configResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.log.Debug("Failed to create config request", "url", url, "error", err)
		return nil
	}
	if validator.ETag != "" {
		req.Header.Set("If-None-Match", validator.ETag)
	} else if validator.LastModified != "" {
		req.Header.Set("If-Modified-Since", validator.LastModified)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Debug("Failed to fetch config", "url", url, "error", err)
		return nil
	}
	defer resp.Body.Close()
	updated := configValidator{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	if _, err := http.ParseTime(updated.LastModified); err != nil {
		updated.LastModified = ""
	}
	if resp.StatusCode == http.StatusNotModified {
		if validator == (configValidator{}) {
			c.log.Debug("Ignoring unsolicited config 304", "url", url)
			return nil
		}
		if updated.ETag == "" {
			updated.ETag = validator.ETag
		}
		if updated.LastModified == "" {
			updated.LastModified = validator.LastModified
		}
		return &configResponse{url: url, validator: updated, unchanged: true}
	}
	if resp.StatusCode != http.StatusOK {
		c.log.Debug("Config fetch returned non-200 status", "url", url, "status", resp.StatusCode)
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigSize+1))
	if err != nil {
		c.log.Debug("Failed to read config response", "url", url, "error", err)
		return nil
	}
	if len(data) > maxConfigSize {
		c.log.Debug("Config response exceeds size cap", "url", url, "cap", maxConfigSize)
		return nil
	}
	return &configResponse{url: url, data: data, validator: updated}
}

func (c *Client) rememberConfigValidator(url string, validator configValidator) bool {
	if c.configValidators[url] == validator {
		return false
	}
	if c.configValidators == nil {
		c.configValidators = make(map[string]configValidator)
	}
	if validator == (configValidator{}) {
		delete(c.configValidators, url)
	} else {
		c.configValidators[url] = validator
	}
	return true
}

func (c *Client) loadConfigValidators() {
	if c.configCachePath == "" || c.configHash == "" {
		return
	}
	f, err := os.Open(c.configCachePath + ".http.json")
	if err != nil {
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return
	}
	var metadata configMetadata
	if json.Unmarshal(data, &metadata) != nil || metadata.SHA256 != c.configHash {
		return
	}
	// Validate the complete configured set before changing state, so a corrupt
	// timestamp cannot leave a partially restored set of conditional headers.
	for _, url := range c.configURLs {
		if modified := metadata.Validators[url].LastModified; modified != "" {
			if _, err := http.ParseTime(modified); err != nil {
				return
			}
		}
	}
	for _, url := range c.configURLs {
		c.rememberConfigValidator(url, metadata.Validators[url])
	}
}

// persistConfigValidators binds metadata to the exact cached bytes. Torn writes
// or another process replacing either file cause a hash mismatch and a full GET.
func (c *Client) persistConfigValidators() {
	if c.configCachePath == "" || c.configHash == "" {
		return
	}
	data, err := json.Marshal(configMetadata{SHA256: c.configHash, Validators: c.configValidators})
	if err == nil {
		err = writeFile(c.configCachePath+".http.json", data)
	}
	if err != nil {
		c.log.Warn("Failed to persist config validators", "path", c.configCachePath, "error", err)
	}
}
