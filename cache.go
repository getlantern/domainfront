package domainfront

import (
	"encoding/json"
	"time"
)

// CachedFront is the serialization format for cached fronts.
type CachedFront struct {
	Domain         string    `json:"Domain"`
	IpAddress      string    `json:"IpAddress"`
	SNI            string    `json:"SNI,omitempty"`
	VerifyHostname *string   `json:"VerifyHostname,omitempty"`
	LastSucceeded  time.Time `json:"LastSucceeded"`
	ProviderID     string    `json:"ProviderID"`
}

// Cache is an interface for persisting and loading front state.
type Cache interface {
	Load() ([]*CachedFront, error)
	Save(fronts []*CachedFront) error
}

// FileCache persists fronts as JSON to a file.
type FileCache struct {
	Path string
}

func (fc *FileCache) Load() ([]*CachedFront, error) {
	data, err := readFile(fc.Path)
	if err != nil || len(data) == 0 {
		return nil, err
	}
	var fronts []*CachedFront
	if err := json.Unmarshal(data, &fronts); err != nil {
		return nil, err
	}
	return fronts, nil
}

func (fc *FileCache) Save(fronts []*CachedFront) error {
	data, err := json.Marshal(fronts)
	if err != nil {
		return err
	}
	return writeFile(fc.Path, data)
}

// NopCache is a no-op cache that never loads or saves anything.
type NopCache struct{}

func (NopCache) Load() ([]*CachedFront, error) { return nil, nil }
func (NopCache) Save([]*CachedFront) error      { return nil }

// frontsToCache converts pool fronts to cache format, limited to maxSize entries.
func frontsToCache(fronts []*front, maxSize int) []*CachedFront {
	if len(fronts) > maxSize {
		fronts = fronts[:maxSize]
	}
	cached := make([]*CachedFront, 0, len(fronts))
	for _, f := range fronts {
		cached = append(cached, &CachedFront{
			Domain:         f.Domain,
			IpAddress:      f.IpAddress,
			SNI:            f.SNI,
			VerifyHostname: f.VerifyHostname,
			LastSucceeded:  f.lastSucceededTime(),
			ProviderID:     f.ProviderID,
		})
	}
	return cached
}

// applyCachedState updates front LastSucceeded from cached values.
func applyCachedState(fronts []*front, cached []*CachedFront, maxAge time.Duration) {
	type key struct{ provider, domain, ip string }
	lookup := make(map[key]*CachedFront, len(cached))
	for _, cf := range cached {
		lookup[key{cf.ProviderID, cf.Domain, cf.IpAddress}] = cf
	}

	now := time.Now()
	for _, f := range fronts {
		if cf, ok := lookup[key{f.ProviderID, f.Domain, f.IpAddress}]; ok {
			if now.Sub(cf.LastSucceeded) < maxAge {
				f.setLastSucceeded(cf.LastSucceeded)
			}
		}
	}
}
