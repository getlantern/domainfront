package domainfront

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSNI(t *testing.T) {
	t.Run("nil config returns empty", func(t *testing.T) {
		assert.Equal(t, "", GenerateSNI(nil, "1.2.3.4"))
	})

	t.Run("disabled arbitrary SNIs returns empty", func(t *testing.T) {
		cfg := &SNIConfig{UseArbitrarySNIs: false, ArbitrarySNIs: []string{"a.com"}}
		assert.Equal(t, "", GenerateSNI(cfg, "1.2.3.4"))
	})

	t.Run("empty list returns empty", func(t *testing.T) {
		cfg := &SNIConfig{UseArbitrarySNIs: true, ArbitrarySNIs: []string{}}
		assert.Equal(t, "", GenerateSNI(cfg, "1.2.3.4"))
	})

	t.Run("deterministic selection", func(t *testing.T) {
		cfg := &SNIConfig{
			UseArbitrarySNIs: true,
			ArbitrarySNIs:    []string{"a.com", "b.com", "c.com", "d.com"},
		}
		sni1 := GenerateSNI(cfg, "10.0.0.1")
		sni2 := GenerateSNI(cfg, "10.0.0.1")
		assert.Equal(t, sni1, sni2, "same IP should produce same SNI")

		// Different IP should (likely) produce different SNI
		sni3 := GenerateSNI(cfg, "10.0.0.2")
		// We can't guarantee they differ, but we can check it's from the list
		assert.Contains(t, cfg.ArbitrarySNIs, sni3)
	})
}

func TestGenerateSNIPrefixEquivalent(t *testing.T) {
	original := &SNIConfig{UseArbitrarySNIs: true, ArbitrarySNIs: make([]string, 1000)}
	for i := range original.ArbitrarySNIs {
		original.ArbitrarySNIs[i] = fmt.Sprintf("sni-%d.example", i)
	}
	compact := &SNIConfig{UseArbitrarySNIs: true, ArbitrarySNIs: original.ArbitrarySNIs[:256]}
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		before := GenerateSNI(original, ip)
		assert.Equal(t, before, GenerateSNI(compact, ip), ip)
		seen[before] = true
	}
	assert.Len(t, seen, 256, "exercise every reachable SNI through the real selector")
}
