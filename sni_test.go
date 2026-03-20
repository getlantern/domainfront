package domainfront

import (
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
