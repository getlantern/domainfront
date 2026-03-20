package domainfront

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderLookup(t *testing.T) {
	p := &Provider{
		HostAliases: map[string]string{
			"api.example.com": "api.cdn.example.com",
			"www.example.com": "www.cdn.example.com",
		},
		PassthroughPatterns: []string{"*.cloudfront.net"},
	}

	t.Run("exact match", func(t *testing.T) {
		assert.Equal(t, "api.cdn.example.com", p.Lookup("api.example.com"))
	})

	t.Run("case insensitive", func(t *testing.T) {
		assert.Equal(t, "api.cdn.example.com", p.Lookup("API.Example.COM"))
	})

	t.Run("with port", func(t *testing.T) {
		assert.Equal(t, "api.cdn.example.com", p.Lookup("api.example.com:443"))
	})

	t.Run("passthrough wildcard", func(t *testing.T) {
		assert.Equal(t, "d123.cloudfront.net", p.Lookup("d123.cloudfront.net"))
	})

	t.Run("no match", func(t *testing.T) {
		assert.Equal(t, "", p.Lookup("unknown.example.com"))
	})
}

func TestExpandedProvider(t *testing.T) {
	p := &Provider{
		HostAliases: map[string]string{"API.Example.COM": "api.cdn.com"},
		TestURL:     "https://test.example.com/ping",
		Masquerades: []*Masquerade{
			{Domain: "cdn.example.com", IpAddress: "1.2.3.4"},
			{Domain: "cdn2.example.com", IpAddress: "5.6.7.8"},
		},
		FrontingSNIs: map[string]*SNIConfig{
			"default": {UseArbitrarySNIs: false},
			"br": {
				UseArbitrarySNIs: true,
				ArbitrarySNIs:    []string{"mercado.com", "amazon.com.br"},
			},
		},
	}

	t.Run("no country code, no SNI", func(t *testing.T) {
		ep := ExpandedProvider(p, "")
		for _, m := range ep.Masquerades {
			assert.Empty(t, m.SNI)
		}
	})

	t.Run("country with arbitrary SNIs", func(t *testing.T) {
		ep := ExpandedProvider(p, "br")
		for _, m := range ep.Masquerades {
			assert.NotEmpty(t, m.SNI)
			assert.Contains(t, []string{"mercado.com", "amazon.com.br"}, m.SNI)
		}
	})

	t.Run("host aliases lowercased", func(t *testing.T) {
		ep := ExpandedProvider(p, "")
		assert.Equal(t, "api.cdn.com", ep.HostAliases["api.example.com"])
	})
}

func TestParseConfigYAML(t *testing.T) {
	yml := `
trustedcas:
  - commonname: "Test CA"
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIBkTCB+wIJALRiMLAh1iGgMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMMElRl
      -----END CERTIFICATE-----
providers:
  testprovider:
    hostaliases:
      example.com: cdn.example.com
    testurl: https://test.example.com/ping
    masquerades:
      - domain: cdn.example.com
        ipaddress: "1.2.3.4"
`
	cfg, err := ParseConfigYAML([]byte(yml))
	require.NoError(t, err)
	require.Len(t, cfg.TrustedCAs, 1)
	assert.Equal(t, "Test CA", cfg.TrustedCAs[0].CommonName)
	require.Contains(t, cfg.Providers, "testprovider")
	p := cfg.Providers["testprovider"]
	assert.Equal(t, "cdn.example.com", p.HostAliases["example.com"])
	require.Len(t, p.Masquerades, 1)
	assert.Equal(t, "1.2.3.4", p.Masquerades[0].IpAddress)
}
