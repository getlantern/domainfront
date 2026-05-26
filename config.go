package domainfront

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/goccy/go-yaml"
)

// Config represents a domain fronting configuration, typically loaded from
// a gzipped YAML file (fronted.yaml.gz).
type Config struct {
	TrustedCAs []*CA                `yaml:"trustedcas"`
	Providers  map[string]*Provider `yaml:"providers"`
}

// CA represents a certificate authority with its PEM-encoded certificate.
type CA struct {
	CommonName string `yaml:"commonname"`
	Cert       string `yaml:"cert"`
}

// Provider is a domain fronting provider (e.g. Akamai, CloudFront).
type Provider struct {
	HostAliases         map[string]string    `yaml:"hostaliases"`
	PassthroughPatterns []string             `yaml:"passthrupatterns"`
	TestURL             string               `yaml:"testurl"`
	Masquerades         []*Masquerade        `yaml:"masquerades"`
	VerifyHostname      *string              `yaml:"verifyhostname"`
	// Pipeline-emitted YAML keys are lowercase-concatenated, not
	// snake_case (the upstream generator uses lowercased Go field
	// names with no yaml tag); the tag here must match the wire
	// format exactly or yaml.Unmarshal silently leaves the field
	// zero-valued.
	FrontingSNIs map[string]*SNIConfig `yaml:"frontingsnis"`
}

// SNIConfig controls SNI generation for a specific country or "default".
type SNIConfig struct {
	UseArbitrarySNIs bool     `yaml:"usearbitrarysnis"`
	ArbitrarySNIs    []string `yaml:"arbitrarysnis"`
}

// Masquerade contains the data for a single domain front.
type Masquerade struct {
	Domain         string  `yaml:"domain"`
	IpAddress      string  `yaml:"ipaddress"`
	SNI            string  `yaml:"sni"`
	VerifyHostname *string `yaml:"verifyhostname"`
}

// Lookup returns the fronted hostname for the given origin hostname.
// Returns empty string if the provider has no mapping for the host.
func (p *Provider) Lookup(hostname string) string {
	// Strip port if present. Check for colon first to avoid net.SplitHostPort
	// which allocates a *AddrError for port-less hostnames (the common case).
	if strings.LastIndexByte(hostname, ':') >= 0 {
		if h, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = h
		}
	}
	// Only allocate a lowercase copy when the hostname isn't already lowercase.
	// In practice, hostnames from Android/Go HTTP clients are almost always
	// lowercase, so this avoids an allocation on the hot request path.
	hostname = toLowerFast(hostname)

	if alias := p.HostAliases[hostname]; alias != "" {
		return alias
	}

	for _, pt := range p.PassthroughPatterns {
		if strings.HasPrefix(pt, "*.") && strings.HasSuffix(hostname, pt[1:]) {
			return hostname
		} else if pt == hostname {
			return hostname
		}
	}
	return ""
}

// toLowerFast returns s lowercased, reusing s if it's already all-lowercase.
func toLowerFast(s string) string {
	for i := range s {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

// ParseConfig parses a gzipped YAML configuration into a Config.
func ParseConfig(gzippedYaml []byte) (*Config, error) {
	r, err := gzip.NewReader(bytes.NewReader(gzippedYaml))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer r.Close()

	yml, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzipped data: %w", err)
	}

	return ParseConfigYAML(yml)
}

// ParseConfigYAML parses uncompressed YAML into a Config.
func ParseConfigYAML(yml []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(yml, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}
	if cfg.Providers == nil {
		cfg.Providers = make(map[string]*Provider)
	}
	return &cfg, nil
}

// CertPool builds an x509.CertPool from the config's trusted CAs.
// Returns an error if any CA certificate fails to parse.
func (cfg *Config) CertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for i, ca := range cfg.TrustedCAs {
		if ok := pool.AppendCertsFromPEM([]byte(ca.Cert)); !ok {
			return nil, fmt.Errorf("failed to parse trusted CA at index %d (%s)", i, ca.CommonName)
		}
	}
	return pool, nil
}

// ExpandedProvider returns a copy of the provider with masquerades expanded
// with SNI based on the country code. Host aliases are lowercased.
// Passthrough patterns are also lowercased for efficient lookup.
func ExpandedProvider(p *Provider, countryCode string) *Provider {
	ep := &Provider{
		HostAliases:         make(map[string]string, len(p.HostAliases)),
		TestURL:             p.TestURL,
		Masquerades:         make([]*Masquerade, 0, len(p.Masquerades)),
		PassthroughPatterns: make([]string, len(p.PassthroughPatterns)),
		VerifyHostname:      p.VerifyHostname,
		FrontingSNIs:        p.FrontingSNIs,
	}

	for k, v := range p.HostAliases {
		ep.HostAliases[strings.ToLower(k)] = v
	}

	for i, pt := range p.PassthroughPatterns {
		ep.PassthroughPatterns[i] = strings.ToLower(pt)
	}

	var sniCfg *SNIConfig
	if countryCode != "" && p.FrontingSNIs != nil {
		var ok bool
		sniCfg, ok = p.FrontingSNIs[countryCode]
		if !ok {
			sniCfg = p.FrontingSNIs["default"]
		}
	}

	for _, m := range p.Masquerades {
		sni := GenerateSNI(sniCfg, m.IpAddress)
		ep.Masquerades = append(ep.Masquerades, &Masquerade{
			Domain:         m.Domain,
			IpAddress:      m.IpAddress,
			SNI:            sni,
			VerifyHostname: p.VerifyHostname,
		})
	}
	return ep
}
