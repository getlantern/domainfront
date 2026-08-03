package domainfront

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
)

// unmodeledKeys are keys the generator publishes that we deliberately do not
// parse. Anything here is invisible to this package by choice, not by accident.
//
//   - validator: flashlight's per-provider response validator (rejectstatus).
//     Enforced by flashlight clients; domainfront does not act on it.
var unmodeledKeys = map[string]bool{
	"validator": true,
}

// TestWireKeysAreClaimed compares the keys in the real published fronted.yaml.gz
// against the yaml tags on the structs that parse it.
//
// yaml.Unmarshal is silent about keys no field claims, and matching is
// case-sensitive, so a mistyped tag costs a feature with no error anywhere: the
// field just stays zero. Asserting on parsed *values* cannot catch this, because
// a key that fails to bind is indistinguishable from one the config left empty —
// every provider currently publishes "passthroughpatterns: []", which is exactly
// how the tag sat misspelled as "passthrupatterns" without breaking a test.
// Comparing key sets is the only check that fails on the tag itself.
func TestWireKeysAreClaimed(t *testing.T) {
	raw := decompress(t, readConfig(t))

	// Parse into a generic tree so we see what the wire says, not what the
	// structs are willing to hear.
	var tree map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &tree))

	assertClaimed(t, "(root)", tree, reflect.TypeOf(Config{}))

	providers, ok := tree["providers"].(map[string]any)
	require.True(t, ok, "published config has no providers map")
	require.NotEmpty(t, providers)

	for name, p := range providers {
		provider, ok := p.(map[string]any)
		require.Truef(t, ok, "provider %q is not a mapping", name)
		assertClaimed(t, "providers."+name, provider, reflect.TypeOf(Provider{}))

		for i, m := range asSlice(provider["masquerades"]) {
			masq, ok := m.(map[string]any)
			require.Truef(t, ok, "%s.masquerades[%d] is not a mapping", name, i)
			assertClaimed(t, name+".masquerades[]", masq, reflect.TypeOf(Masquerade{}))
			break // homogeneous; one sample per provider keeps the failure readable
		}

		snis, _ := provider["frontingsnis"].(map[string]any)
		for country, s := range snis {
			sni, ok := s.(map[string]any)
			require.Truef(t, ok, "%s.frontingsnis.%s is not a mapping", name, country)
			assertClaimed(t, name+".frontingsnis[]", sni, reflect.TypeOf(SNIConfig{}))
			break
		}
	}

	for i, c := range asSlice(tree["trustedcas"]) {
		ca, ok := c.(map[string]any)
		require.Truef(t, ok, "trustedcas[%d] is not a mapping", i)
		assertClaimed(t, "trustedcas[]", ca, reflect.TypeOf(CA{}))
		break
	}
}

// TestPublishedConfigParses is the other half: the keys bind to non-zero values.
// Key coverage alone would still pass if a type were wrong (a []string field
// pointed at a mapping, say), which yaml reports as an error rather than silence.
func TestPublishedConfigParses(t *testing.T) {
	cfg, err := ParseConfig(readConfig(t))
	require.NoError(t, err)

	require.NotEmpty(t, cfg.TrustedCAs)
	require.NotEmpty(t, cfg.Providers)
	for _, ca := range cfg.TrustedCAs {
		require.NotEmpty(t, ca.Cert, "trusted CA %q has no certificate", ca.CommonName)
	}

	pool, err := cfg.CertPool()
	require.NoError(t, err, "the published CAs must build a usable pool")
	require.NotNil(t, pool)

	for name, p := range cfg.Providers {
		require.NotEmptyf(t, p.Masquerades, "provider %q has no masquerades", name)
		require.NotEmptyf(t, p.TestURL, "provider %q has no test URL", name)
		require.NotEmptyf(t, p.HostAliases, "provider %q has no host aliases", name)
		for i, m := range p.Masquerades {
			require.NotEmptyf(t, m.Domain, "%s.masquerades[%d] has no domain", name, i)
			require.NotEmptyf(t, m.IpAddress, "%s.masquerades[%d] has no IP", name, i)
		}
	}
}

// TestVerifyHostnameCasing pins the one tag TestWireKeysAreClaimed cannot check.
//
// Provider.VerifyHostname is camelCase upstream and declared omitempty, and no
// provider sets it today, so the key is absent from the published config
// entirely — a key-set comparison has nothing to compare. The casing is still
// load-bearing the first time a provider pins a hostname, and it reads like a
// typo next to its lowercase siblings, so this asserts the two spellings behave
// as the generator dictates rather than leaving the next reader to "fix" it.
func TestVerifyHostnameCasing(t *testing.T) {
	// Exactly what flashlight's `yaml:"verifyHostname,omitempty"` emits.
	cfg, err := ParseConfigYAML([]byte(
		"providers:\n" +
			"  akamai:\n" +
			"    verifyHostname: edge.example.com\n"))
	require.NoError(t, err)
	require.NotNil(t, cfg.Providers["akamai"].VerifyHostname,
		"provider verifyHostname must bind from the camelCase key the generator emits")
	require.Equal(t, "edge.example.com", *cfg.Providers["akamai"].VerifyHostname)

	// Masquerade.VerifyHostname is untagged upstream, so it arrives lowercased.
	// The asymmetry is the generator's, not ours.
	cfg, err = ParseConfigYAML([]byte(
		"providers:\n" +
			"  akamai:\n" +
			"    masquerades:\n" +
			"      - domain: a248.e.akamai.net\n" +
			"        verifyhostname: a248.e.akamai.net\n"))
	require.NoError(t, err)
	m := cfg.Providers["akamai"].Masquerades[0]
	require.NotNil(t, m.VerifyHostname,
		"masquerade verifyhostname must bind from the lowercase key")
	require.Equal(t, "a248.e.akamai.net", *m.VerifyHostname)
}

// assertClaimed fails for any wire key that no field of typ unmarshals from and
// that isn't listed in unmodeledKeys.
func assertClaimed(t *testing.T, path string, node map[string]any, typ reflect.Type) {
	t.Helper()
	claimed := yamlKeys(typ)
	var unclaimed []string
	for k := range node {
		if !claimed[k] && !unmodeledKeys[k] {
			unclaimed = append(unclaimed, k)
		}
	}
	sort.Strings(unclaimed)
	require.Emptyf(t, unclaimed, ""+
		"%s: published key(s) %v bind to no field of %s.\n"+
		"Either the yaml tag is wrong (matching is case-sensitive and silent), "+
		"or the generator added a key — model it, or add it to unmodeledKeys "+
		"with a note saying why it's ignored.", path, unclaimed, typ.Name())
}

// yamlKeys returns the wire key each exported field of typ unmarshals from.
func yamlKeys(typ reflect.Type) map[string]bool {
	keys := make(map[string]bool, typ.NumField())
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "-" {
			continue
		}
		if tag == "" {
			// goccy's default when a field has no tag.
			tag = strings.ToLower(f.Name)
		}
		keys[tag] = true
	}
	return keys
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func readConfig(t *testing.T) []byte {
	t.Helper()
	// Read rather than embed: integration_test.go already embeds this file, and
	// a second //go:embed of it in the same package is redundant.
	data, err := os.ReadFile("fronted.yaml.gz")
	require.NoError(t, err, "the published config must be committed alongside the parser")
	return data
}

func decompress(t *testing.T, gzipped []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(gzipped))
	require.NoError(t, err)
	defer r.Close()
	raw, err := io.ReadAll(r)
	require.NoError(t, err)
	return raw
}
