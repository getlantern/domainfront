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
// Keyed by the struct the exception applies to, so an unmodeled key appearing at
// an unexpected level still fails.
//
//   - Provider.validator: flashlight's per-provider response validator
//     (rejectstatus). Enforced by flashlight clients; domainfront does not act
//     on it.
var unmodeledKeys = map[reflect.Type]map[string]bool{
	reflect.TypeOf(Provider{}): {"validator": true},
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

	assertClaimed(t, "(root)", []map[string]any{tree}, reflect.TypeOf(Config{}))

	providers, ok := tree["providers"].(map[string]any)
	require.True(t, ok, "published config has no providers map")
	require.NotEmpty(t, providers)

	masqueradesChecked := 0
	for name, p := range providers {
		provider, ok := p.(map[string]any)
		require.Truef(t, ok, "provider %q is not a mapping", name)
		assertClaimed(t, "providers."+name, []map[string]any{provider}, reflect.TypeOf(Provider{}))

		masquerades := mappings(t, name+".masquerades", asSlice(provider["masquerades"]))
		assertClaimed(t, name+".masquerades[]", masquerades, reflect.TypeOf(Masquerade{}))
		masqueradesChecked += len(masquerades)

		assertClaimed(t, name+".frontingsnis[]",
			mappings(t, name+".frontingsnis", values(provider["frontingsnis"])),
			reflect.TypeOf(SNIConfig{}))
	}
	// Every entry is checked rather than a sample per provider. The generator
	// marshals a tagless struct, so in practice all masquerades carry the same
	// keys, but that is the generator's business — the point of this test is to
	// stop trusting the generator's shape.
	require.NotZero(t, masqueradesChecked, "no masquerades were checked")

	assertClaimed(t, "trustedcas[]",
		mappings(t, "trustedcas", asSlice(tree["trustedcas"])),
		reflect.TypeOf(CA{}))
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

// assertClaimed fails for any key across nodes that no field of typ unmarshals
// from and that isn't excepted for typ in unmodeledKeys. Taking every node at a
// level rather than a sample keeps coverage total; the tag set is resolved once
// and unclaimed keys are reported as a set, so 2000+ masquerades cost one pass
// and produce one readable failure.
func assertClaimed(t *testing.T, path string, nodes []map[string]any, typ reflect.Type) {
	t.Helper()
	claimed := yamlKeys(typ)
	excepted := unmodeledKeys[typ]
	seen := make(map[string]bool)
	var unclaimed []string
	for _, node := range nodes {
		for k := range node {
			if claimed[k] || excepted[k] || seen[k] {
				continue
			}
			seen[k] = true
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

// mappings asserts every element of vals is a YAML mapping and returns them.
func mappings(t *testing.T, path string, vals []any) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(vals))
	for i, v := range vals {
		m, ok := v.(map[string]any)
		require.Truef(t, ok, "%s[%d] is not a mapping", path, i)
		out = append(out, m)
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// values returns the values of a YAML mapping, discarding the keys — used where
// the keys are data (country codes) rather than field names.
func values(v any) []any {
	m, _ := v.(map[string]any)
	out := make([]any, 0, len(m))
	for _, val := range m {
		out = append(out, val)
	}
	return out
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
