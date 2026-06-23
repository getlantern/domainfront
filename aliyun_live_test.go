package domainfront

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

// TestAliyunProviderLive exercises aliyun-provider.yaml against the real Aliyun
// CDN. It proves the security-critical path end to end: the config's GlobalSign
// root verifies the live Alibaba *.tbcdn.cn chain, the generated SNI is accepted
// by the edge, and the edge routes a *cross-organization* Host (Bilibili's
// s1.hdslb.com) over a TLS session that presents Alibaba's certificate — i.e.
// domain fronting works through this library's own dial + verify code.
//
// Skipped by default (it talks to the public internet). Run with:
//
//	DOMAINFRONT_LIVE=1 go test -run TestAliyunProviderLive -v
func TestAliyunProviderLive(t *testing.T) {
	if os.Getenv("DOMAINFRONT_LIVE") == "" {
		t.Skip("live network test; set DOMAINFRONT_LIVE=1 to run")
	}

	raw, err := os.ReadFile("aliyun-provider.yaml")
	require.NoError(t, err)

	cfg, err := ParseConfigYAML(raw)
	require.NoError(t, err)

	// The GlobalSign root parses into a usable pool.
	pool, err := cfg.CertPool()
	require.NoError(t, err)

	// Expand with a country code so FrontingSNIs drives the wire SNI
	// (config.go only emits SNI when countryCode != "").
	require.Contains(t, cfg.Providers, "aliyun", "aliyun-provider.yaml must define the 'aliyun' provider")
	p := ExpandedProvider(cfg.Providers["aliyun"], "cn")
	require.NotEmpty(t, p.Masquerades)

	const crossOrgHost = "s1.hdslb.com" // Bilibili — unrelated to Alibaba

	// Phase 1: prove the security-critical path through the library's own
	// dialFront — the config's GlobalSign root verifies the live Alibaba
	// *.tbcdn.cn chain under the production Chrome_131 ClientHello, for every
	// masquerade, using the SNI that FrontingSNIs generated.
	// For each masquerade: dial with the production Chrome_131 ClientHello
	// (which Aliyun answers with HTTP/2 over ALPN), then drive the library's
	// real doRequest — proving the h2 transport path fronts a cross-org Host
	// (Bilibili) over a TLS session bearing Alibaba's certificate.
	var dialed int
	var frontedOK, frontedOverH2 bool
	for _, m := range p.Masquerades {
		require.NotEmpty(t, m.SNI, "expanded masquerade should carry an SNI")

		f := newFront(m, "aliyun")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		res := dialFront(ctx, f, pool, utls.HelloChrome_131, NetDialer{})
		if res.err != nil {
			cancel()
			t.Logf("dial %s (SNI %s) failed: %v", m.IpAddress, m.SNI, res.err)
			continue
		}
		dialed++
		proto := negotiatedProtocol(res.conn)
		t.Logf("TLS+verify OK: ip=%s sni=%s alpn=%s (cert chained to config's GlobalSign root)", m.IpAddress, m.SNI, proto)

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+crossOrgHost+"/", nil)
		resp, rerr := (&roundTripper{}).doRequest(req, res.conn, crossOrgHost, nil)
		if rerr != nil {
			res.conn.Close()
			cancel()
			t.Logf("fronted GET via %s failed: %v", m.IpAddress, rerr)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close() // h2Body close tears down the conn
		cancel()
		t.Logf("fronted %s via %s (SNI %s, %s): HTTP %d, proto=HTTP/%d, body=%q",
			crossOrgHost, m.IpAddress, m.SNI, proto, resp.StatusCode, resp.ProtoMajor, strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusOK {
			frontedOK = true
			// Only count it as proving the h2 path when ALPN actually
			// negotiated h2 and the response came back as HTTP/2.
			if proto == "h2" && resp.ProtoMajor == 2 {
				frontedOverH2 = true
			}
		}
	}
	require.NotZero(t, dialed, "no Aliyun edge IP completed TLS + GlobalSign verification")
	require.True(t, frontedOK, "no edge served the cross-org Host (%s) — fronting did not route", crossOrgHost)
	require.True(t, frontedOverH2, "no edge fronted %s over HTTP/2 — the h2 path was not exercised", crossOrgHost)
}
