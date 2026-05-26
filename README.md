# domainfront

A clean, production-grade domain fronting library for Go.

`domainfront` tunnels HTTP traffic through CDN infrastructure (CloudFront, Akamai, etc.) using domain fronting — connecting to a CDN edge IP with one hostname in the TLS SNI extension while routing the HTTP request to a different origin via the `Host` header. This makes it difficult for network observers to determine the true destination of traffic.

**Important:** This library is not a general-purpose HTTP client. It only works for origin hosts that have been **explicitly mapped** in the configuration. Each origin you want to reach (e.g. `config.example.com`) must have a corresponding CDN distribution set up to proxy traffic to it, and that mapping must be listed in the provider's `hostaliases`. If you try to send a request to an unmapped host, the library will return an error — it cannot front arbitrary destinations.

## Features

- **No global state** — all state lives on `*Client`; safe to run multiple instances
- **Context-driven lifecycle** — a single `context.Context` controls all background goroutines; `Close()` shuts everything down cleanly
- **Atomic config updates** — `FrontPool.Replace()` swaps the candidate set without unbounded growth, preserving state from previously-working fronts
- **Smart round-trip** — checks provider host mapping *before* dialing TLS, avoiding wasted connections
- **TLS fingerprinting** — uses [utls](https://github.com/refraction-networking/utls) to mimic real browser Client Hellos (Chrome 131 by default)
- **Country-aware SNI** — deterministic SNI selection from per-country lists, derived from IP hash
- **Persistent caching** — working fronts are cached to disk (JSON) for fast startup
- **Auto-updating config** — optionally fetches updated `fronted.yaml.gz` from a URL every 12 hours
- **Minimal dependencies** — only `utls` and `go-yaml`; no worker pool libraries, no logging frameworks, no custom HTTP fetchers
- **Fully testable** — `Dialer` and `Cache` interfaces; unit tests use pipe-based mock TLS servers, no real CDN infrastructure required

## Installation

```bash
go get github.com/getlantern/domainfront
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "os"

    "github.com/getlantern/domainfront"
)

func main() {
    // Load configuration (typically embedded in your binary)
    configData, _ := os.ReadFile("fronted.yaml.gz")
    config, err := domainfront.ParseConfig(configData)
    if err != nil {
        panic(err)
    }

    // Create client
    ctx := context.Background()
    client, err := domainfront.New(ctx, config,
        domainfront.WithCacheFile(domainfront.DefaultCacheFilePath()),
        domainfront.WithCountryCode("us"),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Use the RoundTripper for all HTTP requests
    httpClient := &http.Client{Transport: client.RoundTripper()}

    resp, err := httpClient.Get("https://config.example.com/api/data")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

## Configuration

The library accepts the same `fronted.yaml.gz` format used by [getlantern/fronted](https://github.com/getlantern/fronted). The key concept is the **provider**, which represents a CDN (CloudFront, Akamai, etc.) through which traffic is tunneled. Each provider declares:

- **`hostaliases`** — the mapping from origin hostnames you want to reach to CDN distribution hostnames that proxy to them. You must set up each CDN distribution separately to forward traffic to your origin, then list the mapping here. Only origins listed in `hostaliases` (or matching a `passthrupatterns` wildcard) can be reached through the library.
- **`masquerades`** — CDN edge IPs and domains to connect to. These are the actual TLS endpoints the library dials.
- **`testurl`** — a URL used to vet whether a masquerade is working (should return 202 on POST).

```yaml
trustedcas:
  - commonname: "Amazon Root CA 1"
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----

providers:
  cloudfront:
    hostaliases:
      config.example.com: d1234.cloudfront.net
    passthrupatterns:
      - "*.cloudfront.net"
    testurl: https://d1234.cloudfront.net/ping
    masquerades:
      - domain: d5678.cloudfront.net
        ipaddress: 13.224.0.1
  akamai:
    hostaliases:
      api.example.com: api.dsa.akamai.example.com
    testurl: https://fronted-ping.dsa.akamai.example.com/ping
    frontingsnis:
      default:
        usearbitrarysnis: false
      br:
        usearbitrarysnis: true
        arbitrarysnis:
          - mercadopago.com
          - amazon.com.br
    masquerades:
      - domain: a248.e.akamai.net
        ipaddress: 23.192.228.145
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithCacheFile(path)` | Path for persistent front cache | No caching |
| `WithCache(cache)` | Custom `Cache` implementation | `NopCache` |
| `WithCountryCode(cc)` | Country code for SNI selection | `""` (use default SNI config) |
| `WithConfigURL(url)` | URL to fetch config updates from | No auto-update |
| `WithHTTPClient(client)` | HTTP client for config fetches | `http.DefaultClient` |
| `WithDialer(dialer)` | Custom TCP dialer | `net.Dialer{}` |
| `WithClientHelloID(id)` | utls Client Hello fingerprint | `HelloChrome_131` |
| `WithDefaultProviderID(id)` | Fallback provider ID | `"cloudfront"` |
| `WithMaxRetries(n)` | Max round-trip retry attempts | `6` |
| `WithCrawlerConcurrency(n)` | Parallel front-vetting goroutines | `10` |
| `WithLogger(logger)` | `*slog.Logger` for diagnostics | `slog.Default()` |

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │                  Client                     │
                    │                                              │
  New(ctx, config)──┤  ┌──────────┐  ┌─────────┐  ┌────────────┐ │
                    │  │ Crawler  │  │  Cache   │  │  Config    │ │
                    │  │ (vets    │  │  Saver   │  │  Updater   │ │
                    │  │  fronts) │  │ (5s/dirty│  │ (12h fetch)│ │
                    │  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
                    │       │             │              │         │
                    │       ▼             ▼              │         │
                    │  ┌─────────────────────────┐       │         │
                    │  │      frontPool          │◄──────┘         │
                    │  │  (Take / Return / Replace)                │
                    │  └────────┬────────────────┘                 │
                    │           │                                   │
                    │           ▼                                   │
  RoundTripper ─────┤  1. Take(ctx) → front                       │
                    │  2. provider.Lookup(host) → fronted host     │
                    │  3. dialFront(front) → TLS conn              │
                    │  4. rewrite request → send over conn         │
                    │  5. Return(front, succeeded)                 │
                    └──────────────────────────────────────────────┘
```

### Key Design Decisions

**Check mapping before dialing.** The `RoundTripper` verifies that the provider has a host mapping for the origin *before* establishing a TLS connection. If not, the front is returned as "good" (it's not the front's fault) and the next front is tried. This avoids wasting expensive TLS handshakes.

**Channel-based ready queue.** Working fronts flow through a buffered channel. `Take` is a simple `select` on the ready channel and context — no `sync.Cond`, no goroutine-per-call overhead.

**Atomic Replace.** Config updates call `frontPool.Replace()` which swaps the candidate set while preserving `LastSucceeded` timestamps from matching fronts (keyed by provider+domain+IP). The ready channel is drained and the crawler repopulates it.

**Timestamp-snapshot sorting.** `candidates()` snapshots all `LastSucceeded` timestamps into a parallel array before sorting, avoiding O(n log n) per-front lock acquisitions during the sort comparator.

## File Layout

```
domainfront.go    Client, New(), options, background goroutines
config.go         Config/Provider/Masquerade/CA types, YAML parsing
front.go          front type, frontPool (Take/Return/Replace)
dialer.go         TLS dialing with utls, cert verification
roundtrip.go      RoundTripper, request rewriting, retry logic
sni.go            Deterministic SNI generation from IP hash
cache.go          Cache interface, FileCache (JSON), NopCache
fileutil.go       File read/write helpers
```

## Migrating from `getlantern/fronted`

| `fronted` | `domainfront` |
|-----------|---------------|
| `fronted.NewFronted(opts...)` | `domainfront.New(ctx, config, opts...)` |
| `f.NewConnectedRoundTripper(ctx, addr)` | `client.RoundTripper()` (reusable) |
| `fronted.SetLogger(logger)` | `domainfront.WithLogger(logger)` |
| `fronted.WithCacheFile(path)` | `domainfront.WithCacheFile(path)` |
| `fronted.WithConfigURL(url)` | `domainfront.WithConfigURL(url)` |
| Global `log` variable | Per-client `*slog.Logger` |
| `stopCh` / `cacheClosed` / `sync.Once` | Single `context.Context` |
| `threadSafeFronts.addFronts()` (append-only) | `frontPool.Replace()` (atomic swap) |
| 4000-capacity buffered channel | Channel-based ready queue |
| `pond` worker pool | Semaphore + WaitGroup |
| `keepcurrent` library | Simple HTTP fetch loop |
| `ops` library | `log/slog` |

## License

Apache 2.0
