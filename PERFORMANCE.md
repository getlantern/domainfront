# Performance Comparison: `domainfront` vs `fronted`

Benchmarks run on Apple M4 Pro, Go 1.24, `go test -bench=. -benchmem -count=3`.

## Goroutine Load

| Metric | `fronted` | `domainfront` | Improvement |
|--------|-----------|---------------|-------------|
| Goroutines during operation | 15 | 3 | **5x fewer** |
| Goroutines leaked after Close | 6 | 0 | **Clean shutdown** |

`fronted` spawns ~15 goroutines: 1 keepcurrent runner, 1 keepcurrent data channel consumer, 10 pond workers, 1 findWorkingFronts loop, 1 maintainCache, plus any leaked from pond. `domainfront` spawns exactly **3**: crawler, cacheSaver, and (optionally) configUpdater. All exit cleanly on `Close()` with zero leaks.

## Hot Path: Take/Return Cycle

| Operation | `fronted` | `domainfront` |
|-----------|-----------|---------------|
| Take + Return | 17 ns/op, 0 allocs | 68 ns/op, 0 allocs |

`fronted` is ~4x faster here because it's a raw buffered channel send/receive. `domainfront` uses the same channel internally but `ReturnSuccess` also calls `markSucceeded()` (mutex lock + `time.Now()`). This 50ns difference is **negligible** compared to the ~5-50ms TLS dial that follows every Take.

## Candidates/Sort (called by crawler + cache saver)

| Operation | `fronted` | `domainfront` | Improvement |
|-----------|-----------|---------------|-------------|
| 5000 fronts sort | 677 us, 82 KB | 359 us, 205 KB | **1.9x faster** |

`domainfront` is nearly **2x faster** because it snapshots timestamps outside the lock and sorts without acquiring per-front read locks during comparison. It uses more memory (205 KB vs 82 KB) because of the parallel `indexed` struct array — a deliberate trade of ~120 KB temporary memory for halved sort time and reduced lock contention.

## Provider Lookup

| Operation | `fronted` | `domainfront` | Improvement |
|-----------|-----------|---------------|-------------|
| Exact host alias match | 37 ns/op | 34 ns/op | ~same |
| Passthrough pattern match | 53 ns/op | 39 ns/op | **1.4x faster** |

`domainfront` pre-lowercases passthrough patterns at config load time, saving a `strings.ToLower` on every lookup in the hot path.

## SNI Generation

| Operation | `fronted` | `domainfront` | Improvement |
|-----------|-----------|---------------|-------------|
| GenerateSNI | 49 ns/op, 1 alloc | 51 ns/op, 0 allocs | **Zero allocs** |

Same speed, but `domainfront` avoids the allocation by taking `string` instead of `*Masquerade`.

## Request Rewriting

| Operation | `fronted` | `domainfront` |
|-----------|-----------|---------------|
| Rewrite request | 339 ns/op, 6 allocs | 330 ns/op, 6 allocs |

Essentially identical — same fundamental work.

## Structural/Memory Improvements

| Concern | `fronted` | `domainfront` |
|---------|-----------|---------------|
| Front list growth | Unbounded append (`addFronts`) — grows forever on config updates | `Replace()` atomic swap — bounded to config size |
| Sort under lock | `sortedCopy()` holds RLock during O(n log n) sort | Sort happens **outside** the lock |
| Per-front locks during sort | Sort comparator calls `lastSucceeded()` = O(n log n) lock acquisitions | Timestamps snapshotted once = O(n) lock acquisitions |
| Dependencies | `pond`, `keepcurrent`, `ops` + transitive deps | Only `utls` + `go-yaml` |

## Speed to Working Fronts

Both use the same fundamental approach (parallel vetting with POST to test URL), so time-to-first-working-front is dominated by network latency (~50-200ms per TLS dial). The key structural difference: `domainfront`'s crawler doesn't need `pond` — it uses a simple semaphore + WaitGroup with the same concurrency (10 workers), avoiding the worker pool library overhead and goroutine pool lifecycle.

## Bottom Line

`domainfront` is **not dramatically faster at the micro-benchmark level** — the hot paths (Take/Return, Lookup, rewrite) are in the same ballpark. The real wins are:

1. **5x fewer goroutines** (3 vs 15), zero leaks on shutdown
2. **Bounded memory** — no unbounded front list growth on config updates
3. **2x faster sort** with less lock contention on the candidate list
4. **Cleaner shutdown** — single context cancellation vs multiple stop channels
5. **Fewer dependencies** — smaller binary, less supply chain surface
