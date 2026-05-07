# Changelog

All notable changes to Floo will be documented in this file.

## [Unreleased]

### Changed (perf hygiene + correctness, post-0.2.0 audit)
Cooldown-controlled A/B vs the 0.2.0 baseline (M1, 4 streams ×
8 tunnels, 5 s iperf3 trials, alternating order):

| Cipher    | baseline | this    | Δ                  |
|-----------|----------|---------|--------------------|
| plaintext | 18.25    | 17.80   | -2.5 % (noise)     |
| aes-128   | 28.15    | 28.45   | +1.1 % (noise)     |
| aes-256   | 26.35    | 26.90   | +2.1 % (noise)     |
| aegis-128 | 20.85    | 20.40   | -2.2 % (noise)     |
| chacha20  | ~7.0     | 7.42    | +6 % (consistent)  |

Headline: **chacha20** sees a real ~6 % win, others sit inside the bench
noise window (~±5 %). The chacha20 delta is consistent with the relaxed
atomic ordering (`.acq_rel → .monotonic`): chacha20 is the only
software-only cipher, so per-frame `dmb ish` fences are a larger share
of its budget than they are for hardware-accelerated AES/AEGIS.

- Hot-path mutexes (`Channel.send_mutex`, `TunnelConnection.streams_mutex`,
  `TunnelClient.connections_mutex`, plus the UDP `sessions_mutex` and
  per-session `mutex`) switched from `std.Io.Mutex` to a new
  `common.HotMutex` shim — `os_unfair_lock` on Darwin, raw `linux.futex`
  v1 (3-state Drepper) on Linux. Why: we have no fibers, only OS threads,
  so `Io.Mutex`'s `io.futexWaitUncancelable` vtable hop on the contended
  path is dead weight. Why no measurable speedup: critical sections here
  are dominated by AEAD encrypt + writev (microseconds), so a few-ns
  mutex-impl cost is below the noise floor of the whole frame.
  - The 0.2.0 CHANGELOG cited "Io.Mutex futex paths" as the v0.1.5
    regression source. That was speculation: `Io.Mutex`'s uncontended
    fast path is already a single `cmpxchgStrong` (`std/Io.zig:1599`), and
    `HotMutex`'s `cmpxchgWeak` fast path is at most one LL/SC pair
    cheaper on ARM — not enough to explain a 30 % delta. The real cause
    of the v0.1.5 → v0.2.0 plaintext drop remains open (see "Open" below).
- `Channel.encryptInPlace` no longer calls `clock_gettime` twice per
  frame when `EncryptionStats` is null. Server/client now leave stats
  null by default; the encrypt-time profile printed at process exit is
  re-enabled by setting the **`FLOO_PROFILE_ENCRYPT=1`** environment
  variable (no flag-renaming churn, no silent capability loss). On
  Darwin / Linux, `clock_gettime(MONOTONIC)` is a userspace
  commpage/vDSO read (~10–20 ns each), not a syscall — so the
  per-frame saving is ~30–40 ns, ~1 % of one core at 22 Gbps. Cheap
  to take, but don't expect it to show up in the bench.
- `common.writeFrameDirect`'s `EAGAIN: continue` was dead under blocking
  sockets (which is the whole data path) and would deadlock every
  `send_mutex` holder if a future change ever flipped a data-path
  socket non-blocking. Now returns `error.WriteFailed` so the failure
  surfaces and propagates through the existing `handleSendFailure`
  path rather than spinning indefinitely under the lock.
- Throughput byte counters (`tx_bytes`/`rx_bytes` `fetchAdd`) and
  encryption counters relaxed from `.acq_rel` to `.monotonic`. They
  are write-only counters read once at shutdown — no other thread
  depends on the ordering. On ARM this drops a `dmb ish` per frame
  and is the most likely source of the chacha20 win above.

### Fixed
- **SIGTERM was unbound** in both server and client signal-action
  setup (only SIGINT/SIGHUP/SIGUSR1 were registered). The handler at
  `handleSignal` already accepts SIGTERM, but without a matching
  `posix.sigaction(posix.SIG.TERM, ...)` the kernel took the
  default-action path and process-killed before any `defer` ran. Net
  effects of the previous behaviour:
  - `defer diagnostics.flush*` never fired on `kill` / systemd stop /
    Docker `SIGTERM` — the `[PROFILE] ... encryption ...` and
    `[PROFILE] ... throughput ...` lines were silently lost in the
    common production-shutdown path.
  - The `cleanup()` paths inside `TunnelConnection` / `TunnelClient`
    wouldn't run, leaking sockets until the OS reclaimed them.
  - SIGINT (Ctrl-C) was the only graceful-shutdown signal that
    actually worked, which is contrary to the convention every
    process supervisor expects.
  Now binds SIGTERM through the same handler.

### Open (reviewer-flagged, not addressed in this patch)
- **Per-iteration pollfd rebuild** (`server.zig` recv loop ~803-829,
  `client.zig` similar). The `streams_mutex` is taken on every poll
  cycle to walk the hashmap and rebuild the pollfd array, doing one
  `acquireRef`/`releaseRef` per stream per cycle. Streams change
  rarely (per CONNECT / CLOSE) but the array is rebuilt on every wake.
  Caching the array with a generation-counter invalidation is the
  most likely real throughput win on this codebase, and the most
  likely true source of the v0.1.5 → v0.2.0 plaintext regression.
- **Plaintext vs AES anomaly** (~18 vs ~22 Gbps on M1 loopback). Asserted
  earlier as a pacing artifact without proof. Open until someone runs
  `iperf3 -l {8K, 128K, 1M}` across both ciphers and locates where the
  curves cross.

## [0.2.0] - 2026-05-06

### Changed (Zig 0.16 migration)
- **Targets Zig 0.16.0 stable** (was 0.16.0-dev / master tracking).
  `minimum_zig_version` bumped accordingly.
- Migrated the entire I/O surface to `std.Io`. The audit-time medium-level
  `std.posix.*` socket/file wrappers (close, recv, send, socket, bind,
  listen, accept, connect, writev, recvfrom, sendto, fcntl, pipe2,
  shutdown, socketpair) were removed in 0.16.
  - TCP uses `std.Io.net.Server` + `std.Io.net.Stream`.
  - UDP uses `std.Io.net.Socket` + `IncomingMessage` (no more manual
    sockaddr juggling for source addresses).
  - Filesystem uses `std.Io.Dir.cwd().readFileAlloc(io, ...)`.
  - Mutexes are `std.Io.Mutex` with `lockUncancelable(io)`.
- Retired `src/net_compat.zig` shim (~170 lines); callers use
  `std.Io.net.IpAddress` directly.
- `pub fn main()` takes `std.process.Init` and uses the gpa + io
  provided by `start.zig` (DebugAllocator in debug, smp_allocator in
  release).
- Process arg handling moved from `process.argsAlloc` to
  `process.Args.Iterator`.
- Allocator pattern: `GeneralPurposeAllocator` → `DebugAllocator`
  (debug, with leak tracking) and `smp_allocator` (release, lock-free).
- CI workflows pinned to `version: 0.16.0` (was `master`).

### Performance
- Hot data path bypasses the buffered `Stream.Writer` interface and
  calls `std.c.writev` directly (one syscall per length-prefixed frame,
  matching the pre-migration scatter-gather semantics). The audit-noted
  3× regression from the buffered writer was largely recovered:
  - aes-256-gcm: +53% multi-stream
  - aes-128-gcm: +46% multi-stream
  - aegis-256: +71% multi-stream
  - plaintext: +26% multi-stream
- Throughput is now within ~30% of the v0.1.5 README baseline (host
  noise on this machine accounts for some of the gap; remaining headroom
  is in `Io.Mutex` futex paths vs the original `pthread_mutex_t`).

### Fixed
- **Reverse-mode multi-stream race**: `addr.listen(.reuse_address=true)`
  sets BOTH SO_REUSEADDR and SO_REUSEPORT on POSIX. SO_REUSEPORT load-
  balances new connections across all listeners on the same port — and
  during the floo server's reverse-listener rebind (one tunnel handing
  off to another), the kernel briefly routed connections to the
  soon-to-die listener, getting them reset. Fixed by constructing the
  reverse listener via raw libc `socket + setsockopt(SO_REUSEADDR) +
  bind + listen` (new `common.bindListener`).
- **LocalConnection / Stream ref-counting leak**: the old pattern was
  `create()→ref=1, acquireRef()→ref=2, put(map)`, where only ONE ref
  was ever released (creation ref leaked → small per-connection memory
  leak). Surfaced by 0.16's `DebugAllocator`. Fixed by treating the
  create ref AS the map ref; no extra `acquireRef` before `put`.
- `TunnelConnection.create` heartbeat-spawn error path had an
  `errdefer allocator.destroy(conn)` AND an explicit
  `allocator.destroy(conn)` — double-free on `Thread.spawn` failure.
- `RateLimiter.tryAcquire` no longer short-circuits in Debug mode (the
  zig compiler bug it worked around is fixed; the bypass was a footgun
  for tests).
- `diagnostics.zig` no longer writes to a hardcoded `/tmp/floo_profile.log`
  (audit-flagged smell + std.fs.createFileAbsolute removed in 0.16).

### Removed
- `src/net_compat.zig` (replaced by `std.Io.net.IpAddress`).
- Self-pipe signal-wake mechanism (posix.pipe2 was removed in 0.16).
  Signals still set atomic flags; the 1s poll iteration picks them up,
  giving up to 1s shutdown latency vs the old sub-millisecond.
- Inline `forwardLocalData`/`forwardTargetData` tests (depended on
  `posix.socketpair` and `common.sendAllToFd`, both gone in 0.16).
  Coverage will return via an integration test harness.

## [0.1.5] - 2025-11-19

### Changed
- Migrated to Zig master branch (0.16.0-dev) for latest performance improvements.
- Updated CI/CD workflows to support Zig master.
- Fixed Linux compilation issues regarding `sigset_t` initialization.

### Performance
- **22.2 Gbps** AES-128-GCM throughput (Reverse Mode, M1).
- AES-GCM now outperforms AEGIS ciphers on hardware with AES-NI/ARMv8 Crypto extensions.
- Outperforms Rathole by ~1.5x and FRP by ~2.1x.

## [0.1.4] - 2025-11-09

### Performance
- **30.9 Gbps** plaintext throughput (single stream, M1)
- **22.1 Gbps** AEGIS-128L encrypted throughput (single stream, M1)
- **23.3 Gbps** AEGIS-128L reverse mode (single stream, M1)
- 3.4x faster than FRP in single-stream benchmarks
- 1.3x faster than Rathole with AEGIS-128L
- Multi-stream performance: 7.7-9.6 Gbps (4 concurrent streams)

### Changed
- Updated benchmark methodology for better accuracy (single-stream testing)
- Enhanced performance testing coverage across all cipher types
- Improved documentation with comprehensive architecture explanation

### Documentation
- Added detailed architecture deep-dive
- Updated benchmark results with single-stream and multi-stream comparisons
- Added cipher performance comparison tables
- Documented data flow paths and design patterns

## [0.1.3] - 2024-11-08

### Added
- Reference counting for streams and connections to prevent use-after-free bugs
- Comprehensive reverse forwarding examples (Emby/Jellyfin)
- Multi-client load balancing example
- Corporate proxy tunneling example
- Dedicated `configs/` directory for configuration templates
- Socket buffer size configuration support (up to 8MB)

### Changed
- Simplified TOML configuration format
- Improved stream lifecycle management with proper cleanup
- Updated benchmark script to test both forward and reverse modes
- Reorganized project structure for better clarity
- Enhanced documentation with clearer examples

### Fixed
- **Critical**: Reverse forwarding crashes after first request
- **Critical**: Use-after-free vulnerability in ReverseListener
- **Critical**: Mutex deadlocks during blocking I/O operations
- Memory leaks in stream and connection cleanup
- Signal handling for SIGPIPE and EINTR
- Hardware crypto acceleration on ARM processors (restored 22+ Gbps performance)

### Performance
- AEGIS-128L: 22.6 Gbps (encrypted with hardware acceleration)
- AES-256-GCM: 18.0 Gbps (2.2x faster than FRP)
- Plaintext: 28+ Gbps single stream
- Reverse mode now performs as well as forward mode

### Security
- Fixed timing attack vulnerability in token comparison
- All PSK comparisons now use constant-time equality checks

## [0.1.2] - Previous Release

Initial stable release with basic forward and reverse tunneling support.