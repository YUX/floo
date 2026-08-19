# Changelog

All notable changes to Floo will be documented in this file.

## [0.3.0] - 2026-08-19

Protocol v2 only. There is no 0.2.x wire interop — mismatched peers fail closed at decrypt or version exchange.

### Protocol v2

- Encrypted frames are `[u32be length][u64be seq][ciphertext || 16-byte tag]`. AEAD AAD is the 12-byte prefix `length || seq`.
- `cipher = "none"` frames stay `[u32be length][plaintext]` (no seq) after the existing PSK nonce/HMAC exchange.
- `ServiceId` is `u32` (was `u16`). Stream headers are 9 bytes (`type` + service + stream).
- `generateServiceId` uses the first 4 Blake3 bytes, rejects `0`, and still fails closed on collision.
- `MessageType.parse` / `ErrorCode.parse` return errors instead of `@enumFromInt`.
- Channel encrypt is lock-free (`fetchAdd` on the send seq); only `writev` stays under the send mutex. Decrypt uses the frame seq.

### Migration

See [MIGRATION_NOTES.md](MIGRATION_NOTES.md) for the 0.2 → 0.3 cut. Both sides must be 0.3.0.

### Security (post-0.2.1 audit hardening)

- **`cipher = "none"` no longer disables authentication.** Audit finding S-1.
  Previously, plaintext mode skipped the entire Noise XX handshake including
  the post-split HMAC-SHA256 PSK proof-of-knowledge — the documented "Debug
  only" mode was effectively an open relay where per-service tokens leaked
  in cleartext to anyone who could reach the port. Plaintext mode now runs a
  small mutual handshake (each side draws a 32-byte random nonce, exchanges
  nonces, and both compute `HMAC-SHA256(psk, "floo-plaintext-psk-v1" ||
  initiator_nonce || responder_nonce || role_byte)`; tags are
  constant-time-compared via `common.constantTimeEqual`). Confidentiality
  and frame integrity are still off — that remains the documented meaning
  of `cipher = "none"` — but the connection drops cleanly when either side
  doesn't know the PSK.
- **PSK is now mandatory regardless of cipher.** A previously-empty PSK
  with `cipher = "none"` is now refused at config-load time with
  `error.MissingPsk` and a `[SECURITY]` log line explaining why.
- **Coarse low-entropy credential gate.** S-5. PSKs that pass the >=16-char
  length check but contain fewer than 8 distinct byte values
  (`AAAAAAAAAAAAAAAA`, `abababababababab`, …) are now rejected as
  `error.WeakPSK`. Doesn't try to catch every weak passphrase — the README
  says "use `openssl rand`", the length gate filters fat-finger inputs, and
  this catches the long tail of obvious low-entropy strings.
- **HTTP CONNECT credential safety documented.** S-7. The base-64 encoder
  is invoked *after* `username:password` concatenation, so any CR/LF in
  the credential becomes a regular base-64 character before reaching the
  HTTP header line — header injection is impossible by construction.
  Inline comment added so the ordering doesn't get flipped in a future
  refactor.

### Added

- **`--doctor` now covers UDP service ports and reverse-service targets.**
  D-1. UDP services are probed with a datagram `bind()` rather than the
  pre-fix wrongly-used TCP `listen()` (which would warn-with-noise on a
  free UDP port). Reverse-service local targets get a real TCP connect
  probe (or, for UDP reverse, a sender-socket sanity check) so the
  operator notices when their local Jellyfin / Plex / etc. isn't running
  before they ship.

### Fixed

- **UDP server `sessionRecvThread` socket recv timeout.** S-2. A target
  server that never replied previously pinned the thread + its UDP socket
  + its `Session` struct for the lifetime of the process — the only exit
  path was an explicit `shutdown(SHUT_RD)` from `removeSession`, which
  doesn't fire until something else triggers session teardown. Each session
  socket now has SO_RCVTIMEO of 1 second; the thread wakes periodically
  to re-check `running`/`forwarder.running` and continues on EAGAIN/EWOULDBLOCK.
- **RateLimiter slow-path no longer over-refills under contention.** S-4.
  Two concurrent slow-path callers used to both observe `elapsed >= interval`,
  both `tokens.store(max_tokens)`, and both `fetchSub(1)` — briefly letting
  through `max_tokens × N_concurrent` rather than just `max_tokens`. Now the
  refill timestamp is the single-winner CAS gate: `last_refill.cmpxchgStrong(last, now)`
  succeeds for exactly one thread, which then publishes `max_tokens - 1` in a
  single store (taking its own token in the same publish to avoid the brief
  `tokens == max_tokens` race window). Losers fall through and return false
  (or hit the fast path on the next call). Statistical-only behaviour, but
  the CHANGELOG had previously claimed this was hardened in WP-07 and it
  wasn't quite.
- **Triaged the silent `catch {}` cluster in `client.zig`.** R-1.
  Six medium-severity sites that previously dropped errors on the floor —
  REVERSE error / connect-error / CONNECT_ACK encode-and-send (lines 1065,
  1090, 1123), the CLOSE-frame send (line 1312), the multi-service UDP
  attachment + forwarder registration (lines 1995, 2002), and the periodic
  UDP session eviction in the main loop (line 2036) — now log on failure.
  Sleep-failure swallows in retry loops are kept (sleep "should never fail",
  and the loop just runs the next iteration).

### Performance

- **Cached pollfd array with generation-counter invalidation.** P-1.
  Resolves the "Open" item from the previous patch. Both server.zig's
  `TunnelConnection.run()` and client.zig's `TunnelClient.run()` previously
  cleared and rebuilt their `poll_fds + poll_entries` arrays every poll
  wakeup — taking `streams_mutex` / `connections_mutex` for the duration
  of a hashmap walk and doing one `acquireRef` per stream per cycle, even
  though the map only changes on CONNECT / CLOSE. Now: every insert/remove
  bumps a `streams_generation` / `connections_generation` atomic under the
  same lock; the recv loop reads the generation each cycle and only
  rebuilds when it differs from `last_built_generation`. Borrow refs
  survive across poll cycles in the cached array and are released on
  rebuild (or scope exit on disconnect). Final array of borrowed refs is
  drained via the existing `defer` cleanup so no leak on any exit path.

  Cooldown A/B vs the v0.2.0 baseline (M1 8 vCPU, 4 streams × 8 tunnels ×
  3 s, ReleaseFast, single trial each, receiver-side throughput):

  | Cipher    | baseline | post-fix | Δ                  |
  |-----------|---------:|---------:|--------------------|
  | aes128gcm |     22.1 |   **24.4** | +10.4 %          |
  | aes256gcm |     20.9 |     22.2 | +6.2 %             |
  | aegis128l |     19.4 |     20.5 | +5.7 %             |
  | aegis256  |     21.3 |     20.4 | -4.2 % (noise)     |
  | chacha20  |     6.82 |     6.65 | -2.5 % (noise)     |
  | none      |     19.4 |     18.7 | -3.6 % (noise; S-1 adds a one-time PSK round-trip at connect) |

  Hardware-accelerated AEAD ciphers see a clear 5–10 % win because AEAD
  cost is small and poll-loop overhead is a larger share of the per-frame
  budget; ChaCha20 (software-only AEAD) and plaintext are AEAD-bound /
  data-path-bound so the poll-loop savings are absorbed in noise.

- **Coalesce already-encrypted frames into one `writev` under the send
  lock.** Phase 3 stacks showed `writev` at 46–76% of the client hot path.
  `Channel` now queues prepared frames and the poll loop flushes them once
  per wakeup (`common.writeFramesDirect`), so several ready streams share
  one syscall. Still blocking; no non-blocking sockets / POLL.OUT.

  Same-machine A/B vs `bench/baseline.json` (Darwin arm64, ReleaseFast,
  5 s × 2, receiver-side SUM, 10 tunnels). Side-read drain was tried and
  reverted: 8K P=1 stayed inside ±5%, and the AES P=1 win survived
  drain-off.

  | Cell (forward)            | baseline | post | Δ |
  |---------------------------|---------:|-----:|---|
  | aes128gcm 128K P=1 t=10   |    10.21 | **11.59** | **+13.5 %** |
  | aes128gcm 1M P=1 t=10     |    10.51 | **11.46** | **+9.0 %** |
  | none 128K P=1 t=10        |     9.97 |  9.49 | −4.8 % (noise) |
  | aegis128l 128K P=1 t=10   |    10.51 | 10.51 |  0.0 % |
  | chacha20 128K P=1 t=10    |     2.83 |  2.99 | +5.7 % |
  | chacha20 128K P=4 t=10    |     7.89 |  8.96 | +13.5 % |

  `none` P=1 is unchanged (~10 Gbps vs raw 128K P=1 ~36 Gbps): the
  remaining wall is still a blocking `writev` per poll wakeup. AES P=4
  1M dropped ~15% (fatter HOL write); 1-tunnel P≥4 still kills the
  iperf3 control socket.

- **Default `io_batch_bytes` 128K → 512K** (still under the 1 MiB frame
  cap after the 9-byte DATA header + 16-byte AEAD tag). Side-read and
  per-stream send buffers follow the setting; the decoder grew to
  `12 + MAX_FRAME_SIZE + 64K` so a max-size encrypted frame plus the
  next read fits. Inbound `writeAllToHandle` leftover + side POLL.OUT
  was tried and reverted: 1-tunnel P≥4 still dies on the iperf3
  control socket.

  Focused A/B vs `bench/baseline.json` and coalesce HEAD
  (`/tmp/floo-bench-0.3-inbound`, Darwin arm64, ReleaseFast, 5 s × 2):

  | Cell (forward)            | baseline | coalesce | 512K | vs coal |
  |---------------------------|---------:|---------:|-----:|--------:|
  | aegis128l 128K P=1 t=10   |    10.51 |    10.51 | **11.86** | **+12.8 %** |
  | aes128gcm 128K P=1 t=10   |    10.21 |    11.59 | 11.60 | +0.1 % |
  | aes128gcm 1M P=1 t=10     |    10.51 |    11.46 | 11.68 | +1.9 % |
  | none 128K P=1 t=10        |     9.97 |     9.49 |  9.86 | +3.9 % |
  | chacha20 128K P=1 t=10    |     2.83 |     2.99 |  2.93 | −2.0 % |

  AEGIS was paying per-frame poll/`writev` overhead that 512K frames
  amortize. `none` P=1 is still ~10 Gbps vs raw ~40: copy-sized
  `writev` dominates, so fatter frames do not raise that ceiling.

### Changed (perf hygiene + correctness, post-0.2.0 audit)
Cooldown-controlled A/B vs the 0.2.0 baseline (M1, 4 streams ×
8 tunnels, 5 s iperf3 trials, alternating order):

| Cipher | baseline | this | Δ |
|-----------|----------|---------|--------------------|
| plaintext | 18.25 | 17.80 | -2.5 % (noise) |
| aes-128 | 28.15 | 28.45 | +1.1 % (noise) |
| aes-256 | 26.35 | 26.90 | +2.1 % (noise) |
| aegis-128 | 20.85 | 20.40 | -2.2 % (noise) |
| chacha20 | ~7.0 | 7.42 | +6 % (consistent) |

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

### Open (reviewer-flagged, deferred)

- **Frame length not in AEAD AAD.** Audit S-3. The transport AEAD uses
  empty AAD; the 4-byte big-endian length prefix is therefore not
  authenticated by the AEAD tag. Acceptable today (the decoder bounds
  length against `MAX_FRAME_SIZE` before the AEAD step, so corruption
  is caught at the tag), but folding length into AAD would be
  defense-in-depth. Deferred because it is a wire-format break that
  needs version negotiation.
- **`ServiceId` is u16.** S-6. Truncating the Blake3 hash to 16 bits
  gives a ~1.5e-2 birthday-collision probability at 256 services. The
  collision is detected at parse time and refused (fail-closed), so
  the failure mode is "service refused" not "wrong service hit", but
  widening to u32 would push the collision boundary out indefinitely.
  Wire-format break; deferred.
- **`server.zig` and `client.zig` are large** (1787 / 2109 LOC each).
  Pure code-org refactor; no behaviour change. Deferred.
- **Integration test harness gap.** The pre-0.16-migration inline
  `forwardLocalData` / `forwardTargetData` tests depended on
  `posix.socketpair` and `common.sendAllToFd`, both removed in 0.16.
  Author plans to restore via a separate end-to-end harness.
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
