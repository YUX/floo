# Floo — Zig 0.16 / std.Io Migration Notes

**Branch:** `remediation/v0.2.0`
**Target:** Zig 0.16.0 stable
**Strategy:** Path C — migrate to `std.Io` (high-level abstraction), unlocks io_uring backend down the line.
**Status:** In progress. See *Migration progress* below.

---

## Why this is necessary

Zig 0.16.0 (released April 2026) removed the medium-level `std.posix.*` wrappers
(`close`, `recv`, `send`, `socket`, `bind`, `listen`, `accept`, `connect`,
`writev`, `recvfrom`, `sendto`, `fcntl`, `pipe2`, `shutdown`, `socketpair`)
and the `std.fs.cwd()` / `std.fs.createFileAbsolute` family. Apps must
move to `std.Io` (high-level) or `std.posix.system.*` (raw syscalls).

Floo previously tracked Zig master in CI, which silently froze us against an
intermediate dev snapshot. We've chosen `std.Io` so the same code base later
gains an io_uring backend by swapping `Io.Threaded` for `Io.Uring`.

## Key patterns

### 1. Getting an `Io`

`main` takes a full `std.process.Init`:

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = init.minimal.args;
    // ...
}
```

`Init` is provided by Zig's start code, which constructs an `Io.Threaded`
backed by either `std.heap.smp_allocator` (release) or `std.heap.DebugAllocator`
(debug). We don't allocate our own GPA anymore.

### 2. TCP — `IpAddress`, `Server`, `Stream`

| Old (posix) | New (std.Io) |
|---|---|
| `posix.socket(...)` + `posix.bind(...)` + `posix.listen(...)` | `addr.listen(io, .{}) -> Server` |
| `posix.accept(server_fd, ...)` | `server.accept(io) -> Stream` |
| `posix.connect(...)` | `addr.connect(io, .{}) -> Stream` |
| `posix.recv(fd, buf, 0)` | `stream.reader(io, buf).interface().read(...)` (buffered) — or `stream.reader(io, &.{})` for unbuffered |
| `posix.send(fd, buf, 0)` | `stream.writer(io, buf).interface().writeAll(buf)` |
| `posix.close(fd)` | `stream.close(io)` |
| `posix.shutdown(fd, .recv/.send/.both)` | `stream.shutdown(io, .recv/.send/.both)` |
| `posix.setsockopt(...)` | Set via `ListenOptions`/`ConnectOptions` at create time |

Notes:
- `Stream.Reader` and `Stream.Writer` are **buffered**. The buffer is caller-supplied.
- For floo's "encrypted frame in/out" pattern we want a *small* buffer or to use the
  unbuffered path; otherwise the buffered reader/writer collides with our own ring.
- TCP options like `TCP_NODELAY`, `SO_KEEPALIVE` are set via `ListenOptions.tcp` /
  `ConnectOptions.tcp` (need to verify exact field names per `net.zig`).

### 3. UDP — `Socket`

| Old (posix) | New (std.Io) |
|---|---|
| `posix.socket(AF_INET, SOCK_DGRAM, 0)` + `posix.bind(...)` | `IpAddress.bind(io, .{}) -> Socket` (with `.dgram` mode) |
| `posix.connect(udp_fd, ...)` | `socket.send(io, &dest, data)` (datagram-style, no connect needed) |
| `posix.sendto(udp_fd, data, 0, &addr, len)` | `socket.send(io, &addr, data)` |
| `posix.recvfrom(udp_fd, buf, 0, &addr, &len)` | `socket.receive(io, buf) -> IncomingMessage` (has source addr) |
| `posix.close(udp_fd)` | `socket.close(io)` |

`IncomingMessage` carries the source address — this is exactly what `udp_*.zig`
needs and removes the manual `sockaddr.storage` parsing.

### 4. Filesystem — `Io.Dir`, `Io.File`

| Old | New |
|---|---|
| `std.fs.cwd().readFileAlloc(allocator, path, max)` | `Io.Dir.cwd().readFileAlloc(io, allocator, path, max)` (verify exact name) |
| `std.fs.cwd().access(path, .{})` | `Io.Dir.cwd().access(io, path, .{})` |
| `std.fs.createFileAbsolute(path, .{...})` | `Io.Dir.createFileAbsolute(io, path, .{...})` |
| `file.writeAll(bytes)` | `file.writer(io, buf).interface().writeAll(bytes)` |
| `file.seekFromEnd(0)` | Implicit via `writer.appendMode = true` (verify) |

### 5. Threading

`std.Thread.Mutex`, `std.Thread.spawn`, `std.Thread.getCpuCount` are **retained**
in 0.16 — these don't need migration. The `std.Io.Mutex` exists for code that wants
cancelable, async-aware locking; floo's blocking-thread model is fine with
`std.Thread.Mutex`.

### 6. Address resolution / parsing

`net_compat.zig` becomes obsolete — `std.Io.net.IpAddress.Ip6Address.Unresolved.parse`,
`Ip4Address.parse`, `IpAddress.format` all exist natively in 0.16.

DNS resolution: `Ip6Address.resolve(io, hostname, port)`.

### 7. Cancelable error sets

Many `Io` operations return errors that include `Io.Cancelable`. For floo's
synchronous flows, treat `error.Cancel` like a graceful shutdown signal.

---

## Migration order (bottom-up; each stage breaks compile until the next lands)

1. ✅ **Mechanical** (commit `1cc860a`): allocator, args, ArrayListUnmanaged, posix.exit.
2. ⏳ **`main()` signature** — server.zig, client.zig take `std.process.Init`.
3. ⏳ **`common.zig`** — `sendAllToFd`/`recvAllFromFd`/`writeFrameLocked` accept `io: Io` + `Stream`.
4. ⏳ **`noise.zig`** — `noiseXXHandshake` takes `Stream` + `io` (or pre-built reader/writer).
5. ⏳ **`transport/channel.zig`** — `Channel` holds `Stream` not `fd_t`; takes `io` via init.
6. ⏳ **`net_compat.zig`** — delete; callers use `std.Io.net.IpAddress`.
7. **`proxy.zig`** — `connectViaSocks5` / `connectViaHttpConnect` return `Stream`.
8. **`udp_session.zig`, `udp_client.zig`, `udp_server.zig`** — use `Socket`, `IncomingMessage`.
9. **`server.zig`** — `ReverseListener.create` uses `addr.listen()`; main accept loop uses `Server.accept`.
10. **`client.zig`** — `tcpServiceListener` uses `addr.listen()`; tunnel reconnection uses `addr.connect()`.
11. **`config.zig`, `diagnostics.zig`** — `Io.Dir.cwd()` / `Io.Dir.createFile`.

## Decisions to revisit

- **TCP_NODELAY / keepalive:** `net.zig` exposes these via `ListenOptions`/`ConnectOptions`?
  Need to verify the struct field names — the audit may have to fall back to setting them
  via `posix.system.setsockopt` on the raw `Socket.Handle` if `Io` doesn't expose them.

- **`writev` for length-prefixed frames** (`common.writeFrameLocked`): `Stream.Writer` is
  buffered, so we can write `header` then `payload` and rely on `flush` to coalesce.
  Confirm with a benchmark — the `writev` syscall consolidation is a known floo perf win.

- **CPU pinning** (`linux.sched_setaffinity`) is unaffected — `std.os.linux` survives.

- **Signal handling:** `posix.sigaction` + `posix.SIG.*` are still in `std.posix` (we
  verified `pub fn sigaction` is exported). Self-pipe (`pipe2`) needs to migrate to
  `Io.pipe()` if it exists, or to `std.posix.system.pipe2`.

## How to resume after a session boundary

```bash
cd /Users/yux/Devs/floo
git switch remediation/v0.2.0
git log --oneline -10                        # see committed progress
~/.zvm/0.16.0/zig build 2>&1 | head -30      # see remaining errors
# Pick the next file from the migration order list above.
# Each PR lands one file's worth of changes (intermediate states won't compile
# until the whole graph is done — that's expected).
```

## When the migration is "done"

- `~/.zvm/0.16.0/zig build` produces both binaries.
- `~/.zvm/0.16.0/zig build test` is green.
- `bench/baseline.json` shows no >5% throughput regression vs. v0.1.5.
- CI `.github/workflows/*.yml` pinned to `version: 0.16.0`.
- `MIGRATION_NOTES.md` updated with any patterns we discovered.
