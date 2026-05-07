const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const config = @import("config.zig");

/// Thread-only mutex, no fiber/Io awareness. Designed for the data path
/// where every nanosecond matters and we have only OS threads in flight.
///
/// Why not std.Io.Mutex: that type goes through an Io vtable on contention
/// (`io.futexWaitUncancelable`) so it can suspend a fiber. We have no
/// fibers, so the indirection is dead weight. Why not std.Thread.Mutex:
/// 0.16 doesn't expose one — that name is the kernel-thread struct.
///
///   * Darwin → os_unfair_lock (single CAS uncontended; layout is one u32).
///   * Linux  → 3-state futex (Drepper's classic; same shape as a private
///     pthread_mutex, but no glibc indirection).
///
/// On ARM the fast path is `cmpxchgWeak` — at most one LL/SC pair, allowed
/// to spuriously fail.  `Io.Mutex`'s fast path uses `cmpxchgStrong`, which
/// adds the LL/SC retry loop.  Materially cheaper on ARM, equivalent on
/// x86 (`lock cmpxchg`).
///
/// Held briefly across hashmap lookups, refcount bumps, and (for
/// transport.Channel.send_mutex) one writev syscall plus an in-place
/// AEAD encrypt. Not re-entrant. `os_unfair_lock` is intentionally
/// non-fair — fine for short critical sections, can starve under
/// pathological adversarial contention.
pub const HotMutex = if (builtin.os.tag == .macos or builtin.os.tag == .ios)
    DarwinHotMutex
else
    FutexHotMutex;

const DarwinHotMutex = extern struct {
    raw: std.c.os_unfair_lock = .{},

    pub inline fn lock(self: *DarwinHotMutex) void {
        std.c.os_unfair_lock_lock(&self.raw);
    }

    pub inline fn unlock(self: *DarwinHotMutex) void {
        std.c.os_unfair_lock_unlock(&self.raw);
    }

    pub inline fn tryLock(self: *DarwinHotMutex) bool {
        return std.c.os_unfair_lock_trylock(&self.raw);
    }
};

const FutexHotMutex = extern struct {
    state: std.atomic.Value(u32) = .init(unlocked),

    const unlocked: u32 = 0;
    const locked: u32 = 1;
    const contended: u32 = 2;

    pub inline fn lock(self: *FutexHotMutex) void {
        if (self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic)) |_| {
            self.lockSlow();
        }
    }

    fn lockSlow(self: *FutexHotMutex) void {
        @branchHint(.cold);
        var s = self.state.swap(contended, .acquire);
        while (s != unlocked) {
            futexWait(&self.state, contended);
            s = self.state.swap(contended, .acquire);
        }
    }

    pub inline fn unlock(self: *FutexHotMutex) void {
        if (self.state.swap(unlocked, .release) == contended) {
            futexWake(&self.state, 1);
        }
    }

    pub inline fn tryLock(self: *FutexHotMutex) bool {
        return self.state.cmpxchgStrong(unlocked, locked, .acquire, .monotonic) == null;
    }

    fn futexWait(ptr: *std.atomic.Value(u32), expected: u32) void {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            _ = linux.futex_4arg(
                &ptr.raw,
                .{ .cmd = .WAIT, .private = true },
                expected,
                null,
            );
        } else {
            // No futex available; fall back to a brief yield so we don't
            // burn the CPU.  Hot path on non-Linux non-Darwin is not the
            // current target — Floo ships for macOS and Linux.
            std.Thread.yield() catch {};
        }
    }

    fn futexWake(ptr: *std.atomic.Value(u32), count: u32) void {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            _ = linux.futex_3arg(
                &ptr.raw,
                .{ .cmd = .WAKE, .private = true },
                count,
            );
        }
    }
};

/// Read the monotonic clock as nanoseconds.
///
/// Calls `posix.system.clock_gettime` directly rather than going through
/// the std.Io clock so callers in atomic-update paths (no Io in scope)
/// can still get monotonic timestamps without plumbing Io through every
/// API.  On Darwin and Linux this is a userspace read (commpage / vDSO),
/// not a real syscall — ~10–20 ns each.  The cost is real at multi-Gbps
/// frame rates but smaller than a syscall trap.
pub fn nanoTimestamp() i128 {
    var ts: posix.timespec = undefined;
    _ = posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_ms));
}

// ============================================================================
// Network Configuration Constants
// ============================================================================

/// Maximum number of pending connections in listen queue.
/// This controls how many connections can wait before accept() is called.
/// Linux default is 128, which works well for most use cases.
pub const LISTEN_BACKLOG: u32 = 128;

/// Standard buffer size for socket I/O operations (64KB).
/// Optimal for most network conditions, matches typical TCP window size.
pub const SOCKET_BUFFER_SIZE: usize = 64 * 1024;

/// Large buffer for high-throughput operations (256KB).
/// Used for frame decoding and encryption buffers.
pub const LARGE_BUFFER_SIZE: usize = 256 * 1024;

// ============================================================================
// Thread Stack Sizes
// ============================================================================

/// Default stack size for connection handler threads (256KB).
/// Provides enough space for buffers and call stack.
pub const DEFAULT_THREAD_STACK: usize = 256 * 1024;

/// Stack size for tunnel receiver threads (512KB).
/// Larger stack needed for MAX_FRAME_SIZE buffers and nested calls.
pub const TUNNEL_THREAD_STACK: usize = 512 * 1024;

// ============================================================================
// Message Buffer Sizes
// ============================================================================

/// Control message buffer size (4KB).
/// Pre-allocated buffer for encoding control messages (CONNECT, CLOSE, etc.).
/// Large enough for any control message with reasonable token lengths.
pub const CONTROL_MSG_BUFFER_SIZE: usize = 4096;

/// Lightweight trace helper that compiles away when `enabled` is false.
pub inline fn tracePrint(comptime enabled: bool, comptime fmt: []const u8, args: anytype) void {
    if (enabled) {
        std.debug.print(fmt, args);
    }
}

/// Constant-time comparison to prevent timing attacks.
///
/// This function compares two byte slices in constant time to prevent
/// attackers from using timing measurements to determine the correct
/// value byte-by-byte (timing side-channel attack).
///
/// Returns true if slices are equal, false otherwise.
///
/// Note: Length comparison is NOT constant-time, but that's unavoidable
/// as we need to know if lengths match. The actual content comparison
/// is constant-time.
///
/// Security: Use this for comparing authentication tokens, passwords,
/// PSKs, HMAC tags, or any secret values.
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    const max_len = @max(a.len, b.len);
    var diff: u8 = 0;

    // Walk the full max length so timing does not leak the shorter prefix.
    var i: usize = 0;
    while (i < max_len) : (i += 1) {
        const lhs = if (i < a.len) a[i] else 0;
        const rhs = if (i < b.len) b[i] else 0;
        diff |= lhs ^ rhs;
    }

    return diff == 0 and a.len == b.len;
}

pub const TcpOptions = struct {
    nodelay: bool,
    keepalive: bool,
    keepalive_idle: u32,
    keepalive_interval: u32,
    keepalive_count: u32,
};

/// Build a `TcpOptions` struct from tuning settings.
pub fn tcpOptionsFromSettings(settings: *const config.TcpSettings) TcpOptions {
    return TcpOptions{
        .nodelay = settings.nodelay,
        .keepalive = settings.keepalive,
        .keepalive_idle = settings.keepalive_idle,
        .keepalive_interval = settings.keepalive_interval,
        .keepalive_count = settings.keepalive_count,
    };
}

/// Apply TCP socket options (Nagle/keepalive) on a Stream's underlying handle.
///
/// std.Io.net.ListenOptions/ConnectOptions don't expose TCP_NODELAY/SO_KEEPALIVE,
/// so we set them via posix.setsockopt on the raw fd. `posix.setsockopt` is one
/// of the few wrapper functions retained in 0.16.
pub fn applyTcpOptions(handle: posix.fd_t, opts: TcpOptions) void {
    if (opts.nodelay) {
        const nodelay_value: c_int = 1;
        posix.setsockopt(handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(nodelay_value)) catch |err| {
            std.debug.print("[TCP] Failed to set TCP_NODELAY: {}\n", .{err});
        };
    }

    if (!opts.keepalive) return;

    const keepalive_value: c_int = 1;
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(keepalive_value)) catch |err| {
        std.debug.print("[TCP] Failed to set SO_KEEPALIVE: {}\n", .{err});
    };

    if (@hasDecl(posix.TCP, "KEEPIDLE")) {
        const idle_value: c_int = @intCast(opts.keepalive_idle);
        posix.setsockopt(handle, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(idle_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPINTVL")) {
        const intvl_value: c_int = @intCast(opts.keepalive_interval);
        posix.setsockopt(handle, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(intvl_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPCNT")) {
        const cnt_value: c_int = @intCast(opts.keepalive_count);
        posix.setsockopt(handle, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(cnt_value)) catch {};
    }
}

/// Apply a per-syscall send/recv timeout to a TCP fd. Used during proxy
/// negotiation so a stalled proxy doesn't block the calling tunnel thread
/// indefinitely (audit B-7). After the negotiation completes, the caller
/// can clear the timeout (or leave it; the data plane uses poll-driven
/// reads that don't trigger SO_RCVTIMEO until the kernel buffer is empty).
pub fn applySocketTimeout(handle: posix.fd_t, timeout_seconds: u32) void {
    const tv = std.c.timeval{
        .sec = @intCast(timeout_seconds),
        .usec = 0,
    };
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// Clear per-syscall timeouts on a TCP fd (sets RCVTIMEO/SNDTIMEO to 0).
pub fn clearSocketTimeout(handle: posix.fd_t) void {
    const tv = std.c.timeval{ .sec = 0, .usec = 0 };
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// Tune socket buffers for high throughput.
pub fn tuneSocketBuffers(handle: posix.fd_t, buffer_size: u32) void {
    const size: c_int = @intCast(buffer_size);
    const bytes = std.mem.toBytes(size);
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.RCVBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow RCVBUF to {}: {}\n", .{ buffer_size, err });
    };
    posix.setsockopt(handle, posix.SOL.SOCKET, posix.SO.SNDBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow SNDBUF to {}: {}\n", .{ buffer_size, err });
    };
}

/// Send all data through an Io.Writer (typically wrapping a Stream.Writer).
///
/// Std.Io's Writer interface handles partial writes internally — this is just
/// a thin shim so callers don't have to remember the method name.
pub fn sendAll(writer: *Io.Writer, data: []const u8) !void {
    return writer.writeAll(data);
}

/// Write a length-prefixed frame: [4-byte big-endian length][payload].
///
/// Two writeAll calls let a buffered Writer coalesce header+payload into a
/// single syscall (the std.Io equivalent of the old writev()-based path).
/// Caller must call writer.flush() after a batch of frames if low latency
/// is required, or rely on the buffered Writer's auto-flush on overflow.
pub fn writeFrame(writer: *Io.Writer, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(payload.len), .big);
    try writer.writeAll(&header);
    try writer.writeAll(payload);
}

/// Write a length-prefixed frame DIRECTLY via writev, bypassing any Io
/// buffered Writer.
///
/// This is the hot data path. The std.Io.Stream.Writer interface adds 2-3
/// vtable hops + buffering per frame, which costs us roughly 3x throughput
/// vs the original posix.writev-based path. This helper restores the original
/// scatter-gather behavior: one syscall per frame regardless of header/payload
/// split. libc's writev is consistent across macOS and Linux (we link libc).
pub fn writeFrameDirect(handle: posix.fd_t, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(payload.len), .big);

    var header_sent: usize = 0;
    var payload_sent: usize = 0;

    while (header_sent < header.len or payload_sent < payload.len) {
        var iovecs_buf: [2]std.c.iovec_const = undefined;
        var iovec_count: c_uint = 0;

        if (header_sent < header.len) {
            const remaining = header[header_sent..];
            iovecs_buf[iovec_count] = .{ .base = remaining.ptr, .len = remaining.len };
            iovec_count += 1;
        }

        if (payload_sent < payload.len) {
            const remaining = payload[payload_sent..];
            iovecs_buf[iovec_count] = .{ .base = remaining.ptr, .len = remaining.len };
            iovec_count += 1;
        }

        const written = std.c.writev(handle, &iovecs_buf, iovec_count);
        if (written < 0) {
            const errno = std.posix.errno(written);
            switch (errno) {
                .INTR => continue,
                // The data path holds `Channel.send_mutex` across this
                // loop and only ever uses blocking sockets, so EAGAIN
                // from a blocking writev is a programming error (e.g.,
                // a future change flipping the fd non-blocking without
                // a matching poll-loop integration).  We choose loud
                // failure over a silent infinite spin under the lock.
                .AGAIN => return error.WriteFailed,
                .PIPE => return error.ConnectionClosed,
                .CONNRESET => return error.ConnectionClosed,
                else => return error.WriteFailed,
            }
        }
        if (written == 0) return error.ConnectionClosed;

        var remaining: usize = @intCast(written);
        if (header_sent < header.len) {
            const header_remaining = header.len - header_sent;
            if (remaining >= header_remaining) {
                remaining -= header_remaining;
                header_sent = header.len;
            } else {
                header_sent += remaining;
                remaining = 0;
            }
        }
        if (remaining > 0 and payload_sent < payload.len) {
            payload_sent += @min(remaining, payload.len - payload_sent);
        }
    }
}

/// Format a std.Io.net.IpAddress into a temporary buffer for logging.
pub fn formatAddress(addr: Io.net.IpAddress, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{f}", .{addr}) catch "unavailable";
}

/// Resolve IPv4/IPv6 literal or DNS hostname into an IpAddress.
///
/// Tries v4 literal, then v6 literal, then DNS resolution. DNS resolution
/// is performed via std.Io.net.Ip6Address.resolve which returns IPv4-mapped
/// IPv6 when the hostname resolves to v4.
pub fn resolveHostPort(io: Io, host: []const u8, port: u16) !Io.net.IpAddress {
    if (Io.net.Ip4Address.parse(host, port)) |v4| {
        return .{ .ip4 = v4 };
    } else |_| {}
    if (Io.net.Ip6Address.parse(host, port)) |v6| {
        return .{ .ip6 = v6 };
    } else |_| {}
    const v6 = try Io.net.Ip6Address.resolve(io, host, port);
    return .{ .ip6 = v6 };
}

/// Receive an exact number of bytes through an Io.Reader.
pub fn recvAll(reader: *Io.Reader, buffer: []u8) !void {
    return reader.readSliceAll(buffer);
}

/// Bind a TCP listener with ONLY SO_REUSEADDR (not SO_REUSEPORT).
///
/// std.Io.net.IpAddress.listen(.{ .reuse_address = true }) sets BOTH
/// SO_REUSEADDR and SO_REUSEPORT on POSIX, which changes load-balancing
/// semantics: the kernel distributes incoming connections across all
/// listeners bound to the same port. That breaks floo's reverse-listener
/// rebind (a new tunnel arriving briefly has both old and new listener
/// bound — connections land on the soon-to-die one and get reset).
///
/// Returns a fully-formed Io.net.Server constructed from a raw libc socket.
pub fn bindListener(addr: Io.net.IpAddress, backlog: u32) !Io.net.Server {
    const family: c_uint = switch (addr) {
        .ip4 => @intCast(std.c.AF.INET),
        .ip6 => @intCast(std.c.AF.INET6),
    };

    // macOS' socket(2) rejects SOCK_CLOEXEC as a type-flag; set FD_CLOEXEC
    // via fcntl after instead. (Linux accepts the SOCK_CLOEXEC bit but the
    // fcntl path is portable.)
    const fd = std.c.socket(family, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketCreateFailed;
    errdefer _ = std.c.close(fd);
    _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC));

    const reuse: c_int = 1;
    if (std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &reuse, @sizeOf(c_int)) != 0) {
        return error.SetSockOptFailed;
    }

    switch (addr) {
        .ip4 => |v4| {
            var sa: std.c.sockaddr.in = .{
                .family = std.c.AF.INET,
                .port = std.mem.nativeToBig(u16, v4.port),
                .addr = std.mem.bytesToValue(u32, &v4.bytes),
                .zero = @splat(0),
            };
            if (std.c.bind(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa))) != 0) {
                return error.BindFailed;
            }
        },
        .ip6 => |v6| {
            var sa: std.c.sockaddr.in6 = .{
                .family = std.c.AF.INET6,
                .port = std.mem.nativeToBig(u16, v6.port),
                .flowinfo = v6.flow,
                .addr = v6.bytes,
                .scope_id = v6.interface.index,
            };
            if (std.c.bind(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa))) != 0) {
                return error.BindFailed;
            }
        },
    }

    if (std.c.listen(fd, @intCast(backlog)) != 0) {
        return error.ListenFailed;
    }

    return .{
        .socket = .{ .handle = fd, .address = addr },
        .options = if (Io.net.Server.AcceptOptions != void) .{ .mode = .stream, .protocol = .tcp } else {},
    };
}

/// Write all bytes to a raw socket handle, looping over partial writes.
///
/// Used on the data-forwarding hot path where we hold a Stream's underlying
/// fd and don't want to set up a per-send Writer just to issue one syscall.
/// libc's write() is the consistent cross-platform path since the project
/// links libc (see build.zig). Returns error.ConnectionClosed on EOF/EPIPE.
pub fn writeAllToHandle(handle: posix.fd_t, data: []const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const remaining = data[offset..];
        const n = std.c.write(handle, remaining.ptr, remaining.len);
        if (n < 0) {
            const errno = std.posix.errno(n);
            switch (errno) {
                .INTR => continue,
                .AGAIN => continue,
                .PIPE => return error.ConnectionClosed,
                .CONNRESET => return error.ConnectionClosed,
                else => return error.WriteFailed,
            }
        }
        if (n == 0) return error.ConnectionClosed;
        offset += @intCast(n);
    }
}

// ============================================================================
// Connection Rate Limiting
// ============================================================================

/// Token-bucket rate limiter to prevent connection flood attacks.
///
/// WP-07: the previous implementation short-circuited in Debug mode to avoid
/// a long-fixed compiler bug. That dual behavior was a footgun in tests, so
/// the bypass is removed.
pub const RateLimiter = struct {
    tokens: std.atomic.Value(u32),
    max_tokens: u32,
    refill_interval_ns: i64,
    last_refill: std.atomic.Value(i64),

    /// Create a rate limiter allowing `max_per_second` operations per second.
    pub fn init(max_per_second: u32) RateLimiter {
        return .{
            .tokens = std.atomic.Value(u32).init(max_per_second),
            .max_tokens = max_per_second,
            .refill_interval_ns = @intCast(@divTrunc(std.time.ns_per_s, max_per_second)),
            .last_refill = std.atomic.Value(i64).init(@intCast(nanoTimestamp())),
        };
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    pub fn tryAcquire(self: *RateLimiter) bool {
        // Fast path: try to consume an existing token.
        var current = self.tokens.load(.monotonic);
        while (current > 0) {
            if (self.tokens.cmpxchgWeak(
                current,
                current - 1,
                .monotonic,
                .monotonic,
            )) |updated| {
                current = updated;
            } else {
                return true;
            }
        }

        // Slow path: refill if the interval has elapsed.
        //
        // Race: previously, two callers observing `elapsed >= interval`
        // would both `tokens.store(max_tokens)` then `fetchSub(1)`, briefly
        // letting through `max_tokens × N_concurrent` rather than just
        // `max_tokens`.  Fix: use the last_refill timestamp as the lock —
        // the thread that successfully cmpxchg's the timestamp from `last`
        // to `now` is the unique winner that gets to refill the bucket.
        // Losers fall through and return false (or hit the fast path on
        // their next call).
        const now: i64 = @intCast(nanoTimestamp());
        const last = self.last_refill.load(.monotonic);
        const elapsed = now - last;

        if (elapsed >= self.refill_interval_ns) {
            if (self.last_refill.cmpxchgStrong(last, now, .monotonic, .monotonic) == null) {
                // We won the race to refill.  Take one for ourselves and
                // publish the rest.  Doing the +max-1 in one store avoids
                // the brief window where `tokens == max_tokens` could let
                // the fast path race ahead of our own consumption.
                self.tokens.store(self.max_tokens - 1, .monotonic);
                return true;
            }
        }

        return false;
    }
};

// Tests
test "constantTimeEqual" {
    try std.testing.expect(common_test_constantTimeEqualHelper("abc", "abc"));
    try std.testing.expect(!common_test_constantTimeEqualHelper("abc", "abd"));
    try std.testing.expect(!common_test_constantTimeEqualHelper("abc", "abcd"));
    try std.testing.expect(!common_test_constantTimeEqualHelper("", "x"));
    try std.testing.expect(common_test_constantTimeEqualHelper("", ""));
}

fn common_test_constantTimeEqualHelper(a: []const u8, b: []const u8) bool {
    return constantTimeEqual(a, b);
}

test "RateLimiter exhausts and refills (works in all build modes)" {
    var rl = RateLimiter.init(3);
    try std.testing.expect(rl.tryAcquire());
    try std.testing.expect(rl.tryAcquire());
    try std.testing.expect(rl.tryAcquire());
    try std.testing.expect(!rl.tryAcquire()); // exhausted
}
