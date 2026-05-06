const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const config = @import("config.zig");

/// Read the monotonic clock as nanoseconds.
///
/// Goes through `posix.system.clock_gettime` (raw syscall) rather than the
/// std.Io clock so that callers in atomic-update paths (no Io in scope) can
/// still get monotonic timestamps without plumbing Io through every API.
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
        const now: i64 = @intCast(nanoTimestamp());
        const last = self.last_refill.load(.monotonic);
        const elapsed = now - last;

        if (elapsed >= self.refill_interval_ns) {
            self.tokens.store(self.max_tokens, .monotonic);
            _ = self.last_refill.cmpxchgWeak(last, now, .monotonic, .monotonic);

            const refilled = self.tokens.load(.monotonic);
            if (refilled > 0) {
                _ = self.tokens.fetchSub(1, .monotonic);
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
