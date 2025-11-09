const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const config = @import("config.zig");

inline fn socketHandle(fd: posix.fd_t) posix.socket_t {
    if (builtin.target.os.tag == .windows) {
        return @ptrCast(fd);
    }
    return fd;
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

/// Apply TCP socket options (Nagle/keepalive) with best-effort error reporting.
pub fn applyTcpOptions(fd: posix.fd_t, opts: TcpOptions) void {
    if (opts.nodelay) {
        const nodelay_value: c_int = 1;
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(nodelay_value)) catch |err| {
            std.debug.print("[TCP] Failed to set TCP_NODELAY: {}\n", .{err});
        };
    }

    if (!opts.keepalive) return;

    const keepalive_value: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(keepalive_value)) catch |err| {
        std.debug.print("[TCP] Failed to set SO_KEEPALIVE: {}\n", .{err});
    };

    if (@hasDecl(posix.TCP, "KEEPIDLE")) {
        const idle_value: c_int = @intCast(opts.keepalive_idle);
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPIDLE, &std.mem.toBytes(idle_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPINTVL")) {
        const intvl_value: c_int = @intCast(opts.keepalive_interval);
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPINTVL, &std.mem.toBytes(intvl_value)) catch {};
    }
    if (@hasDecl(posix.TCP, "KEEPCNT")) {
        const cnt_value: c_int = @intCast(opts.keepalive_count);
        posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.KEEPCNT, &std.mem.toBytes(cnt_value)) catch {};
    }
}

/// Tune socket buffers for high throughput.
pub fn tuneSocketBuffers(fd: posix.fd_t, buffer_size: u32) void {
    const size: c_int = @intCast(buffer_size);
    const bytes = std.mem.toBytes(size);
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow RCVBUF to {}: {}\n", .{ buffer_size, err });
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &bytes) catch |err| {
        std.debug.print("[SOCKET] Failed to grow SNDBUF to {}: {}\n", .{ buffer_size, err });
    };
}

/// Send all data to file descriptor, handling partial writes.
///
/// This function ensures all bytes are sent, handling the case where
/// send() returns fewer bytes than requested (partial write).
///
/// Returns error.ConnectionClosed if the connection is closed before
/// all data is sent (send returns 0).
///
/// Extracted from client.zig and server.zig to eliminate duplication.
pub fn sendAllToFd(fd: posix.fd_t, data: []const u8) !void {
    const socket_fd = socketHandle(fd);
    var offset: usize = 0;
    while (offset < data.len) {
        const n = posix.send(socket_fd, data[offset..], 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

/// Write length-prefixed frame using writev() for scatter-gather I/O.
///
/// Frame format: [4-byte big-endian length][payload]
///
/// This function uses writev() for atomic write of header and payload,
/// minimizing system calls and ensuring both parts are sent together.
///
/// Handles partial writes by tracking which iovecs have been sent and
/// updating offsets accordingly.
///
/// Extracted from client.zig and server.zig to eliminate duplication.
pub fn writeFrameLocked(fd: posix.fd_t, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(payload.len), .big);

    // Track how much of each part has been sent
    var header_sent: usize = 0;
    var payload_sent: usize = 0;

    while (header_sent < header.len or payload_sent < payload.len) {
        // Prepare iovecs based on what still needs to be sent
        var iovecs_buf: [2]posix.iovec_const = undefined;
        var iovec_count: usize = 0;

        if (header_sent < header.len) {
            const header_remaining = header[header_sent..];
            iovecs_buf[iovec_count] = posix.iovec_const{ .base = header_remaining.ptr, .len = header_remaining.len };
            iovec_count += 1;
        }

        if (payload_sent < payload.len) {
            const payload_remaining = payload[payload_sent..];
            iovecs_buf[iovec_count] = posix.iovec_const{ .base = payload_remaining.ptr, .len = payload_remaining.len };
            iovec_count += 1;
        }

        const iovecs = iovecs_buf[0..iovec_count];
        const written = posix.writev(fd, iovecs) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (written == 0) return error.ConnectionClosed;

        // Update counters based on bytes written
        var remaining = written;

        // Process header first if not fully sent
        if (header_sent < header.len) {
            const header_bytes_to_send = header.len - header_sent;
            if (remaining >= header_bytes_to_send) {
                remaining -= header_bytes_to_send;
                header_sent = header.len;
            } else {
                header_sent += remaining;
                remaining = 0;
            }
        }

        // Then process payload if we have remaining bytes
        if (remaining > 0 and payload_sent < payload.len) {
            payload_sent += @min(remaining, payload.len - payload_sent);
        }
    }
}

/// Format a std.net.Address into a temporary buffer for logging.
pub fn formatAddress(addr: std.net.Address, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{f}", .{addr}) catch "unavailable";
}

/// Resolve IPv4/IPv6/DNS host strings into a std.net.Address.
pub fn resolveHostPort(host: []const u8, port: u16) !std.net.Address {
    return std.net.Address.parseIp4(host, port) catch
        std.net.Address.parseIp6(host, port) catch
        std.net.Address.resolveIp(host, port);
}

/// Receive an exact number of bytes from a socket file descriptor.
pub fn recvAllFromFd(fd: posix.fd_t, buffer: []u8) !void {
    const socket_fd = socketHandle(fd);
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = posix.recv(socket_fd, buffer[offset..], 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

// ============================================================================
// Connection Rate Limiting
// ============================================================================

/// Simple token bucket rate limiter to prevent connection flood attacks
pub const RateLimiter = struct {
    tokens: std.atomic.Value(u32),
    max_tokens: u32,
    refill_interval_ns: i64,
    last_refill: std.atomic.Value(i64),

    /// Create a rate limiter allowing `max_per_second` operations per second
    pub fn init(max_per_second: u32) RateLimiter {
        return .{
            .tokens = std.atomic.Value(u32).init(max_per_second),
            .max_tokens = max_per_second,
            .refill_interval_ns = @intCast(@divTrunc(std.time.ns_per_s, max_per_second)),
            .last_refill = std.atomic.Value(i64).init(@intCast(std.time.nanoTimestamp())),
        };
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited
    pub fn tryAcquire(self: *RateLimiter) bool {
        // In Debug mode, skip complex rate limiting to avoid compiler bugs
        if (builtin.mode == .Debug) {
            return true;
        }

        // Try to consume a token
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

        // Refill if needed
        const now: i64 = @intCast(std.time.nanoTimestamp());
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
