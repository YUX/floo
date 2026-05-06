const std = @import("std");
const Io = std.Io;
const tunnel = @import("tunnel.zig");
const common = @import("common.zig");

/// UDP session key — identifies a unique UDP "client" by source address.
///
/// Stored as a flat byte array so it's a value-typed HashMap key. IPv4 uses
/// the first 4 bytes; IPv6 uses all 16. `family` distinguishes the two so
/// that `0.0.0.0:N` and `::N` don't collide.
pub const SessionKey = struct {
    family: u8, // 4 or 6
    addr_bytes: [16]u8,
    port: u16, // native endian

    pub fn initFromAddress(addr: Io.net.IpAddress) SessionKey {
        var key: SessionKey = .{
            .family = 0,
            .addr_bytes = [_]u8{0} ** 16,
            .port = 0,
        };

        switch (addr) {
            .ip4 => |v4| {
                key.family = 4;
                @memcpy(key.addr_bytes[0..4], &v4.bytes);
                key.port = v4.port;
            },
            .ip6 => |v6| {
                key.family = 6;
                @memcpy(&key.addr_bytes, &v6.bytes);
                key.port = v6.port;
            },
        }

        return key;
    }

    pub fn eql(self: SessionKey, other: SessionKey) bool {
        return self.family == other.family and
            self.port == other.port and
            std.mem.eql(u8, &self.addr_bytes, &other.addr_bytes);
    }

    pub fn hash(self: SessionKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{self.family});
        hasher.update(&self.addr_bytes);
        hasher.update(std.mem.asBytes(&self.port));
        return hasher.final();
    }
};

/// UDP session context
pub const UdpSession = struct {
    stream_id: tunnel.StreamId,
    source_addr: Io.net.IpAddress,
    last_activity_ns: i128, // Nanoseconds since epoch

    pub fn init(stream_id: tunnel.StreamId, source_addr: Io.net.IpAddress) UdpSession {
        return .{
            .stream_id = stream_id,
            .source_addr = source_addr,
            .last_activity_ns = common.nanoTimestamp(),
        };
    }

    pub fn touch(self: *UdpSession) void {
        self.last_activity_ns = common.nanoTimestamp();
    }

    pub fn isExpired(self: *const UdpSession, timeout_seconds: u64) bool {
        const now = common.nanoTimestamp();
        const timeout_ns = @as(i128, timeout_seconds) * std.time.ns_per_s;
        return (now - self.last_activity_ns) > timeout_ns;
    }
};

/// Context for managing UDP sessions
pub const UdpSessionManager = struct {
    allocator: std.mem.Allocator,
    sessions: std.AutoHashMap(SessionKey, UdpSession),
    reverse_map: std.AutoHashMap(tunnel.StreamId, SessionKey),
    mutex: std.Thread.Mutex,
    next_stream_id: std.atomic.Value(u32),
    scratch_keys: std.ArrayListUnmanaged(SessionKey),

    pub fn init(allocator: std.mem.Allocator) UdpSessionManager {
        return .{
            .allocator = allocator,
            .sessions = std.AutoHashMap(SessionKey, UdpSession).init(allocator),
            .reverse_map = std.AutoHashMap(tunnel.StreamId, SessionKey).init(allocator),
            .mutex = std.Thread.Mutex{},
            .next_stream_id = std.atomic.Value(u32).init(1),
            .scratch_keys = .empty,
        };
    }

    pub fn deinit(self: *UdpSessionManager) void {
        self.sessions.deinit();
        self.reverse_map.deinit();
        self.scratch_keys.deinit(self.allocator);
    }

    /// Get or create session for a source address
    pub fn getOrCreate(self: *UdpSessionManager, source_addr: Io.net.IpAddress) !UdpSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = SessionKey.initFromAddress(source_addr);

        if (self.sessions.get(key)) |*session| {
            var updated = session.*;
            updated.touch();
            try self.sessions.put(key, updated);
            return updated;
        }

        const stream_id = self.next_stream_id.fetchAdd(1, .monotonic);
        const session = UdpSession.init(stream_id, source_addr);

        try self.sessions.put(key, session);
        try self.reverse_map.put(stream_id, key);

        return session;
    }

    /// Look up session by stream_id (for reverse lookup)
    pub fn getByStreamId(self: *UdpSessionManager, stream_id: tunnel.StreamId) ?UdpSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = self.reverse_map.get(stream_id) orelse return null;
        return self.sessions.get(key);
    }

    /// Remove expired sessions
    pub fn cleanupExpired(self: *UdpSessionManager, timeout_seconds: u64) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.scratch_keys.clearRetainingCapacity();

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired(timeout_seconds)) {
                try self.scratch_keys.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (self.scratch_keys.items) |key| {
            if (self.sessions.fetchRemove(key)) |removed| {
                _ = self.reverse_map.remove(removed.value.stream_id);
            }
        }

        return self.scratch_keys.items.len;
    }

    /// Count active sessions
    pub fn count(self: *UdpSessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.count();
    }
};

// Tests
test "SessionKey equality and hashing" {
    const v4 = try Io.net.Ip4Address.parse("127.0.0.1", 8080);
    const addr1: Io.net.IpAddress = .{ .ip4 = v4 };
    const addr2: Io.net.IpAddress = .{ .ip4 = v4 };
    const v4b = try Io.net.Ip4Address.parse("127.0.0.1", 8081);
    const addr3: Io.net.IpAddress = .{ .ip4 = v4b };

    const key1 = SessionKey.initFromAddress(addr1);
    const key2 = SessionKey.initFromAddress(addr2);
    const key3 = SessionKey.initFromAddress(addr3);

    try std.testing.expect(key1.eql(key2));
    try std.testing.expect(!key1.eql(key3));
    try std.testing.expectEqual(key1.hash(), key2.hash());
}

test "UdpSession expiration" {
    const v4 = try Io.net.Ip4Address.parse("127.0.0.1", 8080);
    const addr: Io.net.IpAddress = .{ .ip4 = v4 };
    var session = UdpSession.init(123, addr);

    try std.testing.expect(!session.isExpired(60));

    session.last_activity_ns = common.nanoTimestamp() - (61 * std.time.ns_per_s);

    try std.testing.expect(session.isExpired(60));
}

test "UdpSessionManager basic operations" {
    const allocator = std.testing.allocator;
    var manager = UdpSessionManager.init(allocator);
    defer manager.deinit();

    const v4_a = try Io.net.Ip4Address.parse("192.168.1.1", 12345);
    const v4_b = try Io.net.Ip4Address.parse("192.168.1.2", 12346);
    const addr1: Io.net.IpAddress = .{ .ip4 = v4_a };
    const addr2: Io.net.IpAddress = .{ .ip4 = v4_b };

    const session1 = try manager.getOrCreate(addr1);
    try std.testing.expectEqual(@as(u32, 1), session1.stream_id);

    const session2 = try manager.getOrCreate(addr2);
    try std.testing.expectEqual(@as(u32, 2), session2.stream_id);

    const session1_again = try manager.getOrCreate(addr1);
    try std.testing.expectEqual(session1.stream_id, session1_again.stream_id);

    const found = manager.getByStreamId(session1.stream_id);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(session1.stream_id, found.?.stream_id);

    try std.testing.expectEqual(@as(usize, 2), manager.count());
}
