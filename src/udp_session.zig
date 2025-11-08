const std = @import("std");
const posix = std.posix;
const tunnel = @import("tunnel.zig");

/// UDP session key - identifies a unique UDP "connection" by source address
/// We store the raw sockaddr to avoid issues with Address union
pub const SessionKey = struct {
    family: u8, // AF.INET or AF.INET6
    addr_bytes: [16]u8, // IPv4 uses first 4 bytes, IPv6 uses all 16
    port: u16, // Network byte order

    pub fn initFromAddress(addr: std.net.Address) SessionKey {
        var key: SessionKey = undefined;
        key.family = @intCast(addr.any.family);
        key.addr_bytes = [_]u8{0} ** 16;

        switch (addr.any.family) {
            posix.AF.INET => {
                const ipv4 = addr.in;
                @memcpy(key.addr_bytes[0..4], std.mem.asBytes(&ipv4.sa.addr));
                key.port = ipv4.getPort();
            },
            posix.AF.INET6 => {
                const ipv6 = addr.in6;
                @memcpy(&key.addr_bytes, &ipv6.sa.addr);
                key.port = ipv6.getPort();
            },
            else => unreachable,
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
    source_addr: std.net.Address,
    last_activity_ns: i128, // Nanoseconds since epoch

    pub fn init(stream_id: tunnel.StreamId, source_addr: std.net.Address) UdpSession {
        return .{
            .stream_id = stream_id,
            .source_addr = source_addr,
            .last_activity_ns = std.time.nanoTimestamp(),
        };
    }

    pub fn touch(self: *UdpSession) void {
        self.last_activity_ns = std.time.nanoTimestamp();
    }

    pub fn isExpired(self: *const UdpSession, timeout_seconds: u64) bool {
        const now = std.time.nanoTimestamp();
        const timeout_ns = @as(i128, timeout_seconds) * std.time.ns_per_s;
        return (now - self.last_activity_ns) > timeout_ns;
    }
};

/// Context for managing UDP sessions
pub const UdpSessionManager = struct {
    allocator: std.mem.Allocator,
    // Map: SessionKey -> UdpSession
    sessions: std.AutoHashMap(SessionKey, UdpSession),
    // Reverse map: stream_id -> SessionKey (for tunnel -> local forwarding)
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
            .scratch_keys = .{},
        };
    }

    pub fn deinit(self: *UdpSessionManager) void {
        self.sessions.deinit();
        self.reverse_map.deinit();
        self.scratch_keys.deinit(self.allocator);
    }

    /// Get or create session for a source address
    pub fn getOrCreate(self: *UdpSessionManager, source_addr: std.net.Address) !UdpSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = SessionKey.initFromAddress(source_addr);

        if (self.sessions.get(key)) |*session| {
            // Existing session - update activity time
            var updated = session.*;
            updated.touch();
            try self.sessions.put(key, updated);
            return updated;
        }

        // New session - allocate stream ID
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

        // Remove expired sessions
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
    const addr1 = try std.net.Address.parseIp4("127.0.0.1", 8080);
    const addr2 = try std.net.Address.parseIp4("127.0.0.1", 8080);
    const addr3 = try std.net.Address.parseIp4("127.0.0.1", 8081);

    const key1 = SessionKey.initFromAddress(addr1);
    const key2 = SessionKey.initFromAddress(addr2);
    const key3 = SessionKey.initFromAddress(addr3);

    try std.testing.expect(key1.eql(key2));
    try std.testing.expect(!key1.eql(key3));
    try std.testing.expectEqual(key1.hash(), key2.hash());
}

test "UdpSession expiration" {
    const addr = try std.net.Address.parseIp4("127.0.0.1", 8080);
    var session = UdpSession.init(123, addr);

    // Fresh session should not be expired
    try std.testing.expect(!session.isExpired(60));

    // Simulate old session by setting past timestamp
    session.last_activity_ns = std.time.nanoTimestamp() - (61 * std.time.ns_per_s);

    // Should now be expired with 60 second timeout
    try std.testing.expect(session.isExpired(60));
}

test "UdpSessionManager basic operations" {
    const allocator = std.testing.allocator;
    var manager = UdpSessionManager.init(allocator);
    defer manager.deinit();

    const addr1 = try std.net.Address.parseIp4("192.168.1.1", 12345);
    const addr2 = try std.net.Address.parseIp4("192.168.1.2", 12346);

    // Create first session
    const session1 = try manager.getOrCreate(addr1);
    try std.testing.expectEqual(@as(u32, 1), session1.stream_id);

    // Create second session
    const session2 = try manager.getOrCreate(addr2);
    try std.testing.expectEqual(@as(u32, 2), session2.stream_id);

    // Get existing session (should return same stream_id)
    const session1_again = try manager.getOrCreate(addr1);
    try std.testing.expectEqual(session1.stream_id, session1_again.stream_id);

    // Reverse lookup
    const found = manager.getByStreamId(session1.stream_id);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(session1.stream_id, found.?.stream_id);

    // Count
    try std.testing.expectEqual(@as(usize, 2), manager.count());
}
