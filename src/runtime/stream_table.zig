const std = @import("std");
const tunnel = @import("../tunnel.zig");
const common = @import("../common.zig");

pub const StreamKey = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
};

pub const StreamKeyContext = struct {
    pub fn hash(_: StreamKeyContext, key: StreamKey) u64 {
        return (@as(u64, key.service_id) *% 0x9E3779B97F4A7C15) ^ @as(u64, key.stream_id);
    }

    pub fn eql(_: StreamKeyContext, a: StreamKey, b: StreamKey) bool {
        return a.service_id == b.service_id and a.stream_id == b.stream_id;
    }
};

/// Refcounted stream map used by both server and client roles.
pub fn StreamTable(comptime T: type) type {
    return struct {
        const Self = @This();

        map: std.HashMap(StreamKey, *T, StreamKeyContext, 80),
        mutex: common.HotMutex = .{},
        generation: std.atomic.Value(u64) = .init(0),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .map = std.HashMap(StreamKey, *T, StreamKeyContext, 80).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        pub fn put(self: *Self, key: StreamKey, ptr: *T) !void {
            try self.map.put(key, ptr);
            _ = self.generation.fetchAdd(1, .acq_rel);
        }

        pub fn get(self: *Self, key: StreamKey) ?*T {
            return self.map.get(key);
        }

        pub fn fetchRemove(self: *Self, key: StreamKey) ?*T {
            const removed = self.map.fetchRemove(key) orelse return null;
            _ = self.generation.fetchAdd(1, .acq_rel);
            return removed.value;
        }

        pub fn loadGeneration(self: *const Self) u64 {
            return self.generation.load(.acquire);
        }
    };
}

/// Shared by the in-file test and `src/stream_table_test.zig` (the addTest
/// root must live under `src/` so `../tunnel.zig` stays inside the module).
pub fn runStreamTableUnitTests() !void {
    const allocator = std.testing.allocator;
    var table = StreamTable(u32).init(allocator);
    defer table.deinit();

    var a: u32 = 11;
    var b: u32 = 22;
    const key_a = StreamKey{ .service_id = 7, .stream_id = 1 };
    const key_b = StreamKey{ .service_id = 7, .stream_id = 2 };
    const missing = StreamKey{ .service_id = 9, .stream_id = 1 };

    try std.testing.expectEqual(@as(u64, 0), table.loadGeneration());
    try std.testing.expect(table.get(key_a) == null);

    try table.put(key_a, &a);
    try std.testing.expectEqual(@as(u64, 1), table.loadGeneration());
    try std.testing.expectEqual(&a, table.get(key_a).?);
    try std.testing.expectEqual(@as(u32, 11), table.get(key_a).?.*);

    // Lookups must not bump the poll-generation counter.
    _ = table.get(key_a);
    try std.testing.expectEqual(@as(u64, 1), table.loadGeneration());

    try table.put(key_b, &b);
    try std.testing.expectEqual(@as(u64, 2), table.loadGeneration());

    // put always bumps, including overwrite of an existing key.
    try table.put(key_a, &a);
    try std.testing.expectEqual(@as(u64, 3), table.loadGeneration());

    const removed = table.fetchRemove(key_a);
    try std.testing.expectEqual(&a, removed.?);
    try std.testing.expectEqual(@as(u64, 4), table.loadGeneration());
    try std.testing.expect(table.get(key_a) == null);
    try std.testing.expectEqual(&b, table.get(key_b).?);

    try std.testing.expect(table.fetchRemove(missing) == null);
    try std.testing.expectEqual(@as(u64, 4), table.loadGeneration());

    const removed_b = table.fetchRemove(key_b);
    try std.testing.expectEqual(&b, removed_b.?);
    try std.testing.expectEqual(@as(u64, 5), table.loadGeneration());
}

test "StreamTable put get fetchRemove and generation bump" {
    try runStreamTableUnitTests();
}
