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
