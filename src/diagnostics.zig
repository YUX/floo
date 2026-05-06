const std = @import("std");

pub const CheckStatus = enum { ok, warn, fail };

pub fn reportCheck(status: CheckStatus, comptime fmt: []const u8, args: anytype) void {
    const prefix = switch (status) {
        .ok => "[OK] ",
        .warn => "[WARN] ",
        .fail => "[FAIL] ",
    };
    std.debug.print("{s}", .{prefix});
    std.debug.print(fmt, args);
    std.debug.print("\n", .{});
}

pub fn flushEncryptStats(prefix: []const u8, total: *std.atomic.Value(u64), calls: *std.atomic.Value(u64)) void {
    const total_ns = total.load(.acquire);
    const call_count = calls.load(.acquire);
    if (call_count == 0 or total_ns == 0) return;

    const avg = total_ns / call_count;
    std.debug.print("[PROFILE] {s} encryption total={} ns calls={} avg={} ns\n", .{ prefix, total_ns, call_count, avg });
}

pub fn flushThroughputStats(
    prefix: []const u8,
    tx: *std.atomic.Value(u64),
    rx: *std.atomic.Value(u64),
) void {
    const tx_bytes = tx.load(.acquire);
    const rx_bytes = rx.load(.acquire);
    if (tx_bytes == 0 and rx_bytes == 0) return;

    const tx_mb = asDecimalMB(tx_bytes);
    const rx_mb = asDecimalMB(rx_bytes);
    std.debug.print(
        "[PROFILE] {s} throughput tx={} bytes ({d:.2} MB) rx={} bytes ({d:.2} MB)\n",
        .{ prefix, tx_bytes, tx_mb, rx_bytes, rx_mb },
    );
}

fn asDecimalMB(bytes: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
}
