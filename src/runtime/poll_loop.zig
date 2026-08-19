const std = @import("std");
const posix = std.posix;
const protocol = @import("../protocol.zig");
const stream_table = @import("stream_table.zig");

pub fn PollCallbacks(comptime StreamT: type) type {
    return struct {
        ctx: *anyopaque,
        streamFd: *const fn (*StreamT) posix.fd_t,
        acquire: *const fn (*StreamT) void,
        release: *const fn (*StreamT) void,
        onFrame: *const fn (*anyopaque, protocol.WireFrame) anyerror!void,
        onSide: *const fn (*anyopaque, *StreamT, i16) void,
        shouldStop: ?*const fn (*anyopaque) bool = null,
    };
}

const PollKind = enum { tunnel, stream };

fn PollEntry(comptime StreamT: type) type {
    return union(PollKind) {
        tunnel: void,
        stream: *StreamT,
    };
}

/// Generation-cached poll loop shared by both roles.
pub fn run(
    comptime StreamT: type,
    allocator: std.mem.Allocator,
    table: *stream_table.StreamTable(StreamT),
    tunnel_fd: posix.fd_t,
    decoder: *protocol.FrameDecoder,
    encrypted: bool,
    timeout_ms: i32,
    running: *std.atomic.Value(bool),
    shutdown: *const std.atomic.Value(bool),
    label: []const u8,
    cbs: PollCallbacks(StreamT),
) void {
    var poll_fds = std.ArrayListUnmanaged(posix.pollfd).empty;
    defer poll_fds.deinit(allocator);

    var poll_entries = std.ArrayListUnmanaged(PollEntry(StreamT)).empty;
    defer {
        for (poll_entries.items) |entry| switch (entry) {
            .stream => |ptr| cbs.release(ptr),
            .tunnel => {},
        };
        poll_entries.deinit(allocator);
    }

    var last_built_generation: u64 = 0;
    var have_built = false;

    while (running.load(.acquire) and !shutdown.load(.acquire)) {
        if (cbs.shouldStop) |check| {
            if (check(cbs.ctx)) break;
        }

        const current_generation = table.loadGeneration();
        if (!have_built or current_generation != last_built_generation) {
            for (poll_entries.items) |entry| switch (entry) {
                .stream => |ptr| cbs.release(ptr),
                .tunnel => {},
            };
            poll_fds.clearRetainingCapacity();
            poll_entries.clearRetainingCapacity();

            poll_fds.append(allocator, .{
                .fd = tunnel_fd,
                .events = posix.POLL.IN,
                .revents = 0,
            }) catch unreachable;
            poll_entries.append(allocator, .{ .tunnel = {} }) catch unreachable;

            table.mutex.lock();
            last_built_generation = table.generation.load(.acquire);
            var iter = table.map.iterator();
            while (iter.next()) |entry| {
                const ptr = entry.value_ptr.*;
                cbs.acquire(ptr);
                poll_entries.append(allocator, .{ .stream = ptr }) catch {
                    cbs.release(ptr);
                    continue;
                };
                poll_fds.append(allocator, .{
                    .fd = cbs.streamFd(ptr),
                    .events = posix.POLL.IN,
                    .revents = 0,
                }) catch {
                    _ = poll_entries.pop();
                    cbs.release(ptr);
                    continue;
                };
            }
            table.mutex.unlock();
            have_built = true;
        }

        const ready = posix.poll(poll_fds.items, timeout_ms) catch |err| {
            std.debug.print("[{s}] Poll error: {}\n", .{ label, err });
            break;
        };
        if (ready == 0) continue;

        var fatal_error = false;
        var idx: usize = 0;
        loop: while (idx < poll_entries.items.len) : (idx += 1) {
            const entry = poll_entries.items[idx];
            const fd_info = poll_fds.items[idx];
            switch (entry) {
                .tunnel => {
                    if ((fd_info.revents & posix.POLL.IN) == 0) continue;

                    const dst = decoder.pendingTail();
                    if (dst.len == 0) {
                        std.debug.print("[{s}] Decoder buffer full; framing stalled\n", .{label});
                        fatal_error = true;
                        break :loop;
                    }
                    const n = posix.read(tunnel_fd, dst) catch |err| {
                        std.debug.print("[{s}] Recv error: {}\n", .{ label, err });
                        fatal_error = true;
                        break :loop;
                    };
                    if (n == 0) {
                        std.debug.print("[{s}] Peer disconnected\n", .{label});
                        fatal_error = true;
                        break :loop;
                    }
                    decoder.commitWrite(n);

                    while (true) {
                        const maybe_frame = decoder.decodeMut(encrypted) catch |decode_err| {
                            std.debug.print("[{s}] Decoder error: {}\n", .{ label, decode_err });
                            fatal_error = true;
                            break :loop;
                        };
                        if (maybe_frame) |frame| {
                            cbs.onFrame(cbs.ctx, frame) catch |err| {
                                std.debug.print("[{s}] Handle message error: {}\n", .{ label, err });
                                fatal_error = true;
                                break :loop;
                            };
                            if (!running.load(.acquire)) {
                                fatal_error = true;
                                break :loop;
                            }
                            continue;
                        }
                        break;
                    }
                },
                .stream => |ptr| {
                    if (fd_info.revents != 0) {
                        cbs.onSide(cbs.ctx, ptr, fd_info.revents);
                    }
                },
            }
        }

        if (fatal_error) {
            running.store(false, .release);
            break;
        }
    }
}
