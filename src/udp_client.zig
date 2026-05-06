const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const tunnel = @import("tunnel.zig");
const noise = @import("noise.zig");
const udp_session = @import("udp_session.zig");
const common = @import("common.zig");

/// UDP forwarder for client side
/// Handles local UDP clients and forwards through tunnel
///
/// Design: Client listens on local UDP port and tracks sessions for each
/// local client that sends packets. Each unique source address gets a
/// session ID that's used to route responses back correctly.
pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    io: Io,
    service_id: tunnel.ServiceId,
    local_port: u16,
    local_socket: Io.net.Socket,
    tunnel_conn: *anyopaque, // Opaque pointer to TunnelClient
    send_fn: *const fn (conn: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void,
    running: std.atomic.Value(bool),
    thread: std.Thread,
    session_manager: udp_session.UdpSessionManager,
    timeout_seconds: u64,

    pub fn create(
        allocator: std.mem.Allocator,
        io: Io,
        service_id: tunnel.ServiceId,
        local_host: []const u8,
        local_port: u16,
        tunnel_conn: *anyopaque,
        send_fn: *const fn (conn: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void,
        timeout_seconds: u64,
    ) !*UdpForwarder {
        const bind_addr = try common.resolveHostPort(io, local_host, local_port);
        const local_socket = try bind_addr.bind(io, .{ .mode = .dgram });
        errdefer local_socket.close(io);

        const forwarder = try allocator.create(UdpForwarder);
        forwarder.* = .{
            .allocator = allocator,
            .io = io,
            .service_id = service_id,
            .local_port = local_port,
            .local_socket = local_socket,
            .tunnel_conn = tunnel_conn,
            .send_fn = send_fn,
            .running = std.atomic.Value(bool).init(true),
            .thread = undefined,
            .session_manager = udp_session.UdpSessionManager.init(allocator),
            .timeout_seconds = timeout_seconds,
        };

        forwarder.thread = try std.Thread.spawn(.{
            .stack_size = common.DEFAULT_THREAD_STACK,
        }, localReceiveThread, .{forwarder});

        std.debug.print("[UDP-CLIENT] Listening on {s}:{}\n", .{ local_host, local_port });

        return forwarder;
    }

    fn localReceiveThread(self: *UdpForwarder) void {
        var buf: [common.SOCKET_BUFFER_SIZE]u8 align(64) = undefined;

        std.debug.print("[UDP-CLIENT] Local receiver thread started\n", .{});

        while (self.running.load(.acquire)) {
            const msg = self.local_socket.receive(self.io, &buf) catch |err| {
                if (!self.running.load(.acquire)) break;
                std.debug.print("[UDP-CLIENT] receive error: {}\n", .{err});
                continue;
            };

            if (msg.data.len == 0) continue;

            const session = self.session_manager.getOrCreate(msg.from) catch |err| {
                std.debug.print("[UDP-CLIENT] Session creation error: {}\n", .{err});
                continue;
            };

            std.debug.print("[UDP-CLIENT] Received {} bytes from local {f}, stream_id={}\n", .{
                msg.data.len,
                msg.from,
                session.stream_id,
            });

            // Encode UDP data message
            var encode_buf: [70016]u8 = undefined;

            // Get source address bytes for encoding
            var addr_bytes: [16]u8 = undefined;
            var addr_len: usize = 0;
            var source_port: u16 = 0;

            switch (msg.from) {
                .ip4 => |v4| {
                    @memcpy(addr_bytes[0..4], &v4.bytes);
                    addr_len = 4;
                    source_port = v4.port;
                },
                .ip6 => |v6| {
                    @memcpy(&addr_bytes, &v6.bytes);
                    addr_len = 16;
                    source_port = v6.port;
                },
            }

            const udp_msg = tunnel.UdpDataMsg{
                .service_id = self.service_id,
                .stream_id = session.stream_id,
                .source_addr = addr_bytes[0..addr_len],
                .source_port = source_port,
                .data = msg.data,
            };

            const encoded_len = udp_msg.encodeInto(&encode_buf) catch |err| {
                std.debug.print("[UDP-CLIENT] Encode error: {}\n", .{err});
                continue;
            };

            self.send_fn(self.tunnel_conn, encode_buf[0 .. encoded_len + noise.TAG_LEN], encoded_len) catch |err| {
                std.debug.print("[UDP-CLIENT] Tunnel send error: {}\n", .{err});
            };
        }

        std.debug.print("[UDP-CLIENT] Local receiver thread stopped\n", .{});
    }

    /// Handle incoming UDP data from tunnel (forward to local client)
    pub fn handleUdpData(self: *UdpForwarder, udp_msg: tunnel.UdpDataMsg) !void {
        const session = self.session_manager.getByStreamId(udp_msg.stream_id) orelse {
            std.debug.print("[UDP-CLIENT] Unknown stream_id={}, dropping packet\n", .{udp_msg.stream_id});
            return;
        };

        try self.local_socket.send(self.io, &session.source_addr, udp_msg.data);

        std.debug.print("[UDP-CLIENT] Forwarded {} bytes to local {f}\n", .{
            udp_msg.data.len,
            session.source_addr,
        });
    }

    /// Cleanup expired sessions
    pub fn cleanupExpiredSessions(self: *UdpForwarder) !void {
        const removed = try self.session_manager.cleanupExpired(self.timeout_seconds);
        if (removed > 0) {
            std.debug.print("[UDP-CLIENT] Cleaned up {} expired sessions\n", .{removed});
        }
    }

    pub fn stop(self: *UdpForwarder) void {
        self.running.store(false, .release);
        // Shutdown the receive side to unblock the receiver thread.
        // Use the raw syscall — std.Io.net.Socket has no shutdown method.
        _ = posix.system.shutdown(self.local_socket.handle, posix.SHUT.RD);
        self.thread.join();
    }

    pub fn destroy(self: *UdpForwarder) void {
        self.local_socket.close(self.io);
        self.session_manager.deinit();
        self.allocator.destroy(self);
    }
};
