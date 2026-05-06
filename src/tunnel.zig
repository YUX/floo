const std = @import("std");

/// Tunnel message types
pub const MessageType = enum(u8) {
    /// Client->Server: Request to connect to target
    connect = 0x01,
    /// Bidirectional: Data transfer (TCP)
    data = 0x02,
    /// Bidirectional: Close a stream
    close = 0x03,
    /// Server->Client: Acknowledge connection
    connect_ack = 0x04,
    /// Server->Client: Connection failed
    connect_error = 0x05,
    /// Bidirectional: UDP packet data
    udp_data = 0x06,
    /// Bidirectional: Heartbeat to keep connection alive
    heartbeat = 0x07,
    /// Bidirectional: Version exchange (sent after handshake)
    version = 0x08,
    /// Server->Client: Request reverse connection to local target
    reverse_connect = 0x09,
};

/// Stream ID for multiplexing multiple connections over one tunnel
pub const StreamId = u32;

/// Service ID for identifying different services over one tunnel
/// Each service is an independent port forward with its own protocol (TCP/UDP)
pub const ServiceId = u16;

/// Connect message: Request to forward to a target
pub const ConnectMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    token: []const u8, // Authentication token for this service (optional)

    pub fn encode(self: ConnectMsg, allocator: std.mem.Allocator) ![]u8 {
        // Format: [type:1][service_id:2][stream_id:4][token_len:2][token...]
        const total_len = 1 + 2 + 4 + 2 + self.token.len;
        const buf = try allocator.alloc(u8, total_len);

        buf[0] = @intFromEnum(MessageType.connect);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        std.mem.writeInt(u16, buf[7..9], @intCast(self.token.len), .big);
        @memcpy(buf[9 .. 9 + self.token.len], self.token);

        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    /// Returns the number of bytes written
    pub fn encodeInto(self: ConnectMsg, buffer: []u8) !usize {
        const total_len = 1 + 2 + 4 + 2 + self.token.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.connect);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);
        std.mem.writeInt(u16, buffer[7..9], @intCast(self.token.len), .big);
        @memcpy(buffer[9 .. 9 + self.token.len], self.token);

        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !ConnectMsg {
        if (data.len < 9) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.connect)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const token_len = std.mem.readInt(u16, data[7..9], .big);

        if (data.len < 9 + token_len) return error.InvalidMessage;

        const token = try allocator.alloc(u8, token_len);
        @memcpy(token, data[9 .. 9 + token_len]);

        return ConnectMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .token = token,
        };
    }

    /// Zero-allocation decode that returns a slice into `data` for the token.
    /// Valid only until the underlying decoder buffer is overwritten — used on
    /// the per-CONNECT control-plane hot path where handleConnect consumes
    /// the token synchronously (constant-time-compares it against the
    /// configured token, never holds across the next read).
    pub fn decodeRef(data: []const u8) !ConnectMsg {
        if (data.len < 9) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.connect)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const token_len = std.mem.readInt(u16, data[7..9], .big);
        if (data.len < 9 + token_len) return error.InvalidMessage;

        return ConnectMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .token = data[9 .. 9 + token_len],
        };
    }
};

/// ConnectAck message: Connection succeeded
pub const ConnectAckMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: ConnectAckMsg, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 7);
        buf[0] = @intFromEnum(MessageType.connect_ack);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    /// Returns the number of bytes written
    pub fn encodeInto(self: ConnectAckMsg, buffer: []u8) !usize {
        const total_len = 7;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.connect_ack);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);

        return total_len;
    }

    pub fn decode(data: []const u8) !ConnectAckMsg {
        if (data.len < 7) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.connect_ack)) return error.InvalidMessageType;

        return ConnectAckMsg{
            .service_id = std.mem.readInt(u16, data[1..3], .big),
            .stream_id = std.mem.readInt(u32, data[3..7], .big),
        };
    }
};

/// ConnectError message: Connection failed
/// Error codes for connection failures
pub const ErrorCode = enum(u8) {
    unknown_service = 1,
    authentication_failed = 2,
    connection_refused = 3,
    connection_timeout = 4,
    service_unavailable = 5,
    internal_error = 99,
};

pub const ConnectErrorMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    error_code: ErrorCode,
    error_msg: []const u8,

    pub fn encode(self: ConnectErrorMsg, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 1 + 2 + 4 + 1 + 2 + self.error_msg.len;
        const buf = try allocator.alloc(u8, total_len);

        buf[0] = @intFromEnum(MessageType.connect_error);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        buf[7] = @intFromEnum(self.error_code);
        std.mem.writeInt(u16, buf[8..10], @intCast(self.error_msg.len), .big);
        @memcpy(buf[10 .. 10 + self.error_msg.len], self.error_msg);

        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    /// Returns the number of bytes written
    pub fn encodeInto(self: ConnectErrorMsg, buffer: []u8) !usize {
        const total_len = 1 + 2 + 4 + 1 + 2 + self.error_msg.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.connect_error);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);
        buffer[7] = @intFromEnum(self.error_code);
        std.mem.writeInt(u16, buffer[8..10], @intCast(self.error_msg.len), .big);
        @memcpy(buffer[10 .. 10 + self.error_msg.len], self.error_msg);

        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !ConnectErrorMsg {
        if (data.len < 10) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.connect_error)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const error_code: ErrorCode = @enumFromInt(data[7]);
        const msg_len = std.mem.readInt(u16, data[8..10], .big);

        if (data.len < 10 + msg_len) return error.InvalidMessage;

        const msg = try allocator.alloc(u8, msg_len);
        @memcpy(msg, data[10 .. 10 + msg_len]);

        return ConnectErrorMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .error_code = error_code,
            .error_msg = msg,
        };
    }

    /// Zero-allocation decode that returns a slice into `data` for error_msg.
    /// Valid only until the underlying decoder buffer is overwritten —
    /// callers consume it synchronously (logging) and don't hold across
    /// later reads.
    pub fn decodeRef(data: []const u8) !ConnectErrorMsg {
        if (data.len < 10) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.connect_error)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const error_code: ErrorCode = @enumFromInt(data[7]);
        const msg_len = std.mem.readInt(u16, data[8..10], .big);
        if (data.len < 10 + msg_len) return error.InvalidMessage;

        return ConnectErrorMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .error_code = error_code,
            .error_msg = data[10 .. 10 + msg_len],
        };
    }
};

/// Data message: Transfer data on a stream
pub const DataMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    data: []const u8,

    pub fn encode(self: DataMsg, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 1 + 2 + 4 + self.data.len;
        const buf = try allocator.alloc(u8, total_len);

        buf[0] = @intFromEnum(MessageType.data);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        @memcpy(buf[7 .. 7 + self.data.len], self.data);

        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    /// Returns the number of bytes written
    pub fn encodeInto(self: DataMsg, buffer: []u8) !usize {
        const total_len = 1 + 2 + 4 + self.data.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.data);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);
        @memcpy(buffer[7 .. 7 + self.data.len], self.data);

        return total_len;
    }

    pub fn decode(data: []const u8) !DataMsg {
        if (data.len < 7) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.data)) return error.InvalidMessageType;

        return DataMsg{
            .service_id = std.mem.readInt(u16, data[1..3], .big),
            .stream_id = std.mem.readInt(u32, data[3..7], .big),
            .data = data[7..],
        };
    }
};

/// Close message: Close a stream
pub const CloseMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: CloseMsg, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 7);
        buf[0] = @intFromEnum(MessageType.close);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    /// Returns the number of bytes written
    pub fn encodeInto(self: CloseMsg, buffer: []u8) !usize {
        const total_len = 7;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.close);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);

        return total_len;
    }

    pub fn decode(data: []const u8) !CloseMsg {
        if (data.len < 7) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.close)) return error.InvalidMessageType;

        return CloseMsg{
            .service_id = std.mem.readInt(u16, data[1..3], .big),
            .stream_id = std.mem.readInt(u32, data[3..7], .big),
        };
    }
};

/// UDP Data message: Transfer UDP packet with source address information
/// Format: [type:1][service_id:2][stream_id:4][addr_len:1][addr_bytes...][port:2][data...]
/// This preserves UDP source address so replies can be routed correctly
pub const UdpDataMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    source_addr: []const u8, // IPv4 or IPv6 address bytes
    source_port: u16,
    data: []const u8,

    pub fn encode(self: UdpDataMsg, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 1 + 2 + 4 + 1 + self.source_addr.len + 2 + self.data.len;
        const buf = try allocator.alloc(u8, total_len);

        buf[0] = @intFromEnum(MessageType.udp_data);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        buf[7] = @intCast(self.source_addr.len);
        @memcpy(buf[8 .. 8 + self.source_addr.len], self.source_addr);
        const port_offset = 8 + self.source_addr.len;
        std.mem.writeInt(u16, buf[port_offset..][0..2], self.source_port, .big);
        @memcpy(buf[port_offset + 2 ..], self.data);

        return buf;
    }

    /// Encode directly into provided buffer (no allocation!)
    pub fn encodeInto(self: UdpDataMsg, buffer: []u8) !usize {
        const total_len = 1 + 2 + 4 + 1 + self.source_addr.len + 2 + self.data.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.udp_data);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);
        buffer[7] = @intCast(self.source_addr.len);
        @memcpy(buffer[8 .. 8 + self.source_addr.len], self.source_addr);
        const port_offset = 8 + self.source_addr.len;
        std.mem.writeInt(u16, buffer[port_offset..][0..2], self.source_port, .big);
        @memcpy(buffer[port_offset + 2 .. total_len], self.data);

        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !UdpDataMsg {
        if (data.len < 10) return error.InvalidMessage; // Minimum: type + service_id + stream_id + addr_len(0) + port
        if (data[0] != @intFromEnum(MessageType.udp_data)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const addr_len = data[7];

        if (data.len < 10 + addr_len) return error.InvalidMessage;

        const addr = try allocator.alloc(u8, addr_len);
        @memcpy(addr, data[8 .. 8 + addr_len]);

        const port_offset = 8 + addr_len;
        const port = std.mem.readInt(u16, data[port_offset..][0..2], .big);

        return UdpDataMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .source_addr = addr,
            .source_port = port,
            .data = data[port_offset + 2 ..],
        };
    }

    /// Zero-allocation decode that returns slices into `data`. The returned
    /// `source_addr` and `data` are valid only until the underlying buffer is
    /// overwritten or freed — caller must consume synchronously.
    ///
    /// Used on the per-packet UDP hot path to avoid the alloc+memcpy that
    /// `decode` performs on every datagram.
    pub fn decodeRef(data: []const u8) !UdpDataMsg {
        if (data.len < 10) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.udp_data)) return error.InvalidMessageType;

        const service_id = std.mem.readInt(u16, data[1..3], .big);
        const stream_id = std.mem.readInt(u32, data[3..7], .big);
        const addr_len = data[7];
        if (data.len < 10 + addr_len) return error.InvalidMessage;
        const port_offset = 8 + addr_len;
        const port = std.mem.readInt(u16, data[port_offset..][0..2], .big);

        return UdpDataMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .source_addr = data[8 .. 8 + addr_len],
            .source_port = port,
            .data = data[port_offset + 2 ..],
        };
    }
};

/// Heartbeat message: Keep connection alive and detect failures
pub const HeartbeatMsg = struct {
    /// Timestamp in milliseconds since epoch
    timestamp: i64,

    pub fn encode(self: HeartbeatMsg, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 9); // type(1) + timestamp(8)
        buf[0] = @intFromEnum(MessageType.heartbeat);
        std.mem.writeInt(i64, buf[1..9], self.timestamp, .big);
        return buf;
    }

    pub fn encodeInto(self: HeartbeatMsg, buffer: []u8) !usize {
        if (buffer.len < 9) return error.BufferTooSmall;
        buffer[0] = @intFromEnum(MessageType.heartbeat);
        std.mem.writeInt(i64, buffer[1..9], self.timestamp, .big);
        return 9;
    }

    pub fn decode(data: []const u8) !HeartbeatMsg {
        if (data.len < 9) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.heartbeat)) return error.InvalidMessageType;

        const timestamp = std.mem.readInt(i64, data[1..9], .big);
        return HeartbeatMsg{ .timestamp = timestamp };
    }
};

/// Version message: Exchanged after handshake to ensure compatibility
/// Format: [type:1][version_len:1][version_string]
/// Example: "0.1.2" or "0.2.0"
pub const VersionMsg = struct {
    version: []const u8,

    pub fn encode(self: VersionMsg, allocator: std.mem.Allocator) ![]u8 {
        // Format: [type:1][version_len:1][version_string...]
        const total_len = 1 + 1 + self.version.len;
        const buf = try allocator.alloc(u8, total_len);

        buf[0] = @intFromEnum(MessageType.version);
        buf[1] = @intCast(self.version.len);
        @memcpy(buf[2 .. 2 + self.version.len], self.version);

        return buf;
    }

    pub fn encodeInto(self: VersionMsg, buffer: []u8) !usize {
        const total_len = 2 + self.version.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        buffer[0] = @intFromEnum(MessageType.version);
        buffer[1] = @intCast(self.version.len);
        @memcpy(buffer[2 .. 2 + self.version.len], self.version);

        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !VersionMsg {
        if (data.len < 2) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.version)) return error.InvalidMessageType;

        const version_len = data[1];
        if (data.len < 2 + version_len) return error.InvalidMessage;

        const version = try allocator.alloc(u8, version_len);
        @memcpy(version, data[2 .. 2 + version_len]);

        return VersionMsg{ .version = version };
    }
};

/// ReverseConnect message: Server requests client to connect to local target
/// Format: [type:1][service_id:2][stream_id:4]
/// Used for reverse tunneling where server initiates connection through client
pub const ReverseConnectMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: ReverseConnectMsg, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, 7);
        buf[0] = @intFromEnum(MessageType.reverse_connect);
        std.mem.writeInt(u16, buf[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buf[3..7], self.stream_id, .big);
        return buf;
    }

    pub fn encodeInto(self: ReverseConnectMsg, buffer: []u8) !usize {
        if (buffer.len < 7) return error.BufferTooSmall;
        buffer[0] = @intFromEnum(MessageType.reverse_connect);
        std.mem.writeInt(u16, buffer[1..3], self.service_id, .big);
        std.mem.writeInt(u32, buffer[3..7], self.stream_id, .big);
        return 7;
    }

    pub fn decode(data: []const u8) !ReverseConnectMsg {
        if (data.len < 7) return error.InvalidMessage;
        if (data[0] != @intFromEnum(MessageType.reverse_connect)) return error.InvalidMessageType;

        return ReverseConnectMsg{
            .service_id = std.mem.readInt(u16, data[1..3], .big),
            .stream_id = std.mem.readInt(u32, data[3..7], .big),
        };
    }
};

// Tests
test "ConnectMsg encode/decode" {
    const allocator = std.testing.allocator;

    const msg = ConnectMsg{
        .service_id = 1,
        .stream_id = 123,
        .token = "test-token",
    };

    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    const decoded = try ConnectMsg.decode(encoded, allocator);
    defer allocator.free(decoded.token);

    try std.testing.expectEqual(msg.service_id, decoded.service_id);
    try std.testing.expectEqual(msg.stream_id, decoded.stream_id);
    try std.testing.expectEqualSlices(u8, msg.token, decoded.token);
}

test "DataMsg encode/decode" {
    const allocator = std.testing.allocator;

    const msg = DataMsg{
        .service_id = 2,
        .stream_id = 456,
        .data = "hello world",
    };

    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    const decoded = try DataMsg.decode(encoded);

    try std.testing.expectEqual(msg.service_id, decoded.service_id);
    try std.testing.expectEqual(msg.stream_id, decoded.stream_id);
    try std.testing.expectEqualSlices(u8, msg.data, decoded.data);
}

test "CloseMsg encode/decode" {
    const allocator = std.testing.allocator;

    const msg = CloseMsg{
        .service_id = 3,
        .stream_id = 789,
    };

    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    const decoded = try CloseMsg.decode(encoded);

    try std.testing.expectEqual(msg.service_id, decoded.service_id);
    try std.testing.expectEqual(msg.stream_id, decoded.stream_id);
}

test "UdpDataMsg.decodeRef matches decode (no alloc)" {
    const allocator = std.testing.allocator;

    const msg = UdpDataMsg{
        .service_id = 4,
        .stream_id = 0xDEADBEEF,
        .source_addr = &[_]u8{ 192, 168, 1, 42 },
        .source_port = 5353,
        .data = "hello udp",
    };

    var buf: [128]u8 = undefined;
    const len = try msg.encodeInto(&buf);

    // Reference path: zero-alloc.
    const ref = try UdpDataMsg.decodeRef(buf[0..len]);
    try std.testing.expectEqual(msg.service_id, ref.service_id);
    try std.testing.expectEqual(msg.stream_id, ref.stream_id);
    try std.testing.expectEqual(msg.source_port, ref.source_port);
    try std.testing.expectEqualSlices(u8, msg.source_addr, ref.source_addr);
    try std.testing.expectEqualSlices(u8, msg.data, ref.data);
    // The slice must point into the original buffer, not a copy.
    try std.testing.expect(@intFromPtr(ref.source_addr.ptr) == @intFromPtr(&buf[8]));
    try std.testing.expect(@intFromPtr(ref.data.ptr) == @intFromPtr(&buf[8 + 4 + 2]));

    // Allocating path: parity check.
    const owned = try UdpDataMsg.decode(buf[0..len], allocator);
    defer allocator.free(owned.source_addr);
    try std.testing.expectEqualSlices(u8, msg.source_addr, owned.source_addr);
    try std.testing.expectEqualSlices(u8, msg.data, owned.data);
}

test "UdpDataMsg.decodeRef rejects truncated input" {
    var buf: [9]u8 = undefined;
    buf[0] = @intFromEnum(MessageType.udp_data);
    try std.testing.expectError(error.InvalidMessage, UdpDataMsg.decodeRef(&buf));
}

test "UdpDataMsg.decodeRef rejects wrong message type" {
    var buf: [16]u8 = undefined;
    buf[0] = @intFromEnum(MessageType.data);
    try std.testing.expectError(error.InvalidMessageType, UdpDataMsg.decodeRef(&buf));
}

test "ConnectMsg.decodeRef parity with decode" {
    const allocator = std.testing.allocator;

    const msg = ConnectMsg{
        .service_id = 7,
        .stream_id = 0xCAFEBABE,
        .token = "secret-tok",
    };
    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    // Zero-alloc: token slices into the input buffer.
    const ref = try ConnectMsg.decodeRef(encoded);
    try std.testing.expectEqual(msg.service_id, ref.service_id);
    try std.testing.expectEqual(msg.stream_id, ref.stream_id);
    try std.testing.expectEqualSlices(u8, msg.token, ref.token);
    try std.testing.expect(@intFromPtr(ref.token.ptr) == @intFromPtr(&encoded[9]));

    // Allocating path: same fields.
    const owned = try ConnectMsg.decode(encoded, allocator);
    defer allocator.free(owned.token);
    try std.testing.expectEqualSlices(u8, msg.token, owned.token);
}

test "ConnectMsg.decodeRef rejects truncation and wrong type" {
    var short: [8]u8 = undefined;
    short[0] = @intFromEnum(MessageType.connect);
    try std.testing.expectError(error.InvalidMessage, ConnectMsg.decodeRef(&short));

    var wrong: [16]u8 = undefined;
    wrong[0] = @intFromEnum(MessageType.data);
    try std.testing.expectError(error.InvalidMessageType, ConnectMsg.decodeRef(&wrong));
}

test "ConnectErrorMsg.decodeRef parity" {
    const allocator = std.testing.allocator;

    const msg = ConnectErrorMsg{
        .service_id = 11,
        .stream_id = 0x12345678,
        .error_code = .authentication_failed,
        .error_msg = "bad token",
    };
    const encoded = try msg.encode(allocator);
    defer allocator.free(encoded);

    const ref = try ConnectErrorMsg.decodeRef(encoded);
    try std.testing.expectEqual(msg.service_id, ref.service_id);
    try std.testing.expectEqual(msg.stream_id, ref.stream_id);
    try std.testing.expectEqual(msg.error_code, ref.error_code);
    try std.testing.expectEqualSlices(u8, msg.error_msg, ref.error_msg);
    try std.testing.expect(@intFromPtr(ref.error_msg.ptr) == @intFromPtr(&encoded[10]));
}
