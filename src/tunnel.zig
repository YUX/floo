const std = @import("std");

/// Tunnel message types
pub const MessageType = enum(u8) {
    connect = 0x01,
    data = 0x02,
    close = 0x03,
    connect_ack = 0x04,
    connect_error = 0x05,
    udp_data = 0x06,
    heartbeat = 0x07,
    version = 0x08,
    reverse_connect = 0x09,

    pub fn parse(value: u8) !MessageType {
        return switch (value) {
            0x01 => .connect,
            0x02 => .data,
            0x03 => .close,
            0x04 => .connect_ack,
            0x05 => .connect_error,
            0x06 => .udp_data,
            0x07 => .heartbeat,
            0x08 => .version,
            0x09 => .reverse_connect,
            else => error.InvalidMessageType,
        };
    }
};

pub const StreamId = u32;

/// Service ID for identifying different services over one tunnel.
/// v2: u32, 0 is reserved and rejected at config load.
pub const ServiceId = u32;

/// `type(1) + service(4) + stream(4)`
pub const HEADER_SIZE: usize = 9;
pub const DATA_HEADER_SIZE: usize = HEADER_SIZE;

pub fn writeStreamHeader(buf: []u8, msg_type: MessageType, service_id: ServiceId, stream_id: StreamId) void {
    std.debug.assert(buf.len >= HEADER_SIZE);
    buf[0] = @intFromEnum(msg_type);
    std.mem.writeInt(u32, buf[1..5], service_id, .big);
    std.mem.writeInt(u32, buf[5..9], stream_id, .big);
}

pub const StreamHeader = struct {
    service_id: ServiceId,
    stream_id: StreamId,
};

pub fn readStreamHeader(data: []const u8, expected: MessageType) !StreamHeader {
    if (data.len < HEADER_SIZE) return error.InvalidMessage;
    if (data[0] != @intFromEnum(expected)) return error.InvalidMessageType;
    return .{
        .service_id = std.mem.readInt(u32, data[1..5], .big),
        .stream_id = std.mem.readInt(u32, data[5..9], .big),
    };
}

fn encodeAlloc(allocator: std.mem.Allocator, encode_into: anytype) ![]u8 {
    var scratch: [CONTROL_ENCODE_SCRATCH]u8 = undefined;
    const len = try encode_into.encodeInto(&scratch);
    const buf = try allocator.alloc(u8, len);
    @memcpy(buf, scratch[0..len]);
    return buf;
}

const CONTROL_ENCODE_SCRATCH = 4096;

/// Connect message: Request to forward to a target
/// Format: [type:1][service_id:4][stream_id:4][token_len:2][token...]
pub const ConnectMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    token: []const u8,

    pub fn encode(self: ConnectMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: ConnectMsg, buffer: []u8) !usize {
        const total_len = HEADER_SIZE + 2 + self.token.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        writeStreamHeader(buffer, .connect, self.service_id, self.stream_id);
        std.mem.writeInt(u16, buffer[9..11], @intCast(self.token.len), .big);
        @memcpy(buffer[11 .. 11 + self.token.len], self.token);
        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !ConnectMsg {
        const msg = try decodeRef(data);
        const token = try allocator.alloc(u8, msg.token.len);
        @memcpy(token, msg.token);
        return ConnectMsg{
            .service_id = msg.service_id,
            .stream_id = msg.stream_id,
            .token = token,
        };
    }

    pub fn decodeRef(data: []const u8) !ConnectMsg {
        if (data.len < HEADER_SIZE + 2) return error.InvalidMessage;
        const header = try readStreamHeader(data, .connect);
        const token_len = std.mem.readInt(u16, data[9..11], .big);
        if (data.len < HEADER_SIZE + 2 + token_len) return error.InvalidMessage;
        return ConnectMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
            .token = data[11 .. 11 + token_len],
        };
    }
};

pub const ConnectAckMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: ConnectAckMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: ConnectAckMsg, buffer: []u8) !usize {
        if (buffer.len < HEADER_SIZE) return error.BufferTooSmall;
        writeStreamHeader(buffer, .connect_ack, self.service_id, self.stream_id);
        return HEADER_SIZE;
    }

    pub fn decode(data: []const u8) !ConnectAckMsg {
        const header = try readStreamHeader(data, .connect_ack);
        return ConnectAckMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
        };
    }
};

pub const ErrorCode = enum(u8) {
    unknown_service = 1,
    authentication_failed = 2,
    connection_refused = 3,
    connection_timeout = 4,
    service_unavailable = 5,
    internal_error = 99,

    pub fn parse(value: u8) !ErrorCode {
        return switch (value) {
            1 => .unknown_service,
            2 => .authentication_failed,
            3 => .connection_refused,
            4 => .connection_timeout,
            5 => .service_unavailable,
            99 => .internal_error,
            else => error.InvalidErrorCode,
        };
    }
};

/// Format: [type:1][service_id:4][stream_id:4][error_code:1][msg_len:2][msg...]
pub const ConnectErrorMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    error_code: ErrorCode,
    error_msg: []const u8,

    pub fn encode(self: ConnectErrorMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: ConnectErrorMsg, buffer: []u8) !usize {
        const total_len = HEADER_SIZE + 1 + 2 + self.error_msg.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        writeStreamHeader(buffer, .connect_error, self.service_id, self.stream_id);
        buffer[9] = @intFromEnum(self.error_code);
        std.mem.writeInt(u16, buffer[10..12], @intCast(self.error_msg.len), .big);
        @memcpy(buffer[12 .. 12 + self.error_msg.len], self.error_msg);
        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !ConnectErrorMsg {
        const msg = try decodeRef(data);
        const copied = try allocator.alloc(u8, msg.error_msg.len);
        @memcpy(copied, msg.error_msg);
        return ConnectErrorMsg{
            .service_id = msg.service_id,
            .stream_id = msg.stream_id,
            .error_code = msg.error_code,
            .error_msg = copied,
        };
    }

    pub fn decodeRef(data: []const u8) !ConnectErrorMsg {
        if (data.len < HEADER_SIZE + 3) return error.InvalidMessage;
        const header = try readStreamHeader(data, .connect_error);
        const error_code = try ErrorCode.parse(data[9]);
        const msg_len = std.mem.readInt(u16, data[10..12], .big);
        if (data.len < HEADER_SIZE + 3 + msg_len) return error.InvalidMessage;
        return ConnectErrorMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
            .error_code = error_code,
            .error_msg = data[12 .. 12 + msg_len],
        };
    }
};

pub const DataMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    data: []const u8,

    pub fn encode(self: DataMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: DataMsg, buffer: []u8) !usize {
        const total_len = HEADER_SIZE + self.data.len;
        if (buffer.len < total_len) return error.BufferTooSmall;
        writeStreamHeader(buffer, .data, self.service_id, self.stream_id);
        @memcpy(buffer[HEADER_SIZE .. HEADER_SIZE + self.data.len], self.data);
        return total_len;
    }

    pub fn decode(data: []const u8) !DataMsg {
        const header = try readStreamHeader(data, .data);
        return DataMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
            .data = data[HEADER_SIZE..],
        };
    }
};

pub const CloseMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: CloseMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: CloseMsg, buffer: []u8) !usize {
        if (buffer.len < HEADER_SIZE) return error.BufferTooSmall;
        writeStreamHeader(buffer, .close, self.service_id, self.stream_id);
        return HEADER_SIZE;
    }

    pub fn decode(data: []const u8) !CloseMsg {
        const header = try readStreamHeader(data, .close);
        return CloseMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
        };
    }
};

/// Format: [type:1][service_id:4][stream_id:4][addr_len:1][addr_bytes...][port:2][data...]
pub const UdpDataMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,
    source_addr: []const u8,
    source_port: u16,
    data: []const u8,

    pub fn encode(self: UdpDataMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: UdpDataMsg, buffer: []u8) !usize {
        const total_len = HEADER_SIZE + 1 + self.source_addr.len + 2 + self.data.len;
        if (buffer.len < total_len) return error.BufferTooSmall;

        writeStreamHeader(buffer, .udp_data, self.service_id, self.stream_id);
        buffer[9] = @intCast(self.source_addr.len);
        @memcpy(buffer[10 .. 10 + self.source_addr.len], self.source_addr);
        const port_offset = 10 + self.source_addr.len;
        std.mem.writeInt(u16, buffer[port_offset..][0..2], self.source_port, .big);
        @memcpy(buffer[port_offset + 2 .. total_len], self.data);
        return total_len;
    }

    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !UdpDataMsg {
        const msg = try decodeRef(data);
        const addr = try allocator.alloc(u8, msg.source_addr.len);
        @memcpy(addr, msg.source_addr);
        return UdpDataMsg{
            .service_id = msg.service_id,
            .stream_id = msg.stream_id,
            .source_addr = addr,
            .source_port = msg.source_port,
            .data = msg.data,
        };
    }

    pub fn decodeRef(data: []const u8) !UdpDataMsg {
        if (data.len < HEADER_SIZE + 3) return error.InvalidMessage;
        const header = try readStreamHeader(data, .udp_data);
        const addr_len = data[9];
        if (data.len < HEADER_SIZE + 3 + addr_len) return error.InvalidMessage;
        const port_offset = 10 + addr_len;
        const port = std.mem.readInt(u16, data[port_offset..][0..2], .big);
        return UdpDataMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
            .source_addr = data[10 .. 10 + addr_len],
            .source_port = port,
            .data = data[port_offset + 2 ..],
        };
    }
};

pub const HeartbeatMsg = struct {
    timestamp: i64,

    pub fn encode(self: HeartbeatMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
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
        return HeartbeatMsg{ .timestamp = std.mem.readInt(i64, data[1..9], .big) };
    }
};

pub const VersionMsg = struct {
    version: []const u8,

    pub fn encode(self: VersionMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
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

pub const ReverseConnectMsg = struct {
    service_id: ServiceId,
    stream_id: StreamId,

    pub fn encode(self: ReverseConnectMsg, allocator: std.mem.Allocator) ![]u8 {
        return encodeAlloc(allocator, self);
    }

    pub fn encodeInto(self: ReverseConnectMsg, buffer: []u8) !usize {
        if (buffer.len < HEADER_SIZE) return error.BufferTooSmall;
        writeStreamHeader(buffer, .reverse_connect, self.service_id, self.stream_id);
        return HEADER_SIZE;
    }

    pub fn decode(data: []const u8) !ReverseConnectMsg {
        const header = try readStreamHeader(data, .reverse_connect);
        return ReverseConnectMsg{
            .service_id = header.service_id,
            .stream_id = header.stream_id,
        };
    }
};

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

    const ref = try UdpDataMsg.decodeRef(buf[0..len]);
    try std.testing.expectEqual(msg.service_id, ref.service_id);
    try std.testing.expectEqual(msg.stream_id, ref.stream_id);
    try std.testing.expectEqual(msg.source_port, ref.source_port);
    try std.testing.expectEqualSlices(u8, msg.source_addr, ref.source_addr);
    try std.testing.expectEqualSlices(u8, msg.data, ref.data);
    try std.testing.expect(@intFromPtr(ref.source_addr.ptr) == @intFromPtr(&buf[10]));
    try std.testing.expect(@intFromPtr(ref.data.ptr) == @intFromPtr(&buf[10 + 4 + 2]));

    const owned = try UdpDataMsg.decode(buf[0..len], allocator);
    defer allocator.free(owned.source_addr);
    try std.testing.expectEqualSlices(u8, msg.source_addr, owned.source_addr);
    try std.testing.expectEqualSlices(u8, msg.data, owned.data);
}

test "UdpDataMsg.decodeRef rejects truncated input" {
    var buf: [11]u8 = undefined;
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

    const ref = try ConnectMsg.decodeRef(encoded);
    try std.testing.expectEqual(msg.service_id, ref.service_id);
    try std.testing.expectEqual(msg.stream_id, ref.stream_id);
    try std.testing.expectEqualSlices(u8, msg.token, ref.token);
    try std.testing.expect(@intFromPtr(ref.token.ptr) == @intFromPtr(&encoded[11]));

    const owned = try ConnectMsg.decode(encoded, allocator);
    defer allocator.free(owned.token);
    try std.testing.expectEqualSlices(u8, msg.token, owned.token);
}

test "ConnectMsg.decodeRef rejects truncation and wrong type" {
    var short: [10]u8 = undefined;
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
    try std.testing.expect(@intFromPtr(ref.error_msg.ptr) == @intFromPtr(&encoded[12]));
}

test "MessageType.parse rejects unknown bytes" {
    try std.testing.expectEqual(MessageType.data, try MessageType.parse(0x02));
    try std.testing.expectError(error.InvalidMessageType, MessageType.parse(0xFF));
}

test "ErrorCode.parse rejects unknown bytes" {
    try std.testing.expectEqual(ErrorCode.unknown_service, try ErrorCode.parse(1));
    try std.testing.expectError(error.InvalidErrorCode, ErrorCode.parse(42));
}

test "u32 service id round-trips in headers" {
    const msg = CloseMsg{
        .service_id = 0xAABBCCDD,
        .stream_id = 99,
    };
    var buf: [16]u8 = undefined;
    const len = try msg.encodeInto(&buf);
    try std.testing.expectEqual(HEADER_SIZE, len);
    const decoded = try CloseMsg.decode(buf[0..len]);
    try std.testing.expectEqual(msg.service_id, decoded.service_id);
}
