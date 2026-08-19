const std = @import("std");
const Io = std.Io;
const noise = @import("../noise.zig");
const tunnel = @import("../tunnel.zig");
const protocol = @import("../protocol.zig");
const common = @import("../common.zig");
const build_options = @import("build_options");

/// Role of the endpoint for version exchange and handshake semantics.
pub const Role = enum { server, client };

/// Optional metrics collected while establishing a secure channel.
pub const HandshakeMetrics = struct {
    elapsed_ns: i128 = 0,
};

/// Shared encryption stats so callers can aggregate profile data.
pub const EncryptionStats = struct {
    total_ns: *std.atomic.Value(u64),
    calls: *std.atomic.Value(u64),

    pub fn record(self: EncryptionStats, delta: u64) void {
        _ = self.total_ns.fetchAdd(delta, .monotonic);
        _ = self.calls.fetchAdd(1, .monotonic);
    }
};

pub const ThroughputStats = struct {
    tx_bytes: *std.atomic.Value(u64),
    rx_bytes: *std.atomic.Value(u64),

    pub fn recordTx(self: ThroughputStats, amount: usize) void {
        _ = self.tx_bytes.fetchAdd(@intCast(amount), .monotonic);
    }

    pub fn recordRx(self: ThroughputStats, amount: usize) void {
        _ = self.rx_bytes.fetchAdd(@intCast(amount), .monotonic);
    }
};

pub const ChannelInit = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    reader: *Io.Reader,
    writer: *Io.Writer,
    cipher: []const u8,
    psk: []const u8,
    static_keypair: std.crypto.dh.X25519.KeyPair,
    role: Role,
    version: []const u8 = build_options.version,
    stats: ?EncryptionStats = null,
    throughput: ?ThroughputStats = null,
    handshake_metrics: ?*HandshakeMetrics = null,
};

/// Bidirectional encrypted transport over a TCP Stream.
///
/// Encrypt is lock-free: send seq is a `fetchAdd`, then AEAD runs without
/// the write mutex. `writev` stays under `send_mutex` so bytes stay ordered.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    reader: *Io.Reader,
    writer: *Io.Writer,
    encryption_enabled: bool,
    send_cipher: ?noise.TransportCipher,
    recv_cipher: ?noise.TransportCipher,
    send_mutex: common.HotMutex,
    stats: ?EncryptionStats,
    throughput: ?ThroughputStats,

    pub fn init(params: ChannelInit) !Channel {
        var send_cipher: ?noise.TransportCipher = null;
        var recv_cipher: ?noise.TransportCipher = null;

        const encryption_enabled = !std.mem.eql(u8, params.cipher, "none");

        if (encryption_enabled) {
            const cipher_type = noise.CipherType.fromString(params.cipher) catch return error.InvalidCipher;

            var handshake_timer_start: i128 = 0;
            if (params.handshake_metrics) |_| {
                handshake_timer_start = common.nanoTimestamp();
            }

            const handshake = noise.noiseXXHandshake(
                params.io,
                params.reader,
                params.writer,
                cipher_type,
                params.role == .client,
                params.static_keypair,
                params.psk,
            ) catch |err| switch (err) {
                error.MissingPsk, error.AuthenticationFailed => return err,
                else => return error.HandshakeFailed,
            };

            if (params.handshake_metrics) |metrics| {
                const stop = common.nanoTimestamp();
                metrics.elapsed_ns = stop - handshake_timer_start;
            }

            send_cipher = handshake.send_cipher;
            recv_cipher = handshake.recv_cipher;

            try exchangeVersions(
                params.reader,
                params.writer,
                params.role,
                &send_cipher.?,
                &recv_cipher.?,
                params.version,
                params.allocator,
            );
        } else {
            var handshake_timer_start: i128 = 0;
            if (params.handshake_metrics) |_| {
                handshake_timer_start = common.nanoTimestamp();
            }
            noise.plaintextPskHandshake(
                params.io,
                params.reader,
                params.writer,
                params.role == .client,
                params.psk,
            ) catch |err| switch (err) {
                error.MissingPsk, error.AuthenticationFailed => return err,
                else => return error.HandshakeFailed,
            };
            if (params.handshake_metrics) |metrics| {
                const stop = common.nanoTimestamp();
                metrics.elapsed_ns = stop - handshake_timer_start;
            }
        }

        return Channel{
            .allocator = params.allocator,
            .io = params.io,
            .stream = params.stream,
            .reader = params.reader,
            .writer = params.writer,
            .encryption_enabled = encryption_enabled,
            .send_cipher = send_cipher,
            .recv_cipher = recv_cipher,
            .send_mutex = .{},
            .stats = params.stats,
            .throughput = params.throughput,
        };
    }

    pub fn deinit(self: *Channel) void {
        self.* = undefined;
    }

    pub fn isEncrypted(self: *const Channel) bool {
        return self.encryption_enabled;
    }

    /// Send an immutable payload. Encrypt is lock-free; writev is serialized.
    pub fn sendCopy(self: *Channel, payload: []const u8) !void {
        const fd = self.stream.socket.handle;

        if (!self.encryption_enabled) {
            self.send_mutex.lock();
            defer self.send_mutex.unlock();
            try common.writeFrameDirect(fd, payload, null);
            self.recordTx(payload.len);
            return;
        }

        var stack: [common.CONTROL_MSG_BUFFER_SIZE + noise.TAG_LEN]u8 = undefined;
        var heap: ?[]u8 = null;
        defer if (heap) |buf| self.allocator.free(buf);

        const required_len = payload.len + noise.TAG_LEN;
        const target_buf = if (required_len <= stack.len)
            stack[0..required_len]
        else blk: {
            heap = try self.allocator.alloc(u8, required_len);
            break :blk heap.?;
        };

        @memcpy(target_buf[0..payload.len], payload);
        const seq, const encrypted_slice = try self.encryptInPlace(target_buf, payload.len);
        self.send_mutex.lock();
        defer self.send_mutex.unlock();
        try common.writeFrameDirect(fd, encrypted_slice, seq);
        self.recordTx(payload.len);
    }

    /// Encrypt (lock-free) then write under the mutex.
    pub fn sendDataInPlace(self: *Channel, buffer: []u8, payload_len: usize) !void {
        const slice, const seq = try self.prepareSendSlice(buffer, payload_len);
        self.send_mutex.lock();
        defer self.send_mutex.unlock();
        try common.writeFrameDirect(self.stream.socket.handle, slice, seq);
        self.recordTx(payload_len);
    }

    /// Decrypt a decoded wire frame in place. Plaintext path records Rx.
    pub fn decryptFrameInPlace(self: *Channel, frame: protocol.WireFrame) ![]const u8 {
        if (!self.encryption_enabled) {
            self.recordRx(frame.payload.len);
            return frame.payload;
        }

        if (frame.payload.len < noise.TAG_LEN) {
            return error.InvalidFrame;
        }
        if (frame.seq >= noise.MAX_NONCE) {
            return error.NonceExhausted;
        }

        const plaintext_len = frame.payload.len - noise.TAG_LEN;

        if (self.recv_cipher) |*cipher| {
            try cipher.decrypt(frame.payload, frame.payload[0..plaintext_len], frame.seq, &frame.aad);
        } else {
            return error.CipherUnavailable;
        }
        self.recordRx(plaintext_len);
        return frame.payload[0..plaintext_len];
    }

    fn prepareSendSlice(self: *Channel, buffer: []u8, payload_len: usize) !struct { []u8, ?u64 } {
        if (!self.encryption_enabled) {
            if (payload_len > buffer.len) return error.BufferTooSmall;
            return .{ buffer[0..payload_len], null };
        }

        if (buffer.len < payload_len + noise.TAG_LEN) {
            return error.BufferTooSmall;
        }

        const seq, const slice = try self.encryptInPlace(buffer, payload_len);
        return .{ slice, seq };
    }

    fn encryptInPlace(self: *Channel, buffer: []u8, payload_len: usize) !struct { u64, []u8 } {
        const encrypted_len = payload_len + noise.TAG_LEN;
        const cipher_ptr = if (self.send_cipher) |*cipher| cipher else return error.CipherUnavailable;

        const seq = cipher_ptr.nonce.fetchAdd(1, .monotonic);
        if (seq >= noise.MAX_NONCE) return error.NonceExhausted;

        const aad = protocol.makeAad(@intCast(encrypted_len), seq);

        if (self.stats) |stats| {
            const start_ns = common.nanoTimestamp();
            try cipher_ptr.encrypt(buffer[0..payload_len], buffer[0..encrypted_len], seq, &aad);
            const end_ns = common.nanoTimestamp();
            const delta: u64 = @intCast(end_ns - start_ns);
            stats.record(delta);
        } else {
            try cipher_ptr.encrypt(buffer[0..payload_len], buffer[0..encrypted_len], seq, &aad);
        }

        return .{ seq, buffer[0..encrypted_len] };
    }

    fn recordTx(self: *Channel, amount: usize) void {
        if (self.throughput) |stats| {
            stats.recordTx(amount);
        }
    }

    fn recordRx(self: *Channel, amount: usize) void {
        if (self.throughput) |stats| {
            stats.recordRx(amount);
        }
    }
};

fn exchangeVersions(
    reader: *Io.Reader,
    writer: *Io.Writer,
    role: Role,
    send_cipher: *noise.TransportCipher,
    recv_cipher: *noise.TransportCipher,
    local_version: []const u8,
    allocator: std.mem.Allocator,
) !void {
    var encrypted_buf: [512]u8 = undefined;
    var plaintext_buf: [256]u8 = undefined;

    switch (role) {
        .server => {
            const frame = try receiveEncryptedFrameInto(reader, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
            try sendVersionFrame(writer, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
        },
        .client => {
            try sendVersionFrame(writer, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
            const frame = try receiveEncryptedFrameInto(reader, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
        },
    }
}

const ReceivedFrame = struct {
    seq: u64,
    payload: []u8,
    aad: [protocol.AAD_SIZE]u8,
};

fn receiveEncryptedFrameInto(reader: *Io.Reader, buffer: []u8) !ReceivedFrame {
    var prefix: [protocol.ENCRYPTED_PREFIX_SIZE]u8 = undefined;
    try common.recvAll(reader, &prefix);
    const frame_len = std.mem.readInt(u32, prefix[0..4], .big);
    const seq = std.mem.readInt(u64, prefix[4..12], .big);
    if (frame_len > buffer.len) return error.FrameTooLarge;
    const payload = buffer[0..frame_len];
    try common.recvAll(reader, payload);
    return .{
        .seq = seq,
        .payload = payload,
        .aad = prefix,
    };
}

fn decryptVersionFrameInto(
    cipher: *noise.TransportCipher,
    frame: ReceivedFrame,
    output: []u8,
) ![]const u8 {
    if (frame.payload.len < noise.TAG_LEN) return error.InvalidFrame;
    const plaintext_len = frame.payload.len - noise.TAG_LEN;
    if (plaintext_len > output.len) return error.FrameTooLarge;
    try cipher.decrypt(frame.payload, output[0..plaintext_len], frame.seq, &frame.aad);
    return output[0..plaintext_len];
}

fn sendVersionFrame(
    writer: *Io.Writer,
    cipher: *noise.TransportCipher,
    version: []const u8,
    plain_buf: []u8,
    encrypted_buf: []u8,
) !void {
    const msg = tunnel.VersionMsg{ .version = version };
    const plain_len = try msg.encodeInto(plain_buf);

    const encrypted_len = plain_len + noise.TAG_LEN;
    if (encrypted_len > encrypted_buf.len) return error.FrameTooLarge;

    const seq = cipher.nonce.fetchAdd(1, .monotonic);
    if (seq >= noise.MAX_NONCE) return error.NonceExhausted;
    const aad = protocol.makeAad(@intCast(encrypted_len), seq);
    try cipher.encrypt(plain_buf[0..plain_len], encrypted_buf[0..encrypted_len], seq, &aad);

    try common.writeFrame(writer, encrypted_buf[0..encrypted_len], seq);
    try writer.flush();
}

fn validateVersion(allocator: std.mem.Allocator, payload: []const u8, expected: []const u8) !void {
    const msg = try tunnel.VersionMsg.decode(payload, allocator);
    defer allocator.free(msg.version);

    if (!std.mem.eql(u8, msg.version, expected)) {
        return error.VersionMismatch;
    }
}
