const std = @import("std");
const posix = std.posix;
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
        _ = self.total_ns.fetchAdd(delta, .acq_rel);
        _ = self.calls.fetchAdd(1, .acq_rel);
    }
};

/// Optional throughput counters (bytes in/out) shared by caller.
pub const ThroughputStats = struct {
    tx_bytes: *std.atomic.Value(u64),
    rx_bytes: *std.atomic.Value(u64),

    pub fn recordTx(self: ThroughputStats, amount: usize) void {
        _ = self.tx_bytes.fetchAdd(@intCast(amount), .acq_rel);
    }

    pub fn recordRx(self: ThroughputStats, amount: usize) void {
        _ = self.rx_bytes.fetchAdd(@intCast(amount), .acq_rel);
    }
};

/// Parameters required to establish a tunnel transport.
pub const ChannelInit = struct {
    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    cipher: []const u8,
    psk: []const u8,
    static_keypair: std.crypto.dh.X25519.KeyPair,
    role: Role,
    version: []const u8 = build_options.version,
    stats: ?EncryptionStats = null,
    throughput: ?ThroughputStats = null,
    handshake_metrics: ?*HandshakeMetrics = null,
};

/// Bidirectional transport that knows how to frame, encrypt, and decrypt messages.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    encryption_enabled: bool,
    send_cipher: ?noise.TransportCipher,
    recv_cipher: ?noise.TransportCipher,
    decrypt_buffer: []u8,
    control_buffer: []u8,
    large_send_buffer: []u8,
    send_mutex: std.Thread.Mutex,
    stats: ?EncryptionStats,
    throughput: ?ThroughputStats,

    pub fn init(params: ChannelInit) !Channel {
        var decrypt_buffer: []u8 = &[_]u8{};
        var control_buffer: []u8 = &[_]u8{};
        const large_send_buffer: []u8 = &[_]u8{};
        var send_cipher: ?noise.TransportCipher = null;
        var recv_cipher: ?noise.TransportCipher = null;

        const encryption_enabled = !std.mem.eql(u8, params.cipher, "none");

        if (encryption_enabled) {
            const cipher_type = noise.CipherType.fromString(params.cipher) catch return error.InvalidCipher;

            var handshake_timer_start: i128 = 0;
            if (params.handshake_metrics) |_| {
                handshake_timer_start = std.time.nanoTimestamp();
            }

            const handshake = noise.noiseXXHandshake(
                params.fd,
                cipher_type,
                params.role == .client,
                params.static_keypair,
                params.psk,
            ) catch |err| switch (err) {
                error.MissingPsk => return err,
                else => return error.HandshakeFailed,
            };

            if (params.handshake_metrics) |metrics| {
                const stop = std.time.nanoTimestamp();
                metrics.elapsed_ns = stop - handshake_timer_start;
            }

            send_cipher = handshake.send_cipher;
            recv_cipher = handshake.recv_cipher;

            try exchangeVersions(params.fd, params.role, &send_cipher.?, &recv_cipher.?, params.version, params.allocator);

            decrypt_buffer = try params.allocator.alloc(u8, protocol.MAX_FRAME_SIZE);
            control_buffer = try params.allocator.alloc(u8, common.CONTROL_MSG_BUFFER_SIZE + noise.TAG_LEN);
        } else if (params.handshake_metrics) |metrics| {
            metrics.elapsed_ns = 0;
        }

        return Channel{
            .allocator = params.allocator,
            .fd = params.fd,
            .encryption_enabled = encryption_enabled,
            .send_cipher = send_cipher,
            .recv_cipher = recv_cipher,
            .decrypt_buffer = decrypt_buffer,
            .control_buffer = control_buffer,
            .large_send_buffer = large_send_buffer,
            .send_mutex = .{},
            .stats = params.stats,
            .throughput = params.throughput,
        };
    }

    pub fn deinit(self: *Channel) void {
        if (self.decrypt_buffer.len > 0) {
            self.allocator.free(self.decrypt_buffer);
        }
        if (self.control_buffer.len > 0) {
            self.allocator.free(self.control_buffer);
        }
        if (self.large_send_buffer.len > 0) {
            self.allocator.free(self.large_send_buffer);
        }
        self.* = undefined;
    }

    pub fn isEncrypted(self: *const Channel) bool {
        return self.encryption_enabled;
    }

    /// Send an immutable payload by copying it into an internal scratch buffer.
    /// Used for small control-plane messages and any caller that only has const data.
    pub fn sendCopy(self: *Channel, payload: []const u8) !void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();

        if (!self.encryption_enabled) {
            try common.writeFrameLocked(self.fd, payload);
            self.recordTx(payload.len);
            return;
        }

        const required_len = payload.len + noise.TAG_LEN;
        const target_buf = if (required_len <= self.control_buffer.len)
            self.control_buffer[0..required_len]
        else
            try self.ensureLargeBuffer(required_len);

        @memcpy(target_buf[0..payload.len], payload);
        const encrypted_slice = try self.encryptInPlace(target_buf, payload.len);
        try common.writeFrameLocked(self.fd, encrypted_slice);
        self.recordTx(payload.len);
    }

    /// Encrypt (when necessary) and send a mutable payload in-place.
    /// `buffer.len` must include enough capacity for the ciphertext/tag.
    pub fn sendDataInPlace(self: *Channel, buffer: []u8, payload_len: usize) !void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();

        const slice = try self.prepareSendSlice(buffer, payload_len);
        try common.writeFrameLocked(self.fd, slice);
        self.recordTx(payload_len);
    }

    /// Decrypt frame payload. Returns plaintext slice with lifetime tied to the channel.
    pub fn decryptFrame(self: *Channel, encrypted_payload: []const u8) ![]const u8 {
        if (!self.encryption_enabled) {
            return encrypted_payload;
        }

        if (encrypted_payload.len < noise.TAG_LEN) {
            return error.InvalidFrame;
        }

        const plaintext_len = encrypted_payload.len - noise.TAG_LEN;
        if (plaintext_len > self.decrypt_buffer.len) {
            return error.FrameTooLarge;
        }

        if (self.recv_cipher) |*cipher| {
            try cipher.decrypt(encrypted_payload, self.decrypt_buffer[0..plaintext_len]);
        } else {
            return error.CipherUnavailable;
        }
        self.recordRx(plaintext_len);
        return self.decrypt_buffer[0..plaintext_len];
    }

    fn prepareSendSlice(self: *Channel, buffer: []u8, payload_len: usize) ![]u8 {
        if (!self.encryption_enabled) {
            if (payload_len > buffer.len) return error.BufferTooSmall;
            return buffer[0..payload_len];
        }

        if (buffer.len < payload_len + noise.TAG_LEN) {
            return error.BufferTooSmall;
        }

        return self.encryptInPlace(buffer, payload_len);
    }

    fn encryptInPlace(self: *Channel, buffer: []u8, payload_len: usize) ![]u8 {
        const encrypted_len = payload_len + noise.TAG_LEN;

        if (self.send_cipher) |*cipher| {
            const start_ns = std.time.nanoTimestamp();
            try cipher.encrypt(buffer[0..payload_len], buffer[0..encrypted_len]);
            const end_ns = std.time.nanoTimestamp();

            if (self.stats) |stats| {
                const delta: u64 = @intCast(end_ns - start_ns);
                stats.record(delta);
            }

            return buffer[0..encrypted_len];
        }

        return error.CipherUnavailable;
    }

    fn ensureLargeBuffer(self: *Channel, required_len: usize) ![]u8 {
        if (self.large_send_buffer.len < required_len) {
            if (self.large_send_buffer.len > 0) {
                self.allocator.free(self.large_send_buffer);
            }
            self.large_send_buffer = try self.allocator.alloc(u8, required_len);
        }
        return self.large_send_buffer[0..required_len];
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
    fd: posix.fd_t,
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
            const frame = try receiveFrameInto(fd, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
            try sendVersionFrame(fd, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
        },
        .client => {
            try sendVersionFrame(fd, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
            const frame = try receiveFrameInto(fd, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
        },
    }
}

fn receiveFrameInto(fd: posix.fd_t, buffer: []u8) ![]u8 {
    var header: [4]u8 = undefined;
    try common.recvAllFromFd(fd, &header);
    const frame_len = std.mem.readInt(u32, &header, .big);
    if (frame_len > buffer.len) return error.FrameTooLarge;
    const payload = buffer[0..frame_len];
    try common.recvAllFromFd(fd, payload);
    return payload;
}

fn decryptVersionFrameInto(
    cipher: *noise.TransportCipher,
    frame: []const u8,
    output: []u8,
) ![]const u8 {
    if (frame.len < noise.TAG_LEN) return error.InvalidFrame;
    const plaintext_len = frame.len - noise.TAG_LEN;
    if (plaintext_len > output.len) return error.FrameTooLarge;
    try cipher.decrypt(frame, output[0..plaintext_len]);
    return output[0..plaintext_len];
}

fn sendVersionFrame(
    fd: posix.fd_t,
    cipher: *noise.TransportCipher,
    version: []const u8,
    plain_buf: []u8,
    encrypted_buf: []u8,
) !void {
    const msg = tunnel.VersionMsg{ .version = version };
    const plain_len = try msg.encodeInto(plain_buf);

    const encrypted_len = plain_len + noise.TAG_LEN;
    if (encrypted_len > encrypted_buf.len) return error.FrameTooLarge;
    try cipher.encrypt(plain_buf[0..plain_len], encrypted_buf[0..encrypted_len]);

    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(encrypted_len), .big);
    try common.sendAllToFd(fd, &header);
    try common.sendAllToFd(fd, encrypted_buf[0..encrypted_len]);
}

fn validateVersion(allocator: std.mem.Allocator, payload: []const u8, expected: []const u8) !void {
    const msg = try tunnel.VersionMsg.decode(payload, allocator);
    defer allocator.free(msg.version);

    if (!std.mem.eql(u8, msg.version, expected)) {
        return error.VersionMismatch;
    }
}
