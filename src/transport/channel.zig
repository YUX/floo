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
///
/// `.monotonic` ordering is correct for these write-only counters: no
/// other thread synchronizes through them.  `diagnostics.flushEncryptStats`
/// reads them once at process exit, after all writers have joined or
/// been signalled to stop.  On ARM (M-series) this avoids the `dmb ish`
/// per fetchAdd that an `.acq_rel` order would emit.
pub const EncryptionStats = struct {
    total_ns: *std.atomic.Value(u64),
    calls: *std.atomic.Value(u64),

    pub fn record(self: EncryptionStats, delta: u64) void {
        _ = self.total_ns.fetchAdd(delta, .monotonic);
        _ = self.calls.fetchAdd(1, .monotonic);
    }
};

/// Optional throughput counters (bytes in/out) shared by caller.
/// See `EncryptionStats` for the ordering rationale.
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

/// Parameters required to establish a tunnel transport.
///
/// The caller owns `stream`, `reader`, and `writer` (and the buffers backing
/// reader/writer). The Channel borrows them for its lifetime; on close the
/// caller is responsible for closing the underlying stream.
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
/// Wraps a Stream + buffered Reader/Writer pair with Noise XX handshake
/// and AEAD framing. The send path serializes encryption + write under a
/// mutex; the receive path is single-threaded by convention (the caller's
/// poll loop).
pub const Channel = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    reader: *Io.Reader,
    writer: *Io.Writer,
    encryption_enabled: bool,
    send_cipher: ?noise.TransportCipher,
    recv_cipher: ?noise.TransportCipher,
    control_buffer: []u8,
    large_send_buffer: []u8,
    /// common.HotMutex (os_unfair_lock on Darwin, raw futex on Linux). The
    /// Io.Mutex fast path is the same single CAS, but its slow path goes
    /// through a vtable so a fiber can suspend on contention; we have no
    /// fibers, only OS threads, so the vtable hop is dead weight. CHANGELOG
    /// 0.2.0 cited this as the remaining headroom vs the 0.1.5 baseline.
    send_mutex: common.HotMutex,
    stats: ?EncryptionStats,
    throughput: ?ThroughputStats,

    pub fn init(params: ChannelInit) !Channel {
        var control_buffer: []u8 = &[_]u8{};
        const large_send_buffer: []u8 = &[_]u8{};
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
                error.MissingPsk => return err,
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

            control_buffer = try params.allocator.alloc(u8, common.CONTROL_MSG_BUFFER_SIZE + noise.TAG_LEN);
        } else {
            // S-1: cipher="none" path.  Encryption is off, but mutual PSK
            // authentication is NOT.  Without this, anyone reachable at the
            // server's port could speak the protocol and per-service tokens
            // would leak in cleartext.  We run a small nonce-exchange + HMAC
            // proof-of-PSK so the connection drops cleanly when either side
            // doesn't know the PSK.
            //
            // Frame integrity / confidentiality remain absent — that's the
            // *documented* meaning of cipher=none.  This change only fixes
            // the silent-auth-bypass aspect of the prior behaviour.
            var handshake_timer_start: i128 = 0;
            if (params.handshake_metrics) |_| {
                handshake_timer_start = common.nanoTimestamp();
            }
            try noise.plaintextPskHandshake(
                params.io,
                params.reader,
                params.writer,
                params.role == .client,
                params.psk,
            );
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
            .control_buffer = control_buffer,
            .large_send_buffer = large_send_buffer,
            .send_mutex = .{},
            .stats = params.stats,
            .throughput = params.throughput,
        };
    }

    pub fn deinit(self: *Channel) void {
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
    ///
    /// Hot path: bypasses self.writer's Io.Writer interface and writes directly
    /// via posix writev so we get one syscall per frame (matches the original
    /// pre-migration writev semantics; the buffered Stream.Writer was costing
    /// roughly 3x throughput due to per-call vtable dispatch + flush overhead).
    pub fn sendCopy(self: *Channel, payload: []const u8) !void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();

        const fd = self.stream.socket.handle;

        if (!self.encryption_enabled) {
            try common.writeFrameDirect(fd, payload);
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
        try common.writeFrameDirect(fd, encrypted_slice);
        self.recordTx(payload.len);
    }

    /// Encrypt (when necessary) and send a mutable payload in-place.
    /// `buffer.len` must include enough capacity for the ciphertext/tag.
    ///
    /// Hot path: same direct-writev rationale as sendCopy.
    pub fn sendDataInPlace(self: *Channel, buffer: []u8, payload_len: usize) !void {
        self.send_mutex.lock();
        defer self.send_mutex.unlock();

        const slice = try self.prepareSendSlice(buffer, payload_len);
        try common.writeFrameDirect(self.stream.socket.handle, slice);
        self.recordTx(payload_len);
    }

    /// Decrypt frame payload IN PLACE. The caller-supplied `encrypted_payload`
    /// slice must point into a mutable backing buffer (e.g. the FrameDecoder's
    /// internal buffer via `decodeMut`). On return:
    ///   - Bytes [0..plaintext_len] of the slice contain plaintext.
    ///   - Bytes [plaintext_len..] are stale (the AEAD tag, now garbage).
    /// Returns the plaintext slice limited to `plaintext_len`.
    ///
    /// The previous implementation maintained a per-channel `decrypt_buffer`
    /// of MAX_FRAME_SIZE and did one memcpy via `cipher.decrypt(ct, decrypt_buffer)`
    /// on every received frame. With std.crypto AEADs supporting in-place
    /// decryption (verified by the regression test in noise.zig), that copy
    /// is redundant — we save 1 MB of resident memory per tunnel and one
    /// full memcpy per byte received.
    pub fn decryptFrameInPlace(self: *Channel, encrypted_payload: []u8) ![]const u8 {
        if (!self.encryption_enabled) {
            return encrypted_payload;
        }

        if (encrypted_payload.len < noise.TAG_LEN) {
            return error.InvalidFrame;
        }

        const plaintext_len = encrypted_payload.len - noise.TAG_LEN;

        if (self.recv_cipher) |*cipher| {
            try cipher.decrypt(encrypted_payload, encrypted_payload[0..plaintext_len]);
        } else {
            return error.CipherUnavailable;
        }
        self.recordRx(plaintext_len);
        return encrypted_payload[0..plaintext_len];
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
            // Hot path: only sample the clock when stats are actually wired
            // up (debug/diagnostics builds). On the steady-state data path
            // this used to do two clock_gettime() syscalls per frame even
            // when the recorded value was discarded.
            if (self.stats) |stats| {
                const start_ns = common.nanoTimestamp();
                try cipher.encrypt(buffer[0..payload_len], buffer[0..encrypted_len]);
                const end_ns = common.nanoTimestamp();
                const delta: u64 = @intCast(end_ns - start_ns);
                stats.record(delta);
            } else {
                try cipher.encrypt(buffer[0..payload_len], buffer[0..encrypted_len]);
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
            const frame = try receiveFrameInto(reader, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
            try sendVersionFrame(writer, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
        },
        .client => {
            try sendVersionFrame(writer, send_cipher, local_version, &plaintext_buf, &encrypted_buf);
            const frame = try receiveFrameInto(reader, &encrypted_buf);
            const plaintext = try decryptVersionFrameInto(recv_cipher, frame, &plaintext_buf);
            try validateVersion(allocator, plaintext, local_version);
        },
    }
}

fn receiveFrameInto(reader: *Io.Reader, buffer: []u8) ![]u8 {
    var header: [4]u8 = undefined;
    try common.recvAll(reader, &header);
    const frame_len = std.mem.readInt(u32, &header, .big);
    if (frame_len > buffer.len) return error.FrameTooLarge;
    const payload = buffer[0..frame_len];
    try common.recvAll(reader, payload);
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
    try cipher.encrypt(plain_buf[0..plain_len], encrypted_buf[0..encrypted_len]);

    try common.writeFrame(writer, encrypted_buf[0..encrypted_len]);
    try writer.flush();
}

fn validateVersion(allocator: std.mem.Allocator, payload: []const u8, expected: []const u8) !void {
    const msg = try tunnel.VersionMsg.decode(payload, allocator);
    defer allocator.free(msg.version);

    if (!std.mem.eql(u8, msg.version, expected)) {
        return error.VersionMismatch;
    }
}
