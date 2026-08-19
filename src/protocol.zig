const std = @import("std");

/// Maximum ciphertext/plaintext size after the frame prefix.
pub const MAX_FRAME_SIZE: u32 = 1 * 1024 * 1024;

pub const LENGTH_SIZE: usize = 4;
pub const SEQ_SIZE: usize = 8;
pub const AAD_SIZE: usize = LENGTH_SIZE + SEQ_SIZE;
pub const ENCRYPTED_PREFIX_SIZE: usize = AAD_SIZE;
pub const PLAIN_PREFIX_SIZE: usize = LENGTH_SIZE;

/// Protocol v2 encrypted frame:
///   `[u32be length][u64be seq][ciphertext || 16-byte tag]`
/// AAD is the 12-byte prefix `length || seq`.
///
/// Plaintext (`cipher = "none"`) frame:
///   `[u32be length][plaintext]`
pub const Frame = struct {
    payload: []const u8,

    /// Encode a plaintext (length-prefixed) frame.
    pub fn encode(self: Frame, buffer: []u8) !usize {
        if (self.payload.len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = PLAIN_PREFIX_SIZE + self.payload.len;
        if (buffer.len < total_size) {
            return error.BufferTooSmall;
        }

        const len: u32 = @intCast(self.payload.len);
        std.mem.writeInt(u32, buffer[0..4], len, .big);
        @memcpy(buffer[4..total_size], self.payload);
        return total_size;
    }

    /// Encode an encrypted v2 frame: length + seq + payload (already ciphertext||tag).
    pub fn encodeEncrypted(payload: []const u8, seq: u64, buffer: []u8) !usize {
        if (payload.len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = ENCRYPTED_PREFIX_SIZE + payload.len;
        if (buffer.len < total_size) {
            return error.BufferTooSmall;
        }

        const len: u32 = @intCast(payload.len);
        std.mem.writeInt(u32, buffer[0..4], len, .big);
        std.mem.writeInt(u64, buffer[4..12], seq, .big);
        @memcpy(buffer[12..total_size], payload);
        return total_size;
    }

    pub fn encodeAlloc(self: Frame, allocator: std.mem.Allocator) ![]u8 {
        if (self.payload.len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = PLAIN_PREFIX_SIZE + self.payload.len;
        const buffer = try allocator.alloc(u8, total_size);
        errdefer allocator.free(buffer);
        _ = try self.encode(buffer);
        return buffer;
    }
};

pub fn makeAad(length: u32, seq: u64) [AAD_SIZE]u8 {
    var aad: [AAD_SIZE]u8 = undefined;
    std.mem.writeInt(u32, aad[0..4], length, .big);
    std.mem.writeInt(u64, aad[4..12], seq, .big);
    return aad;
}

/// One decoded frame. `payload` borrows the decoder buffer.
pub const WireFrame = struct {
    seq: u64,
    payload: []u8,
    aad: [AAD_SIZE]u8,
    encrypted: bool,
};

/// FrameDecoder handles buffered decoding of frames.
/// Accumulates bytes until a complete frame is available.
/// Uses offset tracking instead of copying for O(1) decode performance.
pub const FrameDecoder = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    read_pos: usize,
    write_pos: usize,

    const BUFFER_SIZE = 1024 * 1024;

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!FrameDecoder {
        const buffer = try allocator.alloc(u8, BUFFER_SIZE);
        return FrameDecoder{
            .allocator = allocator,
            .buffer = buffer,
            .read_pos = 0,
            .write_pos = 0,
        };
    }

    pub fn deinit(self: *FrameDecoder) void {
        if (self.buffer.len > 0) {
            self.allocator.free(self.buffer);
        }
    }

    /// Feed data into the decoder by copying it into the internal buffer.
    ///
    /// On the recv hot path prefer `pendingTail` + `commitWrite` instead — they
    /// let the caller `read(2)` directly into the decoder's buffer, eliminating
    /// this memcpy. `feed` remains for callers that already have an owned
    /// buffer (tests, the version-exchange path).
    pub fn feed(self: *FrameDecoder, data: []const u8) !void {
        const dst = self.pendingTail();
        if (data.len > dst.len) return error.BufferFull;
        @memcpy(dst[0..data.len], data);
        self.commitWrite(data.len);
    }

    /// Return a writable slice into the decoder's internal buffer where new
    /// bytes should be deposited (e.g. by `posix.read(fd, slice)`). Compacts
    /// the buffer if `read_pos > 0` so the maximum contiguous tail is
    /// available. Caller must follow with `commitWrite(n_bytes_written)`.
    pub fn pendingTail(self: *FrameDecoder) []u8 {
        if (self.write_pos == self.read_pos) {
            self.read_pos = 0;
            self.write_pos = 0;
        } else if (self.read_pos > 0) {
            self.compact();
        }
        return self.buffer[self.write_pos..];
    }

    pub fn commitWrite(self: *FrameDecoder, n: usize) void {
        std.debug.assert(self.write_pos + n <= self.buffer.len);
        self.write_pos += n;
    }

    /// Decode the next plaintext frame. Tests and the `cipher=none` path.
    pub fn decode(self: *FrameDecoder) !?[]const u8 {
        const frame = try self.decodeMut(false) orelse return null;
        return frame.payload;
    }

    /// Decode the next frame. Encrypted frames consume an extra 8-byte seq
    /// between the length prefix and the ciphertext.
    pub fn decodeMut(self: *FrameDecoder, encrypted: bool) !?WireFrame {
        const available = self.write_pos - self.read_pos;
        if (available < LENGTH_SIZE) {
            return null;
        }

        const len = std.mem.readInt(u32, self.buffer[self.read_pos..][0..4], .big);
        if (len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const prefix: usize = if (encrypted) ENCRYPTED_PREFIX_SIZE else PLAIN_PREFIX_SIZE;
        const total_size = prefix + len;
        if (available < total_size) {
            return null;
        }

        var aad: [AAD_SIZE]u8 = undefined;
        var seq: u64 = 0;
        if (encrypted) {
            @memcpy(&aad, self.buffer[self.read_pos..][0..AAD_SIZE]);
            seq = std.mem.readInt(u64, self.buffer[self.read_pos + 4 ..][0..8], .big);
        }

        const payload = self.buffer[self.read_pos + prefix ..][0..len];
        self.read_pos += total_size;

        return WireFrame{
            .seq = seq,
            .payload = payload,
            .aad = aad,
            .encrypted = encrypted,
        };
    }

    fn compact(self: *FrameDecoder) void {
        const available = self.write_pos - self.read_pos;

        if (available == 0) {
            self.read_pos = 0;
            self.write_pos = 0;
            return;
        }

        if (self.read_pos > 0) {
            const remaining = self.buffer[self.read_pos..self.write_pos];
            std.mem.copyForwards(u8, self.buffer[0..remaining.len], remaining);
            self.read_pos = 0;
            self.write_pos = available;
        }
    }

    pub fn reset(self: *FrameDecoder) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }
};

test "encode small frame" {
    const payload = "hello";
    const frame = Frame{ .payload = payload };

    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    try std.testing.expectEqual(@as(usize, 9), size);
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, buffer[0..4], .big));
    try std.testing.expectEqualSlices(u8, payload, buffer[4..9]);
}

test "encode empty frame" {
    const frame = Frame{ .payload = "" };

    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    try std.testing.expectEqual(@as(usize, 4), size);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, buffer[0..4], .big));
}

test "encode frame too large" {
    const allocator = std.testing.allocator;

    const large_payload = try allocator.alloc(u8, MAX_FRAME_SIZE + 1);
    defer allocator.free(large_payload);

    const frame = Frame{ .payload = large_payload };

    var buffer: [1024]u8 = undefined;
    try std.testing.expectError(error.FrameTooLarge, frame.encode(&buffer));
}

test "encode buffer too small" {
    const payload = "hello world";
    const frame = Frame{ .payload = payload };

    var buffer: [10]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, frame.encode(&buffer));
}

test "decode single frame" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload = "test message";
    const frame = Frame{ .payload = payload };
    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    try decoder.feed(buffer[0..size]);

    const decoded = try decoder.decode();
    try std.testing.expect(decoded != null);
    try std.testing.expectEqualSlices(u8, payload, decoded.?);
}

test "decode partial frame" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload = "test message";
    const frame = Frame{ .payload = payload };
    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    try decoder.feed(buffer[0..5]);

    const decoded1 = try decoder.decode();
    try std.testing.expect(decoded1 == null);

    try decoder.feed(buffer[5..size]);

    const decoded2 = try decoder.decode();
    try std.testing.expect(decoded2 != null);
    try std.testing.expectEqualSlices(u8, payload, decoded2.?);
}

test "decode multiple frames" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload1 = "first";
    const payload2 = "second message";

    const frame1 = Frame{ .payload = payload1 };
    const frame2 = Frame{ .payload = payload2 };

    var buffer: [1024]u8 = undefined;
    const size1 = try frame1.encode(buffer[0..]);
    const size2 = try frame2.encode(buffer[size1..]);

    try decoder.feed(buffer[0..(size1 + size2)]);

    const decoded1 = try decoder.decode();
    try std.testing.expect(decoded1 != null);
    try std.testing.expectEqualSlices(u8, payload1, decoded1.?);

    const decoded2 = try decoder.decode();
    try std.testing.expect(decoded2 != null);
    try std.testing.expectEqualSlices(u8, payload2, decoded2.?);

    const decoded3 = try decoder.decode();
    try std.testing.expect(decoded3 == null);
}

test "decode frame too large" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    var buffer: [4]u8 = undefined;
    std.mem.writeInt(u32, &buffer, MAX_FRAME_SIZE + 1, .big);

    try decoder.feed(&buffer);

    try std.testing.expectError(error.FrameTooLarge, decoder.decode());
}

test "encodeAlloc" {
    const allocator = std.testing.allocator;

    const payload = "allocated frame";
    const frame = Frame{ .payload = payload };

    const encoded = try frame.encodeAlloc(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 4 + payload.len), encoded.len);
    try std.testing.expectEqual(@as(u32, payload.len), std.mem.readInt(u32, encoded[0..4], .big));
    try std.testing.expectEqualSlices(u8, payload, encoded[4..]);
}

test "pendingTail/commitWrite path produces same frames as feed" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload1 = "first payload";
    const payload2 = "second longer payload";
    var encoded: [128]u8 = undefined;
    const len1 = try (Frame{ .payload = payload1 }).encode(encoded[0..]);
    const len2 = try (Frame{ .payload = payload2 }).encode(encoded[len1..]);
    const total = len1 + len2;

    {
        const dst1 = decoder.pendingTail();
        try std.testing.expect(dst1.len >= 5);
        @memcpy(dst1[0..5], encoded[0..5]);
        decoder.commitWrite(5);
    }
    {
        const dst2 = decoder.pendingTail();
        try std.testing.expect(dst2.len >= total - 5);
        @memcpy(dst2[0 .. total - 5], encoded[5..total]);
        decoder.commitWrite(total - 5);
    }

    const decoded1 = try decoder.decode();
    try std.testing.expect(decoded1 != null);
    try std.testing.expectEqualSlices(u8, payload1, decoded1.?);

    const decoded2 = try decoder.decode();
    try std.testing.expect(decoded2 != null);
    try std.testing.expectEqualSlices(u8, payload2, decoded2.?);

    try std.testing.expectEqual(@as(?[]const u8, null), try decoder.decode());
}

test "pendingTail compacts when read_pos > 0" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload = "abc";
    var encoded: [16]u8 = undefined;
    const len = try (Frame{ .payload = payload }).encode(&encoded);

    try decoder.feed(encoded[0..len]);
    _ = try decoder.decode();

    const dst = decoder.pendingTail();
    try std.testing.expectEqual(decoder.buffer.len, dst.len);
}

test "v2 encrypted frame encode/decode preserves seq and AAD" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const ciphertext = "ciphertext-and-tag!";
    const seq: u64 = 0x0102030405060708;
    var buffer: [128]u8 = undefined;
    const size = try Frame.encodeEncrypted(ciphertext, seq, &buffer);

    try std.testing.expectEqual(@as(usize, 12 + ciphertext.len), size);
    try std.testing.expectEqual(@as(u32, ciphertext.len), std.mem.readInt(u32, buffer[0..4], .big));
    try std.testing.expectEqual(seq, std.mem.readInt(u64, buffer[4..12], .big));

    try decoder.feed(buffer[0..size]);
    const frame = try decoder.decodeMut(true);
    try std.testing.expect(frame != null);
    try std.testing.expectEqual(seq, frame.?.seq);
    try std.testing.expectEqualSlices(u8, ciphertext, frame.?.payload);
    try std.testing.expectEqualSlices(u8, buffer[0..12], &frame.?.aad);
}

test "v2 encrypted decode waits for seq bytes" {
    const allocator = std.testing.allocator;
    var decoder = try FrameDecoder.init(allocator);
    defer decoder.deinit();

    const ciphertext = "abcd";
    var buffer: [32]u8 = undefined;
    const size = try Frame.encodeEncrypted(ciphertext, 7, &buffer);

    try decoder.feed(buffer[0..8]); // length + first 4 of seq
    try std.testing.expectEqual(@as(?WireFrame, null), try decoder.decodeMut(true));

    try decoder.feed(buffer[8..size]);
    const frame = try decoder.decodeMut(true);
    try std.testing.expect(frame != null);
    try std.testing.expectEqual(@as(u64, 7), frame.?.seq);
    try std.testing.expectEqualSlices(u8, ciphertext, frame.?.payload);
}
