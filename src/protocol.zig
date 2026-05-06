const std = @import("std");

/// Maximum frame size: 1 MB (reduced from 16MB to save memory - frames never exceed 64KB in practice)
pub const MAX_FRAME_SIZE: u32 = 1 * 1024 * 1024;

/// Frame represents a length-prefixed message.
/// Wire format: [4-byte length (big-endian)][payload]
pub const Frame = struct {
    payload: []const u8,

    /// Encode a frame into the provided buffer.
    /// Returns the total bytes written (4 + payload.len).
    /// Buffer must be at least 4 + payload.len bytes.
    pub fn encode(self: Frame, buffer: []u8) !usize {
        if (self.payload.len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = 4 + self.payload.len;
        if (buffer.len < total_size) {
            return error.BufferTooSmall;
        }

        // Write length as big-endian u32
        const len: u32 = @intCast(self.payload.len);
        std.mem.writeInt(u32, buffer[0..4], len, .big);

        // Copy payload
        @memcpy(buffer[4..total_size], self.payload);

        return total_size;
    }

    /// Allocate and encode a frame.
    /// Caller owns the returned memory.
    pub fn encodeAlloc(self: Frame, allocator: std.mem.Allocator) ![]u8 {
        if (self.payload.len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = 4 + self.payload.len;
        const buffer = try allocator.alloc(u8, total_size);
        errdefer allocator.free(buffer);

        _ = try self.encode(buffer);
        return buffer;
    }
};

/// FrameDecoder handles buffered decoding of frames.
/// Accumulates bytes until a complete frame is available.
/// Uses offset tracking instead of copying for O(1) decode performance.
pub const FrameDecoder = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    read_pos: usize,
    write_pos: usize,

    const BUFFER_SIZE = 1024 * 1024; // 1MB buffer per decoder

    pub fn init(allocator: std.mem.Allocator) FrameDecoder {
        // Allocate buffer, return error if allocation fails (handled by caller)
        const buffer = allocator.alloc(u8, BUFFER_SIZE) catch {
            // Return empty decoder on allocation failure
            return FrameDecoder{
                .allocator = allocator,
                .buffer = &[_]u8{},
                .read_pos = 0,
                .write_pos = 0,
            };
        };
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
    ///
    /// Returns an empty slice if the buffer is full of undecoded frames; the
    /// caller should drain `decode()` first in that case.
    pub fn pendingTail(self: *FrameDecoder) []u8 {
        if (self.write_pos == self.read_pos) {
            // Active region is empty — fast reset to base.
            self.read_pos = 0;
            self.write_pos = 0;
        } else if (self.read_pos > 0) {
            self.compact();
        }
        return self.buffer[self.write_pos..];
    }

    /// Advance `write_pos` by `n` bytes after caller-side write into the
    /// slice returned by `pendingTail`.
    pub fn commitWrite(self: *FrameDecoder, n: usize) void {
        std.debug.assert(self.write_pos + n <= self.buffer.len);
        self.write_pos += n;
    }

    /// Try to decode the next frame.
    /// Returns null if not enough data is available yet.
    /// The returned slice borrows the decoder buffer and stays valid
    /// until the next call to `feed` or `reset`.
    pub fn decode(self: *FrameDecoder) !?[]const u8 {
        const available = self.write_pos - self.read_pos;

        // Need at least 4 bytes for length header
        if (available < 4) {
            return null;
        }

        // Read the length
        const len = std.mem.readInt(u32, self.buffer[self.read_pos..][0..4], .big);

        // Validate frame size
        if (len > MAX_FRAME_SIZE) {
            return error.FrameTooLarge;
        }

        const total_size = 4 + len;

        // Do we have the complete frame?
        if (available < total_size) {
            return null; // Not yet
        }

        // Extract the payload (skip the 4-byte length prefix)
        const payload = self.buffer[self.read_pos + 4 ..][0..len];

        // Advance read position (O(1) operation!)
        self.read_pos += total_size;

        return payload;
    }

    /// Compact the buffer by moving unread data to the beginning.
    /// Only called when we need more space.
    fn compact(self: *FrameDecoder) void {
        const available = self.write_pos - self.read_pos;

        if (available == 0) {
            // Empty, just reset positions
            self.read_pos = 0;
            self.write_pos = 0;
            return;
        }

        // Move remaining unread data to beginning
        if (self.read_pos > 0) {
            const remaining = self.buffer[self.read_pos..self.write_pos];
            std.mem.copyForwards(u8, self.buffer[0..remaining.len], remaining);
            self.read_pos = 0;
            self.write_pos = available;
        }
    }

    /// Reset the decoder, clearing all buffered data.
    pub fn reset(self: *FrameDecoder) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }
};

// Tests
test "encode small frame" {
    const payload = "hello";
    const frame = Frame{ .payload = payload };

    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    try std.testing.expectEqual(@as(usize, 9), size); // 4 + 5
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

    // Create a payload that's too large
    const large_payload = try allocator.alloc(u8, MAX_FRAME_SIZE + 1);
    defer allocator.free(large_payload);

    const frame = Frame{ .payload = large_payload };

    var buffer: [1024]u8 = undefined;
    try std.testing.expectError(error.FrameTooLarge, frame.encode(&buffer));
}

test "encode buffer too small" {
    const payload = "hello world";
    const frame = Frame{ .payload = payload };

    var buffer: [10]u8 = undefined; // Too small
    try std.testing.expectError(error.BufferTooSmall, frame.encode(&buffer));
}

test "decode single frame" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    // Encode a frame
    const payload = "test message";
    const frame = Frame{ .payload = payload };
    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    // Feed it to decoder
    try decoder.feed(buffer[0..size]);

    // Decode
    const decoded = try decoder.decode();
    try std.testing.expect(decoded != null);

    try std.testing.expectEqualSlices(u8, payload, decoded.?);
}

test "decode partial frame" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    // Encode a frame
    const payload = "test message";
    const frame = Frame{ .payload = payload };
    var buffer: [1024]u8 = undefined;
    const size = try frame.encode(&buffer);

    // Feed only first 5 bytes
    try decoder.feed(buffer[0..5]);

    // Should not decode yet
    const decoded1 = try decoder.decode();
    try std.testing.expect(decoded1 == null);

    // Feed the rest
    try decoder.feed(buffer[5..size]);

    // Now it should decode
    const decoded2 = try decoder.decode();
    try std.testing.expect(decoded2 != null);

    try std.testing.expectEqualSlices(u8, payload, decoded2.?);
}

test "decode multiple frames" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    // Encode two frames
    const payload1 = "first";
    const payload2 = "second message";

    const frame1 = Frame{ .payload = payload1 };
    const frame2 = Frame{ .payload = payload2 };

    var buffer: [1024]u8 = undefined;
    const size1 = try frame1.encode(buffer[0..]);
    const size2 = try frame2.encode(buffer[size1..]);

    // Feed both frames at once
    try decoder.feed(buffer[0..(size1 + size2)]);

    // Decode first frame
    const decoded1 = try decoder.decode();
    try std.testing.expect(decoded1 != null);
    try std.testing.expectEqualSlices(u8, payload1, decoded1.?);

    // Decode second frame
    const decoded2 = try decoder.decode();
    try std.testing.expect(decoded2 != null);
    try std.testing.expectEqualSlices(u8, payload2, decoded2.?);

    // No more frames
    const decoded3 = try decoder.decode();
    try std.testing.expect(decoded3 == null);
}

test "decode frame too large" {
    const allocator = std.testing.allocator;
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    // Create a fake header claiming an oversized frame
    var buffer: [4]u8 = undefined;
    std.mem.writeInt(u32, &buffer, MAX_FRAME_SIZE + 1, .big);

    try decoder.feed(&buffer);

    // Should error when trying to decode
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
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload1 = "first payload";
    const payload2 = "second longer payload";
    var encoded: [128]u8 = undefined;
    const len1 = try (Frame{ .payload = payload1 }).encode(encoded[0..]);
    const len2 = try (Frame{ .payload = payload2 }).encode(encoded[len1..]);
    const total = len1 + len2;

    // Drop bytes into the decoder via the zero-copy API in two halves to
    // exercise compaction/partial-frame state.
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
    var decoder = FrameDecoder.init(allocator);
    defer decoder.deinit();

    const payload = "abc";
    var encoded: [16]u8 = undefined;
    const len = try (Frame{ .payload = payload }).encode(&encoded);

    try decoder.feed(encoded[0..len]);
    _ = try decoder.decode(); // advances read_pos

    // After decode, read_pos > 0; pendingTail should compact and return
    // the full buffer width minus 0 (since active region is empty post-drain).
    const dst = decoder.pendingTail();
    try std.testing.expectEqual(decoder.buffer.len, dst.len);
}
