const std = @import("std");
const posix = std.posix;
const tunnel = @import("../tunnel.zig");
const noise = @import("../noise.zig");
const transport = @import("../transport/channel.zig");

/// Shared DATA-header + sendDataInPlace path for both roles.
/// Returns bytes read. `error.ConnectionClosed` on EOF.
pub fn forwardSideData(
    fd: posix.fd_t,
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
    frame_buffer: []u8,
    channel: *transport.Channel,
    io_batch: usize,
) !usize {
    const header_len = tunnel.DATA_HEADER_SIZE;
    if (frame_buffer.len <= header_len + noise.TAG_LEN) return error.BufferTooSmall;

    const max_read = @min(io_batch, frame_buffer.len - header_len - noise.TAG_LEN);
    const recv_slice = frame_buffer[header_len..][0..max_read];
    const n = posix.read(fd, recv_slice) catch |err| switch (err) {
        error.WouldBlock => return 0,
        else => return err,
    };
    if (n == 0) return error.ConnectionClosed;

    tunnel.writeStreamHeader(frame_buffer, .data, service_id, stream_id);
    const payload_len = header_len + n;
    if (channel.isEncrypted()) {
        try channel.sendDataInPlace(frame_buffer[0 .. payload_len + noise.TAG_LEN], payload_len);
    } else {
        try channel.sendDataInPlace(frame_buffer[0..payload_len], payload_len);
    }
    return n;
}

pub fn pollErrorMask() i16 {
    const extra: i16 = if (@hasDecl(posix.POLL, "NVAL")) posix.POLL.NVAL else 0;
    return posix.POLL.HUP | posix.POLL.ERR | extra;
}
