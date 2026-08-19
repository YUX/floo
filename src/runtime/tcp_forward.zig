const std = @import("std");
const posix = std.posix;
const tunnel = @import("../tunnel.zig");
const noise = @import("../noise.zig");
const protocol = @import("../protocol.zig");
const transport = @import("../transport/channel.zig");

/// Shared DATA-header + queueDataInPlace path for both roles.
/// One side-read per poll wakeup; the poll loop flushes queued frames
/// in one writev after the side-event sweep.
/// Returns bytes read. `error.StreamClosed` on side-socket EOF/RST — not
/// `error.ConnectionClosed`, which `queueDataInPlace` uses for a dead tunnel.
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

    const room = frame_buffer.len - header_len - noise.TAG_LEN;
    const max_payload = @min(protocol.MAX_DATA_PAYLOAD, room);
    const max_read = @min(io_batch, max_payload);
    const recv_slice = frame_buffer[header_len..][0..max_read];
    const n = posix.read(fd, recv_slice) catch |err| switch (err) {
        error.WouldBlock => return 0,
        // Per-stream close. Must not become handleSendFailure — that
        // tears down every multiplexed stream (iperf3 control included).
        error.ConnectionResetByPeer, error.SocketUnconnected => return error.StreamClosed,
        else => return err,
    };
    if (n == 0) return error.StreamClosed;

    tunnel.writeStreamHeader(frame_buffer, .data, service_id, stream_id);
    const payload_len = header_len + n;
    if (channel.isEncrypted()) {
        try channel.queueDataInPlace(frame_buffer[0 .. payload_len + noise.TAG_LEN], payload_len);
    } else {
        try channel.queueDataInPlace(frame_buffer[0..payload_len], payload_len);
    }
    return n;
}

pub fn pollErrorMask() i16 {
    const extra: i16 = if (@hasDecl(posix.POLL, "NVAL")) posix.POLL.NVAL else 0;
    return posix.POLL.HUP | posix.POLL.ERR | extra;
}
