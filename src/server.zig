const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const build_options = @import("build_options");
const protocol = @import("protocol.zig");
const tunnel = @import("tunnel.zig");
const config = @import("config.zig");
const noise = @import("noise.zig");
const udp_server = @import("udp_server.zig");
const diagnostics = @import("diagnostics.zig");
const common = @import("common.zig");
const transport = @import("transport/channel.zig");
const c = std.c;

const tracePrint = common.tracePrint;
const tcpOptionsFromSettings = common.tcpOptionsFromSettings;
const tuneSocketBuffers = common.tuneSocketBuffers;
const applyTcpOptions = common.applyTcpOptions;
const formatAddress = common.formatAddress;
const resolveHostPort = common.resolveHostPort;

const CheckStatus = diagnostics.CheckStatus;

const DEFAULT_CONFIG_PATH = "floos.toml";
const enable_stream_trace = false;
const enable_tunnel_trace = false;

var global_allocator: std.mem.Allocator = undefined;
var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var config_path_global: []const u8 = undefined; // Store config path for reload
var encrypt_total_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var encrypt_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_tx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_rx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var flush_stats_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var sighup_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var signal_pipe_read_fd: std.atomic.Value(posix.fd_t) = std.atomic.Value(posix.fd_t).init(-1);
var signal_pipe_write_fd: std.atomic.Value(posix.fd_t) = std.atomic.Value(posix.fd_t).init(-1);
var cpu_assigner: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var cached_cpu_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

fn setupSignalPipe() !void {
    if (builtin.target.os.tag == .windows) return;
    if (signal_pipe_read_fd.load(.acquire) != -1) return;

    const fds = try posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    signal_pipe_read_fd.store(fds[0], .release);
    signal_pipe_write_fd.store(fds[1], .release);
}

fn cleanupSignalPipe() void {
    if (builtin.target.os.tag == .windows) return;

    const rd = signal_pipe_read_fd.swap(-1, .acq_rel);
    if (rd != -1) {
        posix.close(rd);
    }

    const wr = signal_pipe_write_fd.swap(-1, .acq_rel);
    if (wr != -1) {
        posix.close(wr);
    }
}

fn drainSignalPipe() void {
    const rd = signal_pipe_read_fd.load(.acquire);
    if (rd == -1) return;

    var buf: [32]u8 = undefined;
    while (true) {
        const result = posix.read(rd, buf[0..]) catch |err| switch (err) {
            error.WouldBlock, error.BrokenPipe => return,
            else => return,
        };
        if (result == 0) return;
    }
}

fn notifySignalPipe(sig: c_int) void {
    const wr = signal_pipe_write_fd.load(.acquire);
    if (wr == -1) return;
    var byte = [_]u8{@intCast(@as(u8, @intCast(sig & 0xFF)))};
    _ = posix.write(wr, &byte) catch {};
}

fn cpuCountCached() usize {
    const cached = cached_cpu_count.load(.acquire);
    if (cached != 0) return cached;
    const detected = std.Thread.getCpuCount() catch 1;
    cached_cpu_count.store(detected, .release);
    return detected;
}

fn nextCpuIndex() usize {
    const count = cpuCountCached();
    const idx = cpu_assigner.fetchAdd(1, .acq_rel);
    return idx % @max(count, 1);
}

fn applyThreadAffinity(index_opt: ?usize) void {
    if (index_opt == null) return;
    if (builtin.target.os.tag == .linux) {
        setThreadAffinityLinux(index_opt.?);
    }
}

fn setThreadAffinityLinux(cpu_index: usize) void {
    if (builtin.target.os.tag != .linux) return;
    const linux = std.os.linux;
    var mask: linux.cpu_set_t = undefined;
    linux.CPU_ZERO(&mask);
    const limited = cpu_index % linux.CPU_SETSIZE;
    linux.CPU_SET(@intCast(@as(c_uint, @intCast(limited))), &mask);
    _ = linux.sched_setaffinity(0, @sizeOf(linux.cpu_set_t), &mask) catch {};
}

const CliMode = enum { run, help, version, doctor, ping };

const CliOptions = struct {
    mode: CliMode = .run,
    config_path: []const u8 = DEFAULT_CONFIG_PATH,
    config_path_set: bool = false,
    port_override: ?u16 = null,
};

const ParseError = error{ UnknownFlag, MissingValue, ConflictingMode, TooManyPositionals, InvalidValue };

const ParseContext = struct {
    arg: []const u8 = "",
};

const SERVER_USAGE =
    \\Usage: floos [options] [config_path]
    \\Options:
    \\  -h, --help                 Show this help message and exit
    \\  -V, --version              Show version information and exit
    \\      --doctor              Run diagnostics for the server configuration and exit
    \\      --ping                Probe configured target services and exit
    \\  -p, --port PORT           Override listening port
    \\  config_path               Optional path to floos.toml (defaults to ./floos.toml)
    \\Examples:
    \\  floos --doctor
    \\  floos -p 9000 --ping configs/floos.toml
    \\
;

fn printServerUsage() void {
    std.debug.print("{s}", .{SERVER_USAGE});
}

fn setMode(opts: *CliOptions, new_mode: CliMode, ctx: *ParseContext, arg: []const u8) ParseError!void {
    if (opts.mode != .run and opts.mode != new_mode) {
        ctx.arg = arg;
        return ParseError.ConflictingMode;
    }
    opts.mode = new_mode;
}

fn parseServerArgs(args_list: [][:0]u8, ctx: *ParseContext) ParseError!CliOptions {
    var opts = CliOptions{};
    var idx: usize = 1;
    while (idx < args_list.len) : (idx += 1) {
        const arg = std.mem.sliceTo(args_list[idx], 0);
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try setMode(&opts, .help, ctx, arg);
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) {
            try setMode(&opts, .version, ctx, arg);
        } else if (std.mem.eql(u8, arg, "--doctor")) {
            try setMode(&opts, .doctor, ctx, arg);
        } else if (std.mem.eql(u8, arg, "--ping")) {
            try setMode(&opts, .ping, ctx, arg);
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            if (idx + 1 >= args_list.len) {
                ctx.arg = arg;
                return ParseError.MissingValue;
            }
            idx += 1;
            const port_str = std.mem.sliceTo(args_list[idx], 0);
            const port = std.fmt.parseInt(u16, port_str, 10) catch {
                ctx.arg = arg;
                return ParseError.InvalidValue;
            };
            opts.port_override = port;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            ctx.arg = arg;
            return ParseError.UnknownFlag;
        } else {
            if (!opts.config_path_set) {
                opts.config_path = arg;
                opts.config_path_set = true;
            } else {
                ctx.arg = arg;
                return ParseError.TooManyPositionals;
            }
        }
    }
    return opts;
}

fn applyServerOverrides(cfg: *config.ServerConfig, opts: *CliOptions) void {
    if (opts.port_override) |port| {
        cfg.port = port;
    }
}

fn loadServerConfigWithOverrides(allocator: std.mem.Allocator, opts: *CliOptions) !config.ServerConfig {
    var cfg = try config.ServerConfig.loadFromFile(allocator, opts.config_path);
    errdefer cfg.deinit();
    applyServerOverrides(&cfg, opts);
    return cfg;
}

fn probeTcpTarget(host: []const u8, port: u16) !i128 {
    const addr = try resolveHostPort(host, port);
    const fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);

    const start = std.time.nanoTimestamp();
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| {
        return err;
    };
    const done = std.time.nanoTimestamp();
    posix.close(fd);
    return done - start;
}

fn runServerPing(allocator: std.mem.Allocator, opts: *CliOptions) !bool {
    var cfg = try loadServerConfigWithOverrides(allocator, opts);
    defer cfg.deinit();

    std.debug.print("Probing configured services...\n", .{});
    var had_fail = false;
    var service_iter = cfg.services.valueIterator();
    var service_count: usize = 0;
    while (service_iter.next()) |service| {
        service_count += 1;
        if (service.transport == .tcp) {
            const duration = probeTcpTarget(service.address, service.port) catch |err| {
                diagnostics.reportCheck(.fail, "Service '{s}' ({}) unreachable at {s}:{d}: {}", .{
                    service.name,
                    service.id,
                    service.address,
                    service.port,
                    err,
                });
                had_fail = true;
                continue;
            };
            const ms = @as(f64, @floatFromInt(duration)) / @as(f64, std.time.ns_per_ms);
            diagnostics.reportCheck(.ok, "Service '{s}' ({}) reachable ({s}:{d}) - connect {d:.2} ms", .{
                service.name,
                service.id,
                service.address,
                service.port,
                ms,
            });
        } else {
            _ = std.net.Address.resolveIp(service.address, service.port) catch |err| {
                diagnostics.reportCheck(.fail, "Service '{s}' ({}) UDP target {s}:{d} not resolvable: {}", .{
                    service.name,
                    service.id,
                    service.address,
                    service.port,
                    err,
                });
                had_fail = true;
                continue;
            };
            diagnostics.reportCheck(.ok, "Service '{s}' ({}) UDP target {s}:{d} resolves successfully", .{
                service.name,
                service.id,
                service.address,
                service.port,
            });
        }
    }

    if (service_count == 0) {
        diagnostics.reportCheck(.warn, "No services configured; nothing to probe", .{});
    }

    return !had_fail;
}

fn runServerDoctor(allocator: std.mem.Allocator, opts: *CliOptions) !bool {
    std.debug.print("Floo Server Doctor\n===================\n", .{});

    var config_exists = true;
    std.fs.cwd().access(opts.config_path, .{}) catch {
        config_exists = false;
    };
    if (config_exists) {
        diagnostics.reportCheck(.ok, "Config file accessible at {s}", .{opts.config_path});
    } else {
        diagnostics.reportCheck(.warn, "Config file {s} not found; defaults will be used", .{opts.config_path});
    }

    var cfg = loadServerConfigWithOverrides(allocator, opts) catch |err| {
        diagnostics.reportCheck(.fail, "Failed to load config: {}", .{err});
        return false;
    };
    defer cfg.deinit();

    var had_fail = false;
    diagnostics.reportCheck(.ok, "Configuration parsed (services: {})", .{cfg.services.count()});
    diagnostics.reportCheck(.ok, "Server version: {s}", .{build_options.version});

    const canonical_cipher = config.canonicalCipher(&cfg);
    if (std.mem.eql(u8, canonical_cipher, "none")) {
        diagnostics.reportCheck(.warn, "Encryption disabled; relying solely on tokens", .{});
    } else if (cfg.psk.len == 0) {
        diagnostics.reportCheck(.fail, "PSK is empty; clients cannot authenticate", .{});
        had_fail = true;
    } else if (std.mem.eql(u8, cfg.psk, config.DEFAULT_PSK)) {
        diagnostics.reportCheck(.warn, "Using default PSK; replace before production", .{});
    }

    var require_default_token = false;
    var svc_iter = cfg.services.valueIterator();
    while (svc_iter.next()) |service| {
        if (service.token.len == 0) {
            require_default_token = true;
            break;
        }
    }
    if ((require_default_token or cfg.services.count() == 0) and cfg.token.len == 0) {
        diagnostics.reportCheck(.warn, "Default token is empty; unauthenticated clients may connect", .{});
    } else if (cfg.token.len > 0 and std.mem.eql(u8, cfg.token, config.DEFAULT_TOKEN)) {
        diagnostics.reportCheck(.warn, "Default token uses placeholder value; update to a secret", .{});
    }

    const listen_addr = resolveHostPort(cfg.bind, cfg.port) catch |err| {
        diagnostics.reportCheck(.fail, "Invalid listen address {s}:{d}: {}", .{ cfg.bind, cfg.port, err });
        return false;
    };

    const listen_fd = posix.socket(listen_addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    if (listen_fd) |fd| {
        defer posix.close(fd);
        const reuse: c_int = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(reuse)) catch {};
        const bind_result = posix.bind(fd, &listen_addr.any, listen_addr.getOsSockLen());
        if (bind_result) |_| {
            diagnostics.reportCheck(.ok, "Bind check succeeded on {s}:{d}", .{ cfg.bind, cfg.port });
        } else |err| {
            if (err == error.AddressInUse) {
                diagnostics.reportCheck(.warn, "Port {d} already in use on {s}", .{ cfg.port, cfg.bind });
                had_fail = true;
            } else {
                diagnostics.reportCheck(.fail, "Failed to bind {s}:{d}: {}", .{ cfg.bind, cfg.port, err });
                return false;
            }
        }
    } else |err| {
        diagnostics.reportCheck(.fail, "Unable to create socket for bind check: {}", .{err});
        return false;
    }

    // Probe configured services (reuse ping logic)
    const ping_ok = try runServerPing(allocator, opts);
    if (!ping_ok) {
        had_fail = true;
    }

    if (had_fail) {
        std.debug.print("\nDiagnostics complete (with warnings/failures).\n", .{});
    } else {
        std.debug.print("\nDiagnostics complete.\n", .{});
    }
    return !had_fail;
}
/// Composite key for routing streams in multi-service mode
const StreamKey = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
};

const StreamKeyContext = struct {
    pub fn hash(_: StreamKeyContext, key: StreamKey) u64 {
        // Fast hash: combine service_id (16 bits) and stream_id (32 bits) into u64
        // This is much faster than Wyhash for such small keys
        return (@as(u64, key.service_id) << 32) | @as(u64, key.stream_id);
    }

    pub fn eql(_: StreamKeyContext, a: StreamKey, b: StreamKey) bool {
        return a.service_id == b.service_id and a.stream_id == b.stream_id;
    }
};

fn handleSignal(sig: c_int) callconv(.c) void {
    if (sig == posix.SIG.INT or sig == posix.SIG.TERM) {
        shutdown_flag.store(true, .release);
    } else if (@hasDecl(posix.SIG, "HUP") and sig == posix.SIG.HUP) {
        sighup_requested.store(true, .release);
    } else if (@hasDecl(posix.SIG, "USR1") and sig == posix.SIG.USR1) {
        flush_stats_requested.store(true, .release);
    }
    if (builtin.target.os.tag != .windows) {
        notifySignalPipe(sig);
    }
}

/// Reverse service listener - accepts connections and forwards through tunnel to client
const ReverseListener = struct {
    allocator: std.mem.Allocator,
    service: config.Service,
    listen_fd: posix.fd_t,
    thread: std.Thread,
    running: std.atomic.Value(bool),
    tunnel_conn: *TunnelConnection,
    thread_joined: std.atomic.Value(bool),

    fn create(
        allocator: std.mem.Allocator,
        service: config.Service,
        tunnel_conn: *TunnelConnection,
    ) !*ReverseListener {
        const addr = try resolveHostPort(service.address, service.port);
        const listen_fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(listen_fd);

        const reuse: c_int = 1;
        try posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(reuse));
        try posix.bind(listen_fd, &addr.any, addr.getOsSockLen());
        try posix.listen(listen_fd, common.LISTEN_BACKLOG);

        const listener = try allocator.create(ReverseListener);
        listener.* = .{
            .allocator = allocator,
            .service = service,
            .listen_fd = listen_fd,
            .thread = undefined,
            .running = std.atomic.Value(bool).init(true),
            .tunnel_conn = tunnel_conn,
            .thread_joined = std.atomic.Value(bool).init(false),
        };

        listener.thread = try std.Thread.spawn(.{
            .stack_size = common.DEFAULT_THREAD_STACK,
        }, acceptorThread, .{listener});

        std.debug.print("[REVERSE] Listening on {s}:{} for service '{s}' (id={})\n", .{
            service.address,
            service.port,
            service.name,
            service.id,
        });

        return listener;
    }

    fn acceptorThread(self: *ReverseListener) void {
        while (self.running.load(.acquire)) {
            if (!self.tunnel_conn.running.load(.acquire)) break;
            const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (err == error.Interrupted) continue;
                std.debug.print("[REVERSE] Accept error on {s}:{}: {}\n", .{ self.service.address, self.service.port, err });
                break;
            };

            std.debug.print("[REVERSE] Accepted connection on {s}:{}\n", .{ self.service.address, self.service.port });

            // Allocate stream ID
            const stream_id = self.tunnel_conn.next_stream_id.fetchAdd(1, .acq_rel);

            // Send REVERSE_CONNECT to client
            const msg = tunnel.ReverseConnectMsg{
                .service_id = self.service.id,
                .stream_id = stream_id,
            };

            var encode_buf: [64]u8 = undefined;
            const encoded_len = msg.encodeInto(&encode_buf) catch {
                std.debug.print("[REVERSE] Failed to encode REVERSE_CONNECT\n", .{});
                posix.close(client_fd);
                continue;
            };

            self.tunnel_conn.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
                std.debug.print("[REVERSE] Failed to send REVERSE_CONNECT: {}\n", .{err});
                posix.close(client_fd);
                continue;
            };

            std.debug.print("[REVERSE] Sent REVERSE_CONNECT service_id={} stream_id={}\n", .{ self.service.id, stream_id });

            // Create Stream for this connection
            const stream = Stream.create(self.allocator, self.service.id, stream_id, client_fd, self.tunnel_conn) catch |err| {
                std.debug.print("[REVERSE] Failed to create stream: {}\n", .{err});
                posix.close(client_fd);
                continue;
            };

            // Add stream to tunnel's streams map (CRITICAL for reverse routing)
            const key = StreamKey{ .service_id = self.service.id, .stream_id = stream_id };
            self.tunnel_conn.streams_mutex.lock();
            defer self.tunnel_conn.streams_mutex.unlock();

            stream.acquireRef(); // map reference
            self.tunnel_conn.streams.put(key, stream) catch |err| {
                std.debug.print("[REVERSE] Failed to register stream: {}\n", .{err});
                stream.releaseRef(); // undo map reference
                stream.stop();
                continue;
            };

            std.debug.print("[REVERSE] Stream {} registered and ready\n", .{stream_id});
        }

        std.debug.print("[REVERSE] Acceptor thread for {s}:{} exiting\n", .{ self.service.address, self.service.port });
    }

    fn stop(self: *ReverseListener) void {
        if (self.thread_joined.swap(true, .acq_rel)) return;
        self.running.store(false, .release);
        posix.shutdown(self.listen_fd, .recv) catch {};
        self.thread.join();
        posix.close(self.listen_fd);
    }

    fn destroy(self: *ReverseListener) void {
        self.allocator.destroy(self);
    }
};

fn stopAllReverseListeners(list: *std.ArrayListUnmanaged(*ReverseListener)) void {
    for (list.items) |listener| {
        listener.stop();
        listener.destroy();
    }
    list.clearRetainingCapacity();
}

/// Represents a forwarding stream (tunnel -> target)
const Stream = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
    target_fd: posix.fd_t,
    tunnel: *TunnelConnection,
    fd_closed: std.atomic.Value(bool), // Track if target_fd is closed
    ref_count: std.atomic.Value(usize),
    read_buffer: []u8,
    frame_buffer: []u8,

    fn create(allocator: std.mem.Allocator, service_id: tunnel.ServiceId, stream_id: tunnel.StreamId, target_fd: posix.fd_t, tunnel_conn: *TunnelConnection) !*Stream {
        const io_batch = tunnel_conn.cfg.advanced.io_batch_bytes;
        const read_buffer = try allocator.alloc(u8, io_batch);
        errdefer allocator.free(read_buffer);

        const header_len: usize = 7;
        const frame_capacity = header_len + io_batch + noise.TAG_LEN + 32;
        const frame_buffer = try allocator.alloc(u8, frame_capacity);
        errdefer allocator.free(frame_buffer);

        const stream = try allocator.create(Stream);
        stream.* = .{
            .service_id = service_id,
            .stream_id = stream_id,
            .target_fd = target_fd,
            .tunnel = tunnel_conn,
            .fd_closed = std.atomic.Value(bool).init(false),
            .ref_count = std.atomic.Value(usize).init(1),
            .read_buffer = read_buffer,
            .frame_buffer = frame_buffer,
        };
        return stream;
    }

    fn acquireRef(self: *Stream) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    fn releaseRef(self: *Stream) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            self.destroyInternal();
        }
    }

    fn destroyInternal(self: *Stream) void {
        self.stop();
        if (self.read_buffer.len > 0) global_allocator.free(self.read_buffer);
        if (self.frame_buffer.len > 0) global_allocator.free(self.frame_buffer);
        global_allocator.destroy(self);
    }

    fn stop(self: *Stream) void {
        if (!self.fd_closed.swap(true, .acq_rel)) {
            posix.close(self.target_fd);
        }
    }
};

/// Tunnel connection handler (one per client connection)
const TunnelConnection = struct {
    tunnel_fd: posix.fd_t,
    streams: std.HashMap(StreamKey, *Stream, StreamKeyContext, 80),
    streams_mutex: std.Thread.Mutex,
    channel: transport.Channel,
    running: std.atomic.Value(bool),

    // UDP support (only one forwarder per tunnel connection)
    udp_forwarder: ?*udp_server.UdpForwarder,
    udp_service_id: ?tunnel.ServiceId,

    // Heartbeat support
    heartbeat_interval_ms: u32, // Heartbeat interval in milliseconds (0 = disabled)
    heartbeat_thread: ?std.Thread, // Heartbeat sender thread

    // Stream ID allocation for reverse services
    next_stream_id: std.atomic.Value(u32),

    // Config reference for TCP tuning
    cfg: *const config.ServerConfig,

    /// Heartbeat thread: periodically sends heartbeat messages to client
    fn heartbeatThreadMain(self: *TunnelConnection) void {
        std.debug.print("[HEARTBEAT] Thread started (interval: {}ms)\n", .{self.heartbeat_interval_ms});

        while (self.running.load(.acquire)) {
            // Sleep in 100ms increments to allow quick shutdown
            const total_sleep_ms = self.heartbeat_interval_ms;
            const sleep_increment_ms = 100;
            var slept_ms: u32 = 0;

            while (slept_ms < total_sleep_ms and self.running.load(.acquire)) {
                const remaining_ms = total_sleep_ms - slept_ms;
                const this_sleep_ms = @min(sleep_increment_ms, remaining_ms);
                std.Thread.sleep(@as(u64, this_sleep_ms) * std.time.ns_per_ms);
                slept_ms += this_sleep_ms;
            }

            // Check if still running (may have been stopped during sleep)
            if (!self.running.load(.acquire)) break;

            // Send heartbeat message
            const timestamp = std.time.milliTimestamp();
            const heartbeat_msg = tunnel.HeartbeatMsg{ .timestamp = timestamp };

            var encode_buf: [16]u8 = undefined; // Heartbeat is 9 bytes
            const encoded_len = heartbeat_msg.encodeInto(&encode_buf) catch {
                std.debug.print("[HEARTBEAT] Encode error\n", .{});
                continue;
            };

            self.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
                std.debug.print("[HEARTBEAT] Send error: {}\n", .{err});
                // Continue trying even if send fails
            };

            tracePrint(enable_tunnel_trace, "[HEARTBEAT] Sent at timestamp {}\n", .{timestamp});
        }

        std.debug.print("[HEARTBEAT] Thread exiting\n", .{});
    }

    fn create(allocator: std.mem.Allocator, tunnel_fd: posix.fd_t, cfg: *const config.ServerConfig, static_keypair: std.crypto.dh.X25519.KeyPair) !*TunnelConnection {
        setSockOpts(tunnel_fd, cfg);

        const canonical_cipher = config.canonicalCipher(cfg);

        var tunnel_fd_owned = true;
        errdefer if (tunnel_fd_owned) posix.close(tunnel_fd);

        const channel = try transport.Channel.init(.{
            .allocator = allocator,
            .fd = tunnel_fd,
            .cipher = canonical_cipher,
            .psk = cfg.psk,
            .static_keypair = static_keypair,
            .role = .server,
            .version = build_options.version,
            .stats = transport.EncryptionStats{
                .total_ns = &encrypt_total_ns,
                .calls = &encrypt_calls,
            },
            .throughput = transport.ThroughputStats{
                .tx_bytes = &tunnel_tx_bytes,
                .rx_bytes = &tunnel_rx_bytes,
            },
        });
        var channel_guard = true;
        defer if (channel_guard) {
            var tmp = channel;
            tmp.deinit();
        };

        const conn = try allocator.create(TunnelConnection);

        // Initialize struct with cipher state
        conn.* = .{
            .tunnel_fd = tunnel_fd,
            .streams = std.HashMap(StreamKey, *Stream, StreamKeyContext, 80).init(allocator),
            .streams_mutex = .{},
            .channel = channel,
            .running = std.atomic.Value(bool).init(true),
            .udp_forwarder = null,
            .udp_service_id = null,
            .heartbeat_interval_ms = cfg.advanced.heartbeat_interval_seconds * 1000, // Convert to milliseconds
            .heartbeat_thread = null,
            .next_stream_id = std.atomic.Value(u32).init(1),
            .cfg = cfg,
        };
        tunnel_fd_owned = false;
        channel_guard = false;

        // Spawn heartbeat thread if enabled
        if (conn.heartbeat_interval_ms > 0) {
            conn.heartbeat_thread = std.Thread.spawn(.{}, heartbeatThreadMain, .{conn}) catch |err| {
                conn.destroy();
                return err;
            };
            std.debug.print("[TUNNEL] Heartbeat enabled: sending every {} seconds\n", .{cfg.advanced.heartbeat_interval_seconds});
        }

        return conn;
    }

    fn setSockOpts(fd: posix.fd_t, cfg: *const config.ServerConfig) void {
        const tcp_options = common.TcpOptions{
            .nodelay = cfg.advanced.tcp_nodelay,
            .keepalive = cfg.advanced.tcp_keepalive,
            .keepalive_idle = cfg.advanced.tcp_keepalive_idle,
            .keepalive_interval = cfg.advanced.tcp_keepalive_interval,
            .keepalive_count = cfg.advanced.tcp_keepalive_count,
        };
        applyTcpOptions(fd, tcp_options);
        tuneSocketBuffers(fd, cfg.advanced.socket_buffer_size);
    }

    fn run(self: *TunnelConnection) void {
        var buf: [256 * 1024]u8 align(64) = undefined; // 256KB for better batching
        var decoder = protocol.FrameDecoder.init(global_allocator);
        defer decoder.deinit();

        // Check if decoder buffer was allocated
        if (decoder.buffer.len == 0) {
            std.debug.print("[TUNNEL] Failed to allocate decoder buffer!\n", .{});
            self.cleanup();
            self.running.store(false, .release);
            return;
        }

        std.debug.print("[TUNNEL] Connection handler started (buffer size: {})\n", .{decoder.buffer.len});

        const PollEntry = union(enum) {
            tunnel,
            stream: *Stream,
        };
        var poll_fds = std.ArrayListUnmanaged(posix.pollfd){};
        defer poll_fds.deinit(global_allocator);
        var poll_entries = std.ArrayListUnmanaged(PollEntry){};
        defer poll_entries.deinit(global_allocator);
        const poll_timeout_ms: i32 = 1000;

        while (self.running.load(.acquire) and !shutdown_flag.load(.acquire)) {
            poll_fds.clearRetainingCapacity();
            poll_entries.clearRetainingCapacity();

            poll_fds.append(global_allocator, .{
                .fd = self.tunnel_fd,
                .events = posix.POLL.IN,
                .revents = 0,
            }) catch unreachable;
            poll_entries.append(global_allocator, .{ .tunnel = {} }) catch unreachable;

            self.streams_mutex.lock();
            var iter = self.streams.iterator();
            while (iter.next()) |entry| {
                const stream_ptr = entry.value_ptr.*;
                stream_ptr.acquireRef();
                poll_entries.append(global_allocator, .{ .stream = stream_ptr }) catch {
                    stream_ptr.releaseRef();
                    continue;
                };
                poll_fds.append(global_allocator, .{
                    .fd = stream_ptr.target_fd,
                    .events = posix.POLL.IN,
                    .revents = 0,
                }) catch {
                    _ = poll_entries.pop();
                    stream_ptr.releaseRef();
                    continue;
                };
            }
            self.streams_mutex.unlock();

            const ready = posix.poll(poll_fds.items, poll_timeout_ms) catch |err| {
                std.debug.print("[TUNNEL] Poll error: {}\n", .{err});
                break;
            };

            if (ready == 0) {
                for (poll_entries.items) |entry| {
                    switch (entry) {
                        .stream => |stream_ptr| stream_ptr.releaseRef(),
                        .tunnel => {},
                    }
                }
                continue;
            }

            var fatal_error = false;
            var idx: usize = 0;
            loop: while (idx < poll_entries.items.len) : (idx += 1) {
                const entry = poll_entries.items[idx];
                const fd_info = poll_fds.items[idx];
                switch (entry) {
                    .tunnel => {
                        if ((fd_info.revents & posix.POLL.IN) == 0) continue;

                        const n = posix.recv(self.tunnel_fd, &buf, 0) catch |err| {
                            std.debug.print("[TUNNEL] Recv error: {}\n", .{err});
                            fatal_error = true;
                            break :loop;
                        };

                        if (n == 0) {
                            std.debug.print("[TUNNEL] Client disconnected\n", .{});
                            fatal_error = true;
                            break :loop;
                        }

                        tracePrint(enable_tunnel_trace, "[TUNNEL] Received {} bytes from client\n", .{n});

                        decoder.feed(buf[0..n]) catch |err| {
                            std.debug.print("[TUNNEL] Decoder feed error: {}\n", .{err});
                            fatal_error = true;
                            break :loop;
                        };

                        while (decoder.decode() catch null) |frame_payload| {
                            self.handleMessage(frame_payload) catch |err| {
                                std.debug.print("[TUNNEL] Handle message error: {}\n", .{err});
                                self.running.store(false, .release);
                                fatal_error = true;
                                break :loop;
                            };
                            if (!self.running.load(.acquire)) break;
                        }

                        if (!self.running.load(.acquire)) {
                            fatal_error = true;
                            break :loop;
                        }
                    },
                    .stream => {
                        if (fd_info.revents != 0) {
                            self.handleStreamPollEvent(entry.stream, fd_info.revents);
                        }
                        entry.stream.releaseRef();
                    },
                }
            }

            if (fatal_error) {
                var release_idx = idx + 1;
                while (release_idx < poll_entries.items.len) : (release_idx += 1) {
                    switch (poll_entries.items[release_idx]) {
                        .stream => |stream_ptr| stream_ptr.releaseRef(),
                        .tunnel => {},
                    }
                }
                break;
            }
        }

        std.debug.print("[TUNNEL] Connection handler stopping\n", .{});
        self.cleanup();
        self.running.store(false, .release);
    }

    fn handleMessage(self: *TunnelConnection, payload: []const u8) !void {
        if (payload.len == 0) return;

        const message_slice = try self.channel.decryptFrame(payload);
        if (message_slice.len == 0) return;

        const msg_type: tunnel.MessageType = @enumFromInt(message_slice[0]);

        switch (msg_type) {
            .connect_ack => {
                // REVERSE MODE: Client acknowledged connection to local target
                const ack = try tunnel.ConnectAckMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[TUNNEL-REVERSE] CONNECT_ACK from client stream_id={}\n", .{ack.stream_id});
                // Connection established, stream thread will start forwarding
            },
            .connect => {
                const connect_msg = try tunnel.ConnectMsg.decode(message_slice, global_allocator);
                defer global_allocator.free(connect_msg.token);

                tracePrint(enable_tunnel_trace, "[TUNNEL] CONNECT request: service_id={} stream_id={}\n", .{
                    connect_msg.service_id,
                    connect_msg.stream_id,
                });

                self.handleConnect(connect_msg) catch |err| {
                    std.debug.print("[TUNNEL] Failed to connect: {}\n", .{err});
                    // Map error to error code
                    const error_code: tunnel.ErrorCode = switch (err) {
                        error.UnknownService => .unknown_service,
                        error.AuthenticationFailed => .authentication_failed,
                        error.ConnectionRefused => .connection_refused,
                        error.ConnectionTimedOut => .connection_timeout,
                        else => .internal_error,
                    };
                    // Send error response (no allocation - use stack buffer)
                    const error_msg = tunnel.ConnectErrorMsg{
                        .service_id = connect_msg.service_id,
                        .stream_id = connect_msg.stream_id,
                        .error_code = error_code,
                        .error_msg = "Connection failed",
                    };

                    var encode_buf: [128]u8 = undefined; // ERROR message with text
                    const encoded_len = error_msg.encodeInto(&encode_buf) catch return;

                    self.channel.sendCopy(encode_buf[0..encoded_len]) catch |send_err| {
                        self.handleSendFailure(send_err);
                    };
                };
            },
            .data => {
                const data_msg = try tunnel.DataMsg.decode(message_slice);

                const key = StreamKey{ .service_id = data_msg.service_id, .stream_id = data_msg.stream_id };
                var stream_ref: ?*Stream = null;

                self.streams_mutex.lock();
                if (self.streams.get(key)) |s| {
                    s.acquireRef();
                    stream_ref = s;
                }
                self.streams_mutex.unlock();

                if (stream_ref) |s| {
                    defer s.releaseRef();
                    if (!s.fd_closed.load(.acquire)) {
                        sendAllToFd(s.target_fd, data_msg.data) catch |err| {
                            std.debug.print("[STREAM {}] Send to target failed: {}\n", .{ data_msg.stream_id, err });
                        };
                    }
                }
            },
            .close => {
                const close_msg = try tunnel.CloseMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[TUNNEL] CLOSE service_id={} stream_id={}\n", .{ close_msg.service_id, close_msg.stream_id });

                const key = StreamKey{ .service_id = close_msg.service_id, .stream_id = close_msg.stream_id };
                self.streams_mutex.lock();
                const maybe_stream = self.streams.fetchRemove(key);
                self.streams_mutex.unlock();

                if (maybe_stream) |entry| {
                    // Stream still exists, stop and destroy it
                    // Note: The stream may have already removed itself, in which case this won't execute
                    entry.value.stop();
                    entry.value.releaseRef(); // drop map reference
                    std.debug.print("[TUNNEL] Stream {} cleaned up after CLOSE message\n", .{close_msg.stream_id});
                } else {
                    // Stream already cleaned itself up
                    tracePrint(enable_tunnel_trace, "[TUNNEL] Stream {} already removed (self-cleanup)\n", .{close_msg.stream_id});
                }
            },
            .udp_data => {
                const udp_msg = try tunnel.UdpDataMsg.decode(message_slice, global_allocator);
                defer global_allocator.free(udp_msg.source_addr);

                if (self.udp_forwarder) |forwarder| {
                    forwarder.handleUdpData(udp_msg) catch |err| {
                        std.debug.print("[UDP] Failed to forward: {}\n", .{err});
                    };
                } else {
                    std.debug.print("[UDP] Received UDP data but no forwarder exists\n", .{});
                }
            },
            .connect_error => {
                // REVERSE MODE: Client failed to connect to local target
                const err_msg = try tunnel.ConnectErrorMsg.decode(message_slice, global_allocator);
                defer global_allocator.free(err_msg.error_msg);
                std.debug.print("[TUNNEL-REVERSE] CONNECT_ERROR from client: stream_id={} error={s}\n", .{ err_msg.stream_id, err_msg.error_msg });

                const key = StreamKey{ .service_id = err_msg.service_id, .stream_id = err_msg.stream_id };
                self.streams_mutex.lock();
                const maybe_stream = self.streams.fetchRemove(key);
                self.streams_mutex.unlock();

                if (maybe_stream) |entry| {
                    entry.value.stop();
                    entry.value.releaseRef();
                    std.debug.print("[TUNNEL-REVERSE] Stream {} cleaned up after CONNECT_ERROR\n", .{err_msg.stream_id});
                }
            },
            .heartbeat => {
                // Server doesn't need to process heartbeat responses from client
                // (client -> server heartbeat is handled by client-side timeout logic)
                const heartbeat_msg = try tunnel.HeartbeatMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[HEARTBEAT] Received from client: timestamp={}\n", .{heartbeat_msg.timestamp});
            },
            .version => {
                // Version exchange happens during handshake only
                // Receiving it here would be unexpected, just ignore
                tracePrint(enable_tunnel_trace, "[SERVER] Unexpected VERSION message during operation (ignoring)\n", .{});
            },
            .reverse_connect => {
                // Server sends REVERSE_CONNECT, doesn't receive it
                // If we receive it, something is wrong - just ignore
                tracePrint(enable_tunnel_trace, "[SERVER] Unexpected REVERSE_CONNECT from client (ignoring)\n", .{});
            },
        }
    }

    fn handleStreamPollEvent(self: *TunnelConnection, stream: *Stream, revents: i16) void {
        var closed = false;
        if ((revents & posix.POLL.IN) != 0) {
            self.forwardTargetData(stream) catch |err| switch (err) {
                error.ConnectionClosed => {
                    self.completeStream(stream, false);
                    closed = true;
                },
                else => {
                    std.debug.print("[STREAM {}] Forward error: {}\n", .{ stream.stream_id, err });
                    self.completeStream(stream, true);
                    closed = true;
                },
            };
        }

        const extra_error_mask: i16 = if (@hasDecl(posix.POLL, "NVAL")) posix.POLL.NVAL else 0;
        const error_mask: i16 = posix.POLL.HUP | posix.POLL.ERR | extra_error_mask;
        if (!closed and (revents & error_mask) != 0) {
            self.completeStream(stream, true);
        }
    }

    fn forwardTargetData(self: *TunnelConnection, stream: *Stream) anyerror!void {
        const message_header_len: usize = 7;
        const encrypted = self.channel.isEncrypted();

        const recv_slice: []u8 = if (encrypted) stream.read_buffer else stream.frame_buffer[message_header_len..];
        const n = posix.recv(stream.target_fd, recv_slice, 0) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        tracePrint(enable_stream_trace, "[STREAM {}] recv() returned {} bytes\n", .{ stream.stream_id, n });

        if (n == 0) {
            self.sendStreamClose(stream);
            return error.ConnectionClosed;
        }

        if (!encrypted) {
            stream.frame_buffer[0] = @intFromEnum(tunnel.MessageType.data);
            std.mem.writeInt(u16, stream.frame_buffer[1..3], stream.service_id, .big);
            std.mem.writeInt(u32, stream.frame_buffer[3..7], stream.stream_id, .big);

            const slice = stream.frame_buffer[0 .. message_header_len + n];
            self.channel.sendDataInPlace(slice, message_header_len + n) catch |err| {
                std.debug.print("[STREAM {}] send() error: {}\n", .{ stream.stream_id, err });
                self.handleSendFailure(err);
                return error.ConnectionClosed;
            };
            return;
        }

        const data_msg = tunnel.DataMsg{
            .service_id = stream.service_id,
            .stream_id = stream.stream_id,
            .data = stream.read_buffer[0..n],
        };

        const encoded_len = data_msg.encodeInto(stream.frame_buffer[0..]) catch {
            return error.ConnectionClosed;
        };

        const slice = stream.frame_buffer[0 .. encoded_len + noise.TAG_LEN];
        self.channel.sendDataInPlace(slice, encoded_len) catch |err| {
            std.debug.print("[STREAM {}] send() error: {}\n", .{ stream.stream_id, err });
            self.handleSendFailure(err);
            return error.ConnectionClosed;
        };
    }

    fn completeStream(self: *TunnelConnection, stream: *Stream, send_close: bool) void {
        const already_closed = stream.fd_closed.load(.acquire);
        if (send_close and !already_closed) {
            self.sendStreamClose(stream);
        }

        self.streams_mutex.lock();
        const key = StreamKey{ .service_id = stream.service_id, .stream_id = stream.stream_id };
        const removed = self.streams.fetchRemove(key);
        self.streams_mutex.unlock();
        if (removed) |_| {
            stream.releaseRef();
        }

        stream.stop();
    }

    fn sendStreamClose(self: *TunnelConnection, stream: *Stream) void {
        var encode_buf: [16]u8 = undefined;
        const close_msg = tunnel.CloseMsg{ .service_id = stream.service_id, .stream_id = stream.stream_id };
        const encoded_len = close_msg.encodeInto(&encode_buf) catch return;
        self.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
            self.handleSendFailure(err);
        };
    }

    fn handleConnect(self: *TunnelConnection, msg: tunnel.ConnectMsg) !void {
        const service_ptr = self.cfg.getServiceById(msg.service_id) orelse {
            std.debug.print("[AUTH] Unknown service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
            return error.UnknownService;
        };
        const service = service_ptr.*;

        // Verify authentication token
        const expected_token = if (service.token.len > 0) service.token else self.cfg.token;
        if (expected_token.len > 0) {
            // Use constant-time comparison to prevent timing attacks
            if (!common.constantTimeEqual(msg.token, expected_token)) {
                std.debug.print("[AUTH] Invalid token for service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
                return error.AuthenticationFailed;
            }
            std.debug.print("[AUTH] Token validated for service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
        }

        switch (service.transport) {
            .tcp => {
                const address = try resolveHostPort(service.address, service.port);
                const target_fd = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
                var target_fd_guard = true;
                defer if (target_fd_guard) posix.close(target_fd);

                setSockOpts(target_fd, self.cfg);

                try posix.connect(target_fd, &address.any, address.getOsSockLen());

                tracePrint(enable_stream_trace, "[STREAM {}] Connected to {s}:{}\n", .{ msg.stream_id, service.address, service.port });

                const stream = try Stream.create(global_allocator, msg.service_id, msg.stream_id, target_fd, self);
                target_fd_guard = false; // ownership transferred to Stream

                self.streams_mutex.lock();
                defer self.streams_mutex.unlock();

                const key = StreamKey{ .service_id = msg.service_id, .stream_id = msg.stream_id };
                stream.acquireRef(); // map reference
                self.streams.put(key, stream) catch |err| {
                    // Drop map ref before shutting down thread
                    stream.releaseRef();
                    stream.stop();
                    return err;
                };
            },
            .udp => {
                if (self.udp_forwarder == null) {
                    std.debug.print("[UDP] Creating UDP forwarder for target {s}:{}\n", .{ service.address, service.port });

                    const forwarder = try udp_server.UdpForwarder.create(
                        global_allocator,
                        msg.service_id,
                        service.address,
                        service.port,
                        @ptrCast(self),
                        sendTunnelPayload,
                        self.cfg.advanced.udp_timeout_seconds,
                    );
                    self.udp_forwarder = forwarder;
                    self.udp_service_id = msg.service_id;
                } else if (self.udp_service_id) |service_id| {
                    if (service_id != msg.service_id) {
                        std.debug.print("[UDP] Forwarder already active for service_id={}, rejecting service_id={}\n", .{ service_id, msg.service_id });
                        return error.UdpForwarderBusy;
                    }
                } else {
                    self.udp_service_id = msg.service_id;
                }
            },
        }

        // Send ACK (no allocation - use stack buffer)
        const ack_msg = tunnel.ConnectAckMsg{ .service_id = msg.service_id, .stream_id = msg.stream_id };

        var encode_buf: [16]u8 = undefined; // ACK is 7 bytes
        const encoded_len = try ack_msg.encodeInto(&encode_buf);

        try self.channel.sendCopy(encode_buf[0..encoded_len]);
    }

    // Wrapper for UDP forwarder callback (converts opaque pointer back to TunnelConnection)
    fn sendTunnelPayload(conn: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void {
        const self: *TunnelConnection = @ptrCast(@alignCast(conn));
        const slice = buffer[0 .. payload_len + noise.TAG_LEN];
        try self.channel.sendDataInPlace(slice, payload_len);
    }

    fn handleSendFailure(self: *TunnelConnection, err: anyerror) void {
        if (!self.running.load(.acquire)) return;
        std.debug.print("[TUNNEL] Send failure: {}\n", .{err});
        self.running.store(false, .release);
        posix.shutdown(self.tunnel_fd, .both) catch {};
    }

    /// Send all data to a file descriptor, looping until complete.
    /// Extracted to common.zig to eliminate duplication with client.zig.
    const sendAllToFd = common.sendAllToFd;

    fn cleanup(self: *TunnelConnection) void {
        // Stop heartbeat thread first
        if (self.heartbeat_thread) |thread| {
            self.running.store(false, .release); // Signal thread to stop
            thread.join();
        }

        // Stop and release all streams without holding the mutex during blocking calls
        while (true) {
            self.streams_mutex.lock();
            var iter = self.streams.iterator();
            const entry = iter.next();
            if (entry) |e| {
                const key_copy = e.key_ptr.*; // copy to avoid invalid pointer after remove
                const stream_ptr = e.value_ptr.*;
                _ = self.streams.remove(key_copy);
                self.streams_mutex.unlock();
                stream_ptr.stop();
                stream_ptr.releaseRef(); // drop map reference
            } else {
                self.streams_mutex.unlock();
                break;
            }
        }
        self.streams.deinit();

        if (self.udp_forwarder) |forwarder| {
            forwarder.stop();
            forwarder.destroy();
            self.udp_forwarder = null;
            self.udp_service_id = null;
        }

        posix.close(self.tunnel_fd);
        self.tunnel_fd = -1;
    }

    fn destroy(self: *TunnelConnection) void {
        // Cleanup UDP forwarder if exists
        if (self.udp_forwarder) |forwarder| {
            forwarder.stop();
            forwarder.destroy();
            self.udp_forwarder = null;
            self.udp_service_id = null;
        }

        if (self.tunnel_fd != -1) {
            posix.close(self.tunnel_fd);
            self.tunnel_fd = -1;
        }

        self.channel.deinit();
        global_allocator.destroy(self);
    }
};

test "forwardTargetData sends plaintext frames" {
    if (builtin.target.os.tag == .windows) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    global_allocator = allocator;

    var cfg = try config.ServerConfig.init(allocator);
    defer cfg.deinit();

    const tunnel_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(tunnel_pair[0]);
    defer posix.close(tunnel_pair[1]);

    const target_pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(target_pair[0]);
    defer posix.close(target_pair[1]);

    const channel = try transport.Channel.init(.{
        .allocator = allocator,
        .fd = tunnel_pair[0],
        .cipher = "none",
        .psk = "",
        .static_keypair = std.crypto.dh.X25519.KeyPair.generate(),
        .role = .server,
        .version = build_options.version,
    });

    var conn = TunnelConnection{
        .tunnel_fd = tunnel_pair[0],
        .streams = std.HashMap(StreamKey, *Stream, StreamKeyContext, 80).init(allocator),
        .streams_mutex = .{},
        .channel = channel,
        .running = std.atomic.Value(bool).init(true),
        .udp_forwarder = null,
        .udp_service_id = null,
        .heartbeat_interval_ms = 0,
        .heartbeat_thread = null,
        .next_stream_id = std.atomic.Value(u32).init(1),
        .cfg = &cfg,
    };
    defer conn.channel.deinit();
    defer conn.streams.deinit();

    const stream = try Stream.create(allocator, 2, 99, target_pair[0], &conn);
    defer stream.releaseRef();

    _ = try posix.write(target_pair[1], "pong");

    try conn.forwardTargetData(stream);

    var frame_header: [4]u8 = undefined;
    try common.recvAllFromFd(tunnel_pair[1], &frame_header);
    const frame_len = std.mem.readInt(u32, frame_header[0..4], .big);
    var payload = try allocator.alloc(u8, frame_len);
    defer allocator.free(payload);
    try common.recvAllFromFd(tunnel_pair[1], payload);

    try std.testing.expectEqual(@as(u8, @intFromEnum(tunnel.MessageType.data)), payload[0]);
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, payload[1..3], .big));
    try std.testing.expectEqual(@as(u32, 99), std.mem.readInt(u32, payload[3..7], .big));
    try std.testing.expectEqualStrings("pong", payload[7..]);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    global_allocator = allocator;
    defer diagnostics.flushEncryptStats("server", &encrypt_total_ns, &encrypt_calls);
    defer diagnostics.flushThroughputStats("server", &tunnel_tx_bytes, &tunnel_rx_bytes);
    defer cleanupSignalPipe();

    var exit_code: u8 = 0;
    defer if (exit_code != 0) posix.exit(exit_code);

    const args_list = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args_list);

    var parse_ctx = ParseContext{};
    var cli_opts = parseServerArgs(args_list, &parse_ctx) catch |err| {
        switch (err) {
            ParseError.UnknownFlag => {
                std.debug.print("error: unknown option '{s}'\n", .{parse_ctx.arg});
            },
            ParseError.MissingValue => {
                std.debug.print("error: missing value for option '{s}'\n", .{parse_ctx.arg});
            },
            ParseError.ConflictingMode => {
                std.debug.print("error: conflicting option '{s}'\n", .{parse_ctx.arg});
            },
            ParseError.TooManyPositionals => {
                std.debug.print("error: unexpected argument '{s}'\n", .{parse_ctx.arg});
            },
            ParseError.InvalidValue => {
                std.debug.print("error: invalid value for option '{s}'\n", .{parse_ctx.arg});
            },
        }
        printServerUsage();
        exit_code = 1;
        return;
    };

    config_path_global = cli_opts.config_path;

    switch (cli_opts.mode) {
        .help => {
            printServerUsage();
            return;
        },
        .version => {
            std.debug.print("floos {s}\n", .{build_options.version});
            return;
        },
        .doctor => {
            const ok = try runServerDoctor(allocator, &cli_opts);
            if (!ok) exit_code = 1;
            return;
        },
        .ping => {
            const ok = try runServerPing(allocator, &cli_opts);
            if (!ok) exit_code = 1;
            return;
        },
        .run => {},
    }

    var cfg = try loadServerConfigWithOverrides(allocator, &cli_opts);
    defer cfg.deinit();
    const port = cfg.port;

    const canonical_cipher = config.canonicalCipher(&cfg);
    if (std.mem.eql(u8, canonical_cipher, "none")) {
        std.debug.print("[WARN] Server encryption disabled; relying solely on tokens for authentication.\n", .{});
    } else if (cfg.psk.len == 0) {
        std.debug.print("[WARN] Server PSK is empty; clients will fail to handshake.\n", .{});
    } else if (std.mem.eql(u8, cfg.psk, config.DEFAULT_PSK)) {
        std.debug.print("[WARN] Server is using the placeholder PSK '{s}'. Update configs for production.\n", .{config.DEFAULT_PSK});
    }

    var default_token_required = false;
    var service_iter = cfg.services.valueIterator();
    while (service_iter.next()) |service| {
        if (service.token.len == 0) {
            default_token_required = true;
            break;
        }
    }

    if (default_token_required and cfg.token.len == 0) {
        std.debug.print("[WARN] Server default token is empty; unauthorized clients may connect.\n", .{});
    } else if (cfg.token.len > 0 and std.mem.eql(u8, cfg.token, config.DEFAULT_TOKEN)) {
        std.debug.print("[WARN] Server is using the placeholder token '{s}'. Change this before deployment.\n", .{config.DEFAULT_TOKEN});
    }

    std.debug.print("Floo Tunnel Server (floos-blocking)\n", .{});
    std.debug.print("====================================\n\n", .{});
    std.debug.print("[CONFIG] Port: {}\n", .{port});
    std.debug.print("[CONFIG] Thread Pinning: {s}\n", .{if (cfg.advanced.pin_threads) "enabled" else "disabled"});
    std.debug.print("[CONFIG] IO Batch Bytes: {}\n", .{cfg.advanced.io_batch_bytes});
    std.debug.print("[CONFIG] Mode: Blocking I/O + Threads\n", .{});
    std.debug.print("[CONFIG] Hot Reload: Disabled (restart floos to apply configuration changes)\n\n", .{});

    // Register signal handlers (POSIX only)
    if (builtin.target.os.tag != .windows and @hasDecl(posix, "Sigaction") and @hasDecl(posix, "sigaction")) {
        try setupSignalPipe();
        const sig_action = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = std.mem.zeroes(posix.sigset_t),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &sig_action, null);
        if (@hasDecl(posix.SIG, "HUP")) {
            posix.sigaction(posix.SIG.HUP, &sig_action, null); // Register SIGHUP for hot reload
        }
        if (@hasDecl(posix.SIG, "USR1")) {
            posix.sigaction(posix.SIG.USR1, &sig_action, null);
        }
        if (@hasDecl(posix.SIG, "PIPE")) {
            const ignore = posix.Sigaction{
                .handler = .{ .handler = posix.SIG.IGN },
                .mask = std.mem.zeroes(posix.sigset_t),
                .flags = 0,
            };
            posix.sigaction(posix.SIG.PIPE, &ignore, null);
        }
    }

    // Create listen socket
    const listen_addr = try resolveHostPort(cfg.bind, port);
    const listen_fd = try posix.socket(listen_addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(listen_fd);

    try posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    try posix.bind(listen_fd, &listen_addr.any, listen_addr.getOsSockLen());
    try posix.listen(listen_fd, common.LISTEN_BACKLOG);

    var addr_buf: [64]u8 = undefined;
    std.debug.print("[SERVER] Listening on {s}\n", .{formatAddress(listen_addr, &addr_buf)});
    std.debug.print("[READY] Server ready. Press Ctrl+C to stop.\n\n", .{});

    // Generate persistent static keypair for Noise XX authentication
    const static_keypair = std.crypto.dh.X25519.KeyPair.generate();

    const ConnectionEntry = struct {
        conn: *TunnelConnection,
        thread: std.Thread,
    };
    var connections = std.ArrayListUnmanaged(ConnectionEntry){};
    var reverse_listeners = std.ArrayListUnmanaged(*ReverseListener){};
    var reverse_listeners_conn: ?*TunnelConnection = null;
    defer {
        stopAllReverseListeners(&reverse_listeners);
        reverse_listeners.deinit(allocator);

        // Stop all connections
        for (connections.items) |entry| {
            entry.conn.running.store(false, .release);
            // Shutdown tunnel socket to unblock recv() in connection thread
            posix.shutdown(entry.conn.tunnel_fd, .recv) catch {};
        }
        // Wait for threads and cleanup
        for (connections.items) |entry| {
            entry.thread.join();
        }
        for (connections.items) |entry| {
            entry.conn.destroy();
        }
        connections.deinit(allocator);
    }

    // Accept loop with rate limiting to prevent connection flood attacks
    // Allow up to 100 new connections per second (reasonable for production)
    var rate_limiter = common.RateLimiter.init(100);
    var shutdown_notice_printed = false;
    while (!shutdown_flag.load(.acquire)) {
        if (flush_stats_requested.swap(false, .acq_rel)) {
            diagnostics.flushEncryptStats("server", &encrypt_total_ns, &encrypt_calls);
            diagnostics.flushThroughputStats("server", &tunnel_tx_bytes, &tunnel_rx_bytes);
        }
        if (sighup_requested.swap(false, .acq_rel)) {
            std.debug.print("\n[INFO] Configuration reload via SIGHUP is currently disabled; restart floos to apply changes.\n", .{});
        }
        if (shutdown_flag.load(.acquire) and !shutdown_notice_printed) {
            std.debug.print("\n[SHUTDOWN] Received interrupt, stopping server...\n", .{});
            shutdown_notice_printed = true;
        }

        // Reap completed connections
        var idx: usize = 0;
        while (idx < connections.items.len) {
            const entry = connections.items[idx];
            if (!entry.conn.running.load(.acquire)) {
                if (reverse_listeners_conn) |active_conn| {
                    if (active_conn == entry.conn) {
                        stopAllReverseListeners(&reverse_listeners);
                        reverse_listeners_conn = null;
                    }
                }
                entry.thread.join();
                entry.conn.destroy();
                _ = connections.swapRemove(idx);
                continue;
            }
            idx += 1;
        }

        // Accept with timeout (poll for shutdown and signal pipe)
        var poll_buf: [2]posix.pollfd = undefined;
        var poll_count: usize = 1;
        poll_buf[0] = .{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 };
        const signal_fd = signal_pipe_read_fd.load(.acquire);
        if (signal_fd != -1) {
            poll_count = 2;
            poll_buf[1] = .{ .fd = signal_fd, .events = posix.POLL.IN, .revents = 0 };
        } else {
            poll_count = 1;
        }

        const ready = posix.poll(poll_buf[0..poll_count], 1000) catch continue; // 1s timeout

        if (signal_fd != -1) {
            const signal_events = poll_buf[1].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR);
            if (signal_events != 0) {
                drainSignalPipe();
            }
        }

        if (ready == 0) continue; // Timeout, check flags
        if ((poll_buf[0].revents & posix.POLL.IN) == 0) continue;

        const tunnel_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
            std.debug.print("[SERVER] Accept error: {}\n", .{err});
            continue;
        };

        // Apply rate limiting to prevent connection flood attacks
        if (!rate_limiter.tryAcquire()) {
            std.debug.print("[SERVER] Rate limit exceeded, rejecting connection fd={}\n", .{tunnel_fd});
            posix.close(tunnel_fd);
            continue;
        }

        std.debug.print("[SERVER] Accepted tunnel connection: fd={}\n", .{tunnel_fd});
        tuneSocketBuffers(tunnel_fd, cfg.advanced.socket_buffer_size);
        const tcp_options = common.TcpOptions{
            .nodelay = cfg.advanced.tcp_nodelay,
            .keepalive = cfg.advanced.tcp_keepalive,
            .keepalive_idle = cfg.advanced.tcp_keepalive_idle,
            .keepalive_interval = cfg.advanced.tcp_keepalive_interval,
            .keepalive_count = cfg.advanced.tcp_keepalive_count,
        };
        applyTcpOptions(tunnel_fd, tcp_options);

        // Create tunnel connection (shares static identity across all connections)
        const tunnel_conn = TunnelConnection.create(allocator, tunnel_fd, &cfg, static_keypair) catch |err| {
            std.debug.print("[SERVER] Failed to create tunnel: {}\n", .{err});
            posix.close(tunnel_fd);
            continue;
        };

        // Spawn thread for this connection
        const cpu_index = if (cfg.advanced.pin_threads) nextCpuIndex() else null;
        const thread = try std.Thread.spawn(.{
            .stack_size = common.TUNNEL_THREAD_STACK,
        }, tunnelConnectionThread, .{TunnelThreadContext{ .conn = tunnel_conn, .cpu_index = cpu_index }});

        connections.append(allocator, .{ .conn = tunnel_conn, .thread = thread }) catch |err| {
            std.debug.print("[SERVER] Failed to track connection: {}\n", .{err});
            tunnel_conn.running.store(false, .release);
            posix.shutdown(tunnel_conn.tunnel_fd, .recv) catch {};
            thread.join();
            tunnel_conn.destroy();
            continue;
        };

        // (Re)bind reverse service listeners to this tunnel if reverse mode is configured
        if (cfg.reverse_services.count() > 0) {
            if (reverse_listeners_conn) |_| {
                stopAllReverseListeners(&reverse_listeners);
                reverse_listeners_conn = null;
            }

            std.debug.print("[REVERSE] Starting {} reverse services on new tunnel...\n", .{cfg.reverse_services.count()});
            var rev_iter = cfg.reverse_services.valueIterator();
            while (rev_iter.next()) |service| {
                const listener = ReverseListener.create(allocator, service.*, tunnel_conn) catch |err| {
                    std.debug.print("[REVERSE] Failed to create listener for service '{s}': {}\n", .{ service.name, err });
                    continue;
                };

                reverse_listeners.append(allocator, listener) catch |err| {
                    std.debug.print("[REVERSE] Failed to track listener: {}\n", .{err});
                    listener.stop();
                    listener.destroy();
                    continue;
                };
            }

            if (reverse_listeners.items.len > 0) {
                reverse_listeners_conn = tunnel_conn;
                std.debug.print("[REVERSE] Reverse services bound to current tunnel connection\n", .{});
            }
        }
    }

    std.debug.print("\n[SHUTDOWN] Server stopped.\n", .{});
}

const TunnelThreadContext = struct {
    conn: *TunnelConnection,
    cpu_index: ?usize,
};

fn tunnelConnectionThread(ctx: TunnelThreadContext) void {
    applyThreadAffinity(ctx.cpu_index);
    tunnelConnectionThreadMain(ctx.conn);
}

fn tunnelConnectionThreadMain(conn: *TunnelConnection) void {
    conn.run();
    // Note: conn.destroy() is called by main thread on shutdown
}

/// Context for reverse service listener thread
const ReverseServiceListenerContext = struct {
    allocator: std.mem.Allocator,
    service_id: tunnel.ServiceId,
    listen_host: []const u8,
    listen_port: u16,
    tunnel_conn: *TunnelConnection,
    next_stream_id: std.atomic.Value(u32),
};

/// Reverse service listener thread - handles one reverse mode service
/// Listens on a public port, sends CONNECT to client when users connect
fn reverseServiceListener(ctx_ptr: *anyopaque) void {
    const ctx: *ReverseServiceListenerContext = @ptrCast(@alignCast(ctx_ptr));
    defer {
        ctx.allocator.free(ctx.listen_host);
        ctx.allocator.destroy(ctx);
    }

    // Create listener socket
    const local_addr = resolveHostPort(ctx.listen_host, ctx.listen_port) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to parse address for service_id={}: {}\n", .{ ctx.service_id, err });
        return;
    };

    const listen_fd = posix.socket(local_addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to create socket for service_id={}: {}\n", .{ ctx.service_id, err });
        return;
    };
    defer posix.close(listen_fd);

    posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};

    posix.bind(listen_fd, &local_addr.any, local_addr.getOsSockLen()) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to bind service_id={} on port {}: {}\n", .{ ctx.service_id, ctx.listen_port, err });
        return;
    };

    posix.listen(listen_fd, common.LISTEN_BACKLOG) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to listen for service_id={}: {}\n", .{ ctx.service_id, err });
        return;
    };

    std.debug.print("[REVERSE-SERVICE] Listening on {s}:{} (service_id={}, reverse mode)\n", .{ ctx.listen_host, ctx.listen_port, ctx.service_id });

    // Accept loop
    while (!shutdown_flag.load(.acquire) and ctx.tunnel_conn.running.load(.acquire)) {
        // Poll for accept with timeout
        var fds = [_]posix.pollfd{
            .{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 },
        };

        const ready = posix.poll(&fds, 1000) catch continue; // 1s timeout
        if (ready == 0) continue; // Timeout, check shutdown

        const user_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
            std.debug.print("[REVERSE-SERVICE] Accept error for service_id={}: {}\n", .{ ctx.service_id, err });
            continue;
        };

        // Generate stream_id
        const stream_id = ctx.next_stream_id.fetchAdd(1, .acq_rel);

        std.debug.print("[REVERSE-SERVICE] External user connected, sending CONNECT to client (service_id={}, stream_id={})\n", .{ ctx.service_id, stream_id });

        // Apply socket tuning
        TunnelConnection.setSockOpts(user_fd, ctx.tunnel_conn.cfg);

        // Send CONNECT message to client through tunnel
        const connect_msg = tunnel.ConnectMsg{
            .service_id = ctx.service_id,
            .stream_id = stream_id,
            .token = "",
        };

        var encode_buf: [512]u8 = undefined;
        const encoded_len = connect_msg.encodeInto(&encode_buf) catch {
            std.debug.print("[REVERSE-SERVICE] Failed to encode CONNECT message\n", .{});
            posix.close(user_fd);
            continue;
        };

        ctx.tunnel_conn.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
            std.debug.print("[REVERSE-SERVICE] Failed to send CONNECT to client: {}\n", .{err});
            ctx.tunnel_conn.handleSendFailure(err);
            posix.close(user_fd);
            continue;
        };

        // Create Stream to forward user_socket <-> tunnel
        const stream = Stream.create(global_allocator, ctx.service_id, stream_id, user_fd, ctx.tunnel_conn) catch |err| {
            std.debug.print("[REVERSE-SERVICE] Failed to create stream: {}\n", .{err});
            posix.close(user_fd);
            continue;
        };

        ctx.tunnel_conn.streams_mutex.lock();
        const key = StreamKey{ .service_id = ctx.service_id, .stream_id = stream_id };
        stream.acquireRef();
        ctx.tunnel_conn.streams.put(key, stream) catch |err| {
            ctx.tunnel_conn.streams_mutex.unlock();
            std.debug.print("[REVERSE-SERVICE] Failed to register stream: {}\n", .{err});
            stream.releaseRef(); // undo map ref
            stream.stop();
            continue;
        };
        ctx.tunnel_conn.streams_mutex.unlock();

        std.debug.print("[REVERSE-SERVICE] Stream {} created for reverse connection\n", .{stream_id});
    }

    std.debug.print("[REVERSE-SERVICE] Service listener stopped for service_id={}\n", .{ctx.service_id});
}
