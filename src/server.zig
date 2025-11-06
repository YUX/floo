const std = @import("std");
const posix = std.posix;
const build_options = @import("build_options");
const protocol = @import("protocol.zig");
const tunnel = @import("tunnel.zig");
const config = @import("config.zig");
const noise = @import("noise.zig");
const udp_server = @import("udp_server.zig");
const diagnostics = @import("diagnostics.zig");
const common = @import("common.zig");

const tracePrint = common.tracePrint;
const tcpOptionsFromConfig = common.tcpOptionsFromConfig;
const tuneSocketBuffers = common.tuneSocketBuffers;
const applyTcpOptions = common.applyTcpOptions;

const CheckStatus = diagnostics.CheckStatus;

const DEFAULT_CONFIG_PATH = "floos.toml";
const enable_stream_trace = false;
const enable_tunnel_trace = false;

var global_allocator: std.mem.Allocator = undefined;
var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var reload_config_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var config_path_global: []const u8 = undefined; // Store config path for reload
var encrypt_total_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var encrypt_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

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

/// Format network address for display (IPv4/IPv6).
/// NOTE: This function is duplicated in client.zig. Consider extracting to common.zig.
fn formatAddress(addr: std.net.Address, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{f}", .{addr}) catch "unavailable";
}

fn probeTcpTarget(host: []const u8, port: u16) !i128 {
    const addr = try std.net.Address.resolveIp(host, port);
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
            const duration = probeTcpTarget(service.target_host, service.target_port) catch |err| {
                diagnostics.reportCheck(.fail, "Service '{s}' ({}) unreachable at {s}:{d}: {}", .{
                    service.name,
                    service.service_id,
                    service.target_host,
                    service.target_port,
                    err,
                });
                had_fail = true;
                continue;
            };
            const ms = @as(f64, @floatFromInt(duration)) / @as(f64, std.time.ns_per_ms);
            diagnostics.reportCheck(.ok, "Service '{s}' ({}) reachable ({s}:{d}) - connect {d:.2} ms", .{
                service.name,
                service.service_id,
                service.target_host,
                service.target_port,
                ms,
            });
        } else {
            _ = std.net.Address.resolveIp(service.target_host, service.target_port) catch |err| {
                diagnostics.reportCheck(.fail, "Service '{s}' ({}) UDP target {s}:{d} not resolvable: {}", .{
                    service.name,
                    service.service_id,
                    service.target_host,
                    service.target_port,
                    err,
                });
                had_fail = true;
                continue;
            };
            diagnostics.reportCheck(.ok, "Service '{s}' ({}) UDP target {s}:{d} resolves successfully", .{
                service.name,
                service.service_id,
                service.target_host,
                service.target_port,
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

    if (std.ascii.eqlIgnoreCase(cfg.cipher, "none")) {
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
    if ((require_default_token or cfg.services.count() == 0) and cfg.default_token.len == 0) {
        diagnostics.reportCheck(.warn, "Default token is empty; unauthenticated clients may connect", .{});
    } else if (cfg.default_token.len > 0 and std.mem.eql(u8, cfg.default_token, config.DEFAULT_TOKEN)) {
        diagnostics.reportCheck(.warn, "Default token uses placeholder value; update to a secret", .{});
    }

    const listen_addr = std.net.Address.parseIp4(cfg.host, cfg.port) catch |err| {
        diagnostics.reportCheck(.fail, "Invalid listen address {s}:{d}: {}", .{ cfg.host, cfg.port, err });
        return false;
    };

    const listen_fd = posix.socket(listen_addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    if (listen_fd) |fd| {
        defer posix.close(fd);
        const reuse: c_int = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(reuse)) catch {};
        const bind_result = posix.bind(fd, &listen_addr.any, listen_addr.getOsSockLen());
        if (bind_result) |_| {
            diagnostics.reportCheck(.ok, "Bind check succeeded on {s}:{d}", .{ cfg.host, cfg.port });
        } else |err| {
            if (err == error.AddressInUse) {
                diagnostics.reportCheck(.warn, "Port {d} already in use on {s}", .{ cfg.port, cfg.host });
                had_fail = true;
            } else {
                diagnostics.reportCheck(.fail, "Failed to bind {s}:{d}: {}", .{ cfg.host, cfg.port, err });
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
        std.debug.print("\n[SHUTDOWN] Received interrupt, stopping server...\n", .{});
        shutdown_flag.store(true, .release);
    } else if (sig == posix.SIG.HUP) {
        std.debug.print("\n[RELOAD] Received SIGHUP, reloading configuration...\n", .{});
        reload_config_flag.store(true, .release);
    } else if (@hasDecl(posix.SIG, "USR1") and sig == posix.SIG.USR1) {
        diagnostics.flushEncryptStats("server", &encrypt_total_ns, &encrypt_calls);
    }
}

/// Represents a forwarding stream (tunnel -> target)
const Stream = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
    target_fd: posix.fd_t,
    tunnel: *TunnelConnection,
    thread: std.Thread,
    running: std.atomic.Value(bool),
    fd_closed: std.atomic.Value(bool), // Track if target_fd is closed

    fn create(allocator: std.mem.Allocator, service_id: tunnel.ServiceId, stream_id: tunnel.StreamId, target_fd: posix.fd_t, tunnel_conn: *TunnelConnection) !*Stream {
        const stream = try allocator.create(Stream);
        stream.* = .{
            .service_id = service_id,
            .stream_id = stream_id,
            .target_fd = target_fd,
            .tunnel = tunnel_conn,
            .thread = undefined,
            .running = std.atomic.Value(bool).init(true),
            .fd_closed = std.atomic.Value(bool).init(false),
        };

        // Spawn thread to handle target -> tunnel forwarding
        stream.thread = try std.Thread.spawn(.{
            .stack_size = 256 * 1024, // 256KB stack (sufficient for 64KB buffer + overhead)
        }, streamThreadMain, .{stream});

        return stream;
    }

    fn streamThreadMain(self: *Stream) void {
        var buf: [65536]u8 align(64) = undefined; // 64KB, cache-aligned (optimal size)
        var frame_buf: [70016]u8 align(64) = undefined; // Buffer for framing + tag
        const message_header_len: usize = 7;

        std.debug.print("[STREAM {}] Thread started, reading from target fd={}\n", .{ self.stream_id, self.target_fd });

        while (self.running.load(.acquire)) {
            // Blocking read from target
            const recv_slice: []u8 = if (self.tunnel.encryption_enabled) &buf else frame_buf[message_header_len..];
            const n = posix.recv(self.target_fd, recv_slice, 0) catch |err| {
                std.debug.print("[STREAM {}] recv() error: {}\n", .{ self.stream_id, err });
                break;
            };
            tracePrint(enable_stream_trace, "[STREAM {}] recv() returned {} bytes\n", .{ self.stream_id, n });
            if (n == 0) {
                std.debug.print("[STREAM {}] EOF from target, sending CLOSE\n", .{self.stream_id});
                // Send CLOSE message to peer (no allocation - use stack buffer)
                const close_msg = tunnel.CloseMsg{ .service_id = self.service_id, .stream_id = self.stream_id };

                var encode_buf: [16]u8 = undefined; // CLOSE is 7 bytes
                const encoded_len = close_msg.encodeInto(&encode_buf) catch break;
                self.tunnel.sendEncryptedMessage(encode_buf[0..encoded_len]) catch |err| {
                    self.tunnel.handleSendFailure(err);
                };
                break; // EOF
            }

            if (!self.tunnel.encryption_enabled) {
                frame_buf[0] = @intFromEnum(tunnel.MessageType.data);
                std.mem.writeInt(u16, frame_buf[1..3], self.service_id, .big);
                std.mem.writeInt(u32, frame_buf[3..7], self.stream_id, .big);

                self.tunnel.sendPlainFrame(frame_buf[0 .. message_header_len + n]) catch |err| {
                    std.debug.print("[STREAM {}] send() error: {}\n", .{ self.stream_id, err });
                    self.tunnel.handleSendFailure(err);
                    break;
                };
                continue;
            }

            // Encode DATA message directly into frame buffer
            const data_msg = tunnel.DataMsg{ .service_id = self.service_id, .stream_id = self.stream_id, .data = buf[0..n] };
            const encoded_len = data_msg.encodeInto(frame_buf[0..]) catch break;

            self.tunnel.send_mutex.lock();
            const encrypted_len = encoded_len + noise.TAG_LEN;

            if (self.tunnel.send_cipher) |*cipher| {
                const start_ns = std.time.nanoTimestamp();
                cipher.encrypt(frame_buf[0..encoded_len], frame_buf[0..encrypted_len]) catch |err| {
                    std.debug.print("[STREAM {}] Encryption error: {}\n", .{ self.stream_id, err });
                    self.tunnel.send_mutex.unlock();
                    break;
                };
                const end_ns = std.time.nanoTimestamp();
                const delta = @as(u64, @intCast(end_ns - start_ns));
                _ = encrypt_total_ns.fetchAdd(delta, .acq_rel);
                _ = encrypt_calls.fetchAdd(1, .acq_rel);
            } else {
                std.debug.print("[STREAM {}] Missing send cipher, closing stream\n", .{self.stream_id});
                self.tunnel.send_mutex.unlock();
                break;
            }

            self.tunnel.writeFrameLocked(frame_buf[0..encrypted_len]) catch |err| {
                std.debug.print("[STREAM {}] send() error: {}\n", .{ self.stream_id, err });
                self.tunnel.handleSendFailure(err);
                self.tunnel.send_mutex.unlock();
                break;
            };
            self.tunnel.send_mutex.unlock();
        }

        // Cleanup
        std.debug.print("[STREAM {}] Thread exiting\n", .{self.stream_id});

        // Atomically mark fd as closed before actually closing it
        self.fd_closed.store(true, .release);
        posix.close(self.target_fd);
    }

    fn stop(self: *Stream) void {
        self.running.store(false, .release);
        // Shutdown socket to unblock recv() call in thread (only if not already closed)
        if (!self.fd_closed.load(.acquire)) {
            posix.shutdown(self.target_fd, .recv) catch {};
        }
        self.thread.join();
    }

    fn destroy(self: *Stream) void {
        global_allocator.destroy(self);
    }
};

/// Tunnel connection handler (one per client connection)
const TunnelConnection = struct {
    tunnel_fd: posix.fd_t,
    streams: std.HashMap(StreamKey, *Stream, StreamKeyContext, 80),
    streams_mutex: std.Thread.Mutex,
    send_mutex: std.Thread.Mutex, // Protect tunnel sends from multiple stream threads
    send_cipher: ?noise.TransportCipher,
    recv_cipher: ?noise.TransportCipher,
    encryption_enabled: bool,
    decrypt_buffer: []u8,
    running: std.atomic.Value(bool),

    // Pre-allocated buffer for control messages (avoid per-frame allocation)
    control_msg_buffer: [4096]u8, // 4KB buffer for control messages (CONNECT_ACK, CLOSE, etc.)
    control_msg_mutex: std.Thread.Mutex,

    // UDP support (only one forwarder per tunnel connection)
    udp_forwarder: ?*udp_server.UdpForwarder,
    udp_service_id: ?tunnel.ServiceId,

    // Heartbeat support
    heartbeat_interval_ms: u32, // Heartbeat interval in milliseconds (0 = disabled)
    heartbeat_thread: ?std.Thread, // Heartbeat sender thread

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

            self.sendEncryptedMessage(encode_buf[0..encoded_len]) catch |err| {
                std.debug.print("[HEARTBEAT] Send error: {}\n", .{err});
                // Continue trying even if send fails
            };

            tracePrint(enable_tunnel_trace, "[HEARTBEAT] Sent at timestamp {}\n", .{timestamp});
        }

        std.debug.print("[HEARTBEAT] Thread exiting\n", .{});
    }

    fn create(allocator: std.mem.Allocator, tunnel_fd: posix.fd_t, cfg: *const config.ServerConfig, static_keypair: std.crypto.dh.X25519.KeyPair) !*TunnelConnection {
        setSockOpts(tunnel_fd, cfg);

        const encryption_enabled = !std.ascii.eqlIgnoreCase(cfg.cipher, "none");

        var tunnel_fd_owned = true;
        errdefer if (tunnel_fd_owned) posix.close(tunnel_fd);

        var send_cipher: ?noise.TransportCipher = null;
        var recv_cipher: ?noise.TransportCipher = null;
        var decrypt_buffer: []u8 = &[_]u8{};
        errdefer if (decrypt_buffer.len != 0) allocator.free(decrypt_buffer);

        if (encryption_enabled) {
            const cipher_type = noise.CipherType.fromString(cfg.cipher) catch .chacha20poly1305;

            // Perform Noise_XX handshake (server is responder, uses persistent static key)
            const handshake = noise.noiseXXHandshake(tunnel_fd, cipher_type, false, static_keypair, cfg.psk) catch |err| switch (err) {
                error.MissingPsk => {
                    std.debug.print("[NOISE] PSK must be configured when encryption is enabled\n", .{});
                    return err;
                },
                else => return error.HandshakeFailed,
            };

            send_cipher = handshake.send_cipher;
            recv_cipher = handshake.recv_cipher;

            decrypt_buffer = try allocator.alloc(u8, protocol.MAX_FRAME_SIZE);
        }

        const conn = try allocator.create(TunnelConnection);

        // Initialize struct with cipher state
        conn.* = .{
            .tunnel_fd = tunnel_fd,
            .streams = std.HashMap(StreamKey, *Stream, StreamKeyContext, 80).init(allocator),
            .streams_mutex = .{},
            .send_mutex = .{},
            .send_cipher = send_cipher,
            .recv_cipher = recv_cipher,
            .encryption_enabled = encryption_enabled,
            .decrypt_buffer = decrypt_buffer,
            .running = std.atomic.Value(bool).init(true),
            .control_msg_buffer = undefined, // Pre-allocated buffer for control messages
            .control_msg_mutex = .{},
            .udp_forwarder = null,
            .udp_service_id = null,
            .heartbeat_interval_ms = cfg.heartbeat_interval_seconds * 1000, // Convert to milliseconds
            .heartbeat_thread = null,
            .cfg = cfg,
        };
        tunnel_fd_owned = false;
        decrypt_buffer = &[_]u8{};

        // Spawn heartbeat thread if enabled
        if (conn.heartbeat_interval_ms > 0) {
            conn.heartbeat_thread = std.Thread.spawn(.{}, heartbeatThreadMain, .{conn}) catch |err| {
                conn.destroy();
                return err;
            };
            std.debug.print("[TUNNEL] Heartbeat enabled: sending every {} seconds\n", .{cfg.heartbeat_interval_seconds});
        }

        return conn;
    }

    fn setSockOpts(fd: posix.fd_t, cfg: *const config.ServerConfig) void {
        applyTcpOptions(fd, tcpOptionsFromConfig(cfg));
        tuneSocketBuffers(fd, cfg.socket_buffer_size);
    }

    fn run(self: *TunnelConnection) void {
        var buf: [256 * 1024]u8 align(64) = undefined; // 256KB for better batching
        var decoder = protocol.FrameDecoder.init(global_allocator);
        defer decoder.deinit();

        // Check if decoder buffer was allocated
        if (decoder.buffer.len == 0) {
            std.debug.print("[TUNNEL] Failed to allocate decoder buffer!\n", .{});
            return;
        }

        std.debug.print("[TUNNEL] Connection handler started (buffer size: {})\n", .{decoder.buffer.len});

        while (self.running.load(.acquire) and !shutdown_flag.load(.acquire)) {
            // Blocking read from tunnel
            const n = posix.recv(self.tunnel_fd, &buf, 0) catch |err| {
                std.debug.print("[TUNNEL] Recv error: {}\n", .{err});
                break;
            };

            if (n == 0) {
                std.debug.print("[TUNNEL] Client disconnected\n", .{});
                break;
            }

            tracePrint(enable_tunnel_trace, "[TUNNEL] Received {} bytes from client\n", .{n});

            // Feed decoder
            decoder.feed(buf[0..n]) catch |err| {
                std.debug.print("[TUNNEL] Decoder feed error: {}\n", .{err});
                break;
            };

            // Process all complete frames
            while (decoder.decode() catch null) |frame_payload| {
                self.handleMessage(frame_payload) catch |err| {
                    std.debug.print("[TUNNEL] Handle message error: {}\n", .{err});
                    self.running.store(false, .release);
                    break;
                };
                if (!self.running.load(.acquire)) break;
            }

            if (!self.running.load(.acquire)) break;
        }

        std.debug.print("[TUNNEL] Connection handler stopping\n", .{});
        self.cleanup();
        self.running.store(false, .release);
    }

    fn handleMessage(self: *TunnelConnection, payload: []const u8) !void {
        if (payload.len == 0) return;

        var message_slice: []const u8 = payload;

        if (self.encryption_enabled) {
            if (payload.len < noise.TAG_LEN) return error.InvalidPayload;

            const decrypted_len = payload.len - noise.TAG_LEN;
            if (decrypted_len > self.decrypt_buffer.len) {
                return error.InvalidPayload;
            }

            // Decrypt with atomic nonce (no mutex needed) - use pointer capture
            const target = self.decrypt_buffer[0..decrypted_len];
            if (self.recv_cipher) |*cipher| {
                cipher.decrypt(payload, target) catch |err| {
                    std.debug.print("[TUNNEL] Decryption error: {} (len={})\n", .{ err, payload.len });
                    return err;
                };
            } else return error.CipherUnavailable;

            message_slice = target;
        }

        if (message_slice.len == 0) return;

        const msg_type: tunnel.MessageType = @enumFromInt(message_slice[0]);

        switch (msg_type) {
            .connect => {
                const connect_msg = try tunnel.ConnectMsg.decode(message_slice, global_allocator);
                defer global_allocator.free(connect_msg.target_host);
                defer global_allocator.free(connect_msg.token);

                tracePrint(enable_tunnel_trace, "[TUNNEL] CONNECT request: stream_id={} target={s}:{}\n", .{ connect_msg.stream_id, connect_msg.target_host, connect_msg.target_port });

                self.handleConnect(connect_msg) catch |err| {
                    std.debug.print("[TUNNEL] Failed to connect: {}\n", .{err});
                    // Send error response (no allocation - use stack buffer)
                    const error_msg = tunnel.ConnectErrorMsg{
                        .service_id = connect_msg.service_id,
                        .stream_id = connect_msg.stream_id,
                        .error_msg = "Connection failed",
                    };

                    var encode_buf: [128]u8 = undefined; // ERROR message with text
                    const encoded_len = error_msg.encodeInto(&encode_buf) catch return;

                    self.sendEncryptedMessage(encode_buf[0..encoded_len]) catch |send_err| {
                        self.handleSendFailure(send_err);
                    };
                };
            },
            .data => {
                const data_msg = try tunnel.DataMsg.decode(message_slice);

                self.streams_mutex.lock();
                const key = StreamKey{ .service_id = data_msg.service_id, .stream_id = data_msg.stream_id };
                const stream = self.streams.get(key);
                self.streams_mutex.unlock();

                if (stream) |s| {
                    // Check if fd is still valid before sending
                    if (!s.fd_closed.load(.acquire)) {
                        // Forward to target (loop until all data sent)
                        sendAllToFd(s.target_fd, data_msg.data) catch |err| {
                            std.debug.print("[STREAM {}] Send to target failed: {}\n", .{ data_msg.stream_id, err });
                        };
                    }
                }
            },
            .close => {
                const close_msg = try tunnel.CloseMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[TUNNEL] CLOSE service_id={} stream_id={}\n", .{ close_msg.service_id, close_msg.stream_id });

                self.streams_mutex.lock();
                const key = StreamKey{ .service_id = close_msg.service_id, .stream_id = close_msg.stream_id };
                const maybe_stream = self.streams.fetchRemove(key);
                self.streams_mutex.unlock();

                if (maybe_stream) |entry| {
                    entry.value.stop();
                    entry.value.destroy();
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
            .heartbeat => {
                // Server doesn't need to process heartbeat responses from client
                // (client -> server heartbeat is handled by client-side timeout logic)
                const heartbeat_msg = try tunnel.HeartbeatMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[HEARTBEAT] Received from client: timestamp={}\n", .{heartbeat_msg.timestamp});
            },
            else => {
                std.debug.print("[TUNNEL] Unknown message type: {}\n", .{msg_type});
            },
        }
    }

    fn handleConnect(self: *TunnelConnection, msg: tunnel.ConnectMsg) !void {
        const service_ptr = self.cfg.getService(msg.service_id) orelse {
            std.debug.print("[AUTH] Unknown service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
            return error.UnknownService;
        };
        const service = service_ptr.*;

        const expected_token = if (service.token.len > 0) service.token else self.cfg.default_token;
        if (expected_token.len > 0) {
            if (!std.mem.eql(u8, msg.token, expected_token)) {
                std.debug.print("[AUTH] Invalid token for service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
                return error.AuthenticationFailed;
            }
            std.debug.print("[AUTH] Token validated for service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
        }

        if (!std.mem.eql(u8, msg.target_host, service.target_host) or msg.target_port != service.target_port) {
            std.debug.print("[AUTH] Client target override ignored for service_id={} stream_id={}\n", .{ msg.service_id, msg.stream_id });
        }

        switch (service.transport) {
            .tcp => {
                const address = try std.net.Address.parseIp4(service.target_host, service.target_port);
                const target_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
                errdefer posix.close(target_fd);

                setSockOpts(target_fd, self.cfg);

                try posix.connect(target_fd, &address.any, address.getOsSockLen());

                tracePrint(enable_stream_trace, "[STREAM {}] Connected to {s}:{}\n", .{ msg.stream_id, service.target_host, service.target_port });

                const stream = try Stream.create(global_allocator, msg.service_id, msg.stream_id, target_fd, self);

                self.streams_mutex.lock();
                const key = StreamKey{ .service_id = msg.service_id, .stream_id = msg.stream_id };
                self.streams.put(key, stream) catch |err| {
                    self.streams_mutex.unlock();
                    stream.stop();
                    stream.destroy();
                    return err;
                };
                self.streams_mutex.unlock();
            },
            .udp => {
                if (self.udp_forwarder == null) {
                    std.debug.print("[UDP] Creating UDP forwarder for target {s}:{}\n", .{ service.target_host, service.target_port });

                    const forwarder = try udp_server.UdpForwarder.create(
                        global_allocator,
                        service.target_host,
                        service.target_port,
                        @ptrCast(self),
                        sendEncryptedMessageWrapper,
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

        try self.sendEncryptedMessage(encode_buf[0..encoded_len]);
    }

    // Wrapper for UDP forwarder callback (converts opaque pointer back to TunnelConnection)
    fn sendEncryptedMessageWrapper(conn: *anyopaque, payload: []const u8) anyerror!void {
        const self: *TunnelConnection = @ptrCast(@alignCast(conn));
        try self.sendEncryptedMessage(payload);
    }

    /// Send plaintext frame (framing only, no encryption).
    /// NOTE: Similar implementation exists in client.zig. Consider unifying.
    fn sendPlainFrame(self: *TunnelConnection, payload: []const u8) !void {
        self.send_mutex.lock();
        const send_result = self.writeFrameLocked(payload);
        self.send_mutex.unlock();
        send_result catch |err| {
            self.handleSendFailure(err);
            return err;
        };
    }

    fn handleSendFailure(self: *TunnelConnection, err: anyerror) void {
        if (!self.running.load(.acquire)) return;
        std.debug.print("[TUNNEL] Send failure: {}\n", .{err});
        self.running.store(false, .release);
        posix.shutdown(self.tunnel_fd, .both) catch {};
    }

    /// Send all data to a file descriptor, looping until complete.
    /// This handles partial writes correctly (blocking sockets can still short-write).
    /// NOTE: This function is duplicated in client.zig. Consider extracting to common.zig.
    fn sendAllToFd(fd: posix.fd_t, data: []const u8) !void {
        var offset: usize = 0;
        while (offset < data.len) {
            const n = posix.send(fd, data[offset..], 0) catch |err| return err;
            if (n == 0) return error.ConnectionClosed;
            offset += n;
        }
    }

    /// Write length-prefixed frame using writev() for scatter-gather I/O.
    /// NOTE: This function is duplicated in client.zig. Consider extracting to common.zig.
    fn writeFrameLocked(self: *TunnelConnection, payload: []const u8) !void {
        var header: [4]u8 = undefined;
        std.mem.writeInt(u32, header[0..4], @intCast(payload.len), .big);

        var iovecs = [_]posix.iovec_const{
            posix.iovec_const{ .base = header[0..].ptr, .len = header.len },
            posix.iovec_const{ .base = payload.ptr, .len = payload.len },
        };

        var index: usize = 0;
        while (index < iovecs.len) {
            const written = posix.writev(self.tunnel_fd, iovecs[index..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (written == 0) return error.ConnectionClosed;

            var remaining = written;
            var current = index;
            while (remaining > 0 and current < iovecs.len) {
                if (remaining >= iovecs[current].len) {
                    remaining -= iovecs[current].len;
                    current += 1;
                } else {
                    iovecs[current].base += remaining;
                    iovecs[current].len -= remaining;
                    remaining = 0;
                }
            }
            index = current;
        }
    }

    /// Encrypt a message payload and send it with frame length prefix.
    /// NOTE: Similar implementation exists in client.zig. Consider unifying.
    fn sendEncryptedMessage(self: *TunnelConnection, payload: []const u8) !void {
        if (!self.encryption_enabled) {
            try self.sendPlainFrame(payload);
            return;
        }

        self.control_msg_mutex.lock();
        defer self.control_msg_mutex.unlock();

        const encrypted_len = payload.len + noise.TAG_LEN;
        if (encrypted_len > self.control_msg_buffer.len) {
            return error.ControlMessageTooLarge;
        }

        @memcpy(self.control_msg_buffer[0..payload.len], payload);

        if (self.send_cipher) |*cipher| {
            const start_ns = std.time.nanoTimestamp();
            cipher.encrypt(self.control_msg_buffer[0..payload.len], self.control_msg_buffer[0..encrypted_len]) catch |err| {
                return err;
            };
            const end_ns = std.time.nanoTimestamp();
            const delta = @as(u64, @intCast(end_ns - start_ns));
            _ = encrypt_total_ns.fetchAdd(delta, .acq_rel);
            _ = encrypt_calls.fetchAdd(1, .acq_rel);
        } else {
            return error.CipherUnavailable;
        }

        self.send_mutex.lock();
        const send_result = self.writeFrameLocked(self.control_msg_buffer[0..encrypted_len]);
        self.send_mutex.unlock();
        send_result catch |err| {
            self.handleSendFailure(err);
            return err;
        };
    }

    fn cleanup(self: *TunnelConnection) void {
        // Stop heartbeat thread first
        if (self.heartbeat_thread) |thread| {
            self.running.store(false, .release); // Signal thread to stop
            thread.join();
        }

        // Stop all streams
        self.streams_mutex.lock();
        var it = self.streams.valueIterator();
        while (it.next()) |stream| {
            stream.*.stop();
        }
        self.streams_mutex.unlock();

        // Wait for streams and destroy
        self.streams_mutex.lock();
        var it2 = self.streams.valueIterator();
        while (it2.next()) |stream| {
            stream.*.destroy();
        }
        self.streams.deinit();
        self.streams_mutex.unlock();

        if (self.udp_forwarder) |forwarder| {
            forwarder.stop();
            forwarder.destroy();
            self.udp_forwarder = null;
            self.udp_service_id = null;
        }

        if (self.decrypt_buffer.len > 0) {
            global_allocator.free(self.decrypt_buffer);
            self.decrypt_buffer = &[_]u8{};
        }

        posix.close(self.tunnel_fd);
    }

    fn destroy(self: *TunnelConnection) void {
        // Cleanup UDP forwarder if exists
        if (self.udp_forwarder) |forwarder| {
            forwarder.stop();
            forwarder.destroy();
            self.udp_forwarder = null;
            self.udp_service_id = null;
        }

        if (self.decrypt_buffer.len > 0) {
            global_allocator.free(self.decrypt_buffer);
        }
        global_allocator.destroy(self);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    global_allocator = allocator;
    defer diagnostics.flushEncryptStats("server", &encrypt_total_ns, &encrypt_calls);

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

    if (std.ascii.eqlIgnoreCase(cfg.cipher, "none")) {
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

    if (default_token_required and cfg.default_token.len == 0) {
        std.debug.print("[WARN] Server default token is empty; unauthorized clients may connect.\n", .{});
    } else if (cfg.default_token.len > 0 and std.mem.eql(u8, cfg.default_token, config.DEFAULT_TOKEN)) {
        std.debug.print("[WARN] Server is using the placeholder token '{s}'. Change this before deployment.\n", .{config.DEFAULT_TOKEN});
    }

    std.debug.print("Floo Tunnel Server (floos-blocking)\n", .{});
    std.debug.print("====================================\n\n", .{});
    std.debug.print("[CONFIG] Port: {}\n", .{port});
    std.debug.print("[CONFIG] Mode: Blocking I/O + Threads\n", .{});
    std.debug.print("[CONFIG] Hot Reload: Enabled (send SIGHUP to reload)\n\n", .{});

    // Register signal handlers (POSIX only)
    if (@hasDecl(posix, "Sigaction") and @hasDecl(posix, "sigaction")) {
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
    }

    // Create listen socket
    const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(listen_fd);

    try posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    const address = try std.net.Address.parseIp4("0.0.0.0", port);
    try posix.bind(listen_fd, &address.any, address.getOsSockLen());
    try posix.listen(listen_fd, 128);

    std.debug.print("[SERVER] Listening on 0.0.0.0:{}\n", .{port});
    std.debug.print("[READY] Server ready. Press Ctrl+C to stop.\n\n", .{});

    // Generate persistent static keypair for Noise XX authentication
    const static_keypair = std.crypto.dh.X25519.KeyPair.generate();

    const ConnectionEntry = struct {
        conn: *TunnelConnection,
        thread: std.Thread,
    };
    var connections = std.ArrayListUnmanaged(ConnectionEntry){};
    defer {
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

    // Accept loop
    while (!shutdown_flag.load(.acquire)) {
        // Check for config reload request
        if (reload_config_flag.load(.acquire)) {
            reload_config_flag.store(false, .release);

            std.debug.print("[RELOAD] Reloading configuration from {s}...\n", .{config_path_global});

            // Reload config file
            const new_cfg = config.ServerConfig.loadFromFile(allocator, config_path_global) catch |err| {
                std.debug.print("[RELOAD] Failed to reload config: {} - keeping current config\n", .{err});
                continue;
            };

            // Update config (new connections will use new settings)
            cfg.deinit();
            cfg = new_cfg;
            applyServerOverrides(&cfg, &cli_opts);

            std.debug.print("[RELOAD] Configuration reloaded successfully!\n", .{});
            std.debug.print("[RELOAD] Heartbeat interval: {}s\n", .{cfg.heartbeat_interval_seconds});
            std.debug.print("[RELOAD] TCP tuning: nodelay={} keepalive={}\n", .{ cfg.tcp_nodelay, cfg.tcp_keepalive });
            std.debug.print("[RELOAD] Existing tunnels will be closed so new policy takes effect.\n", .{});

            for (connections.items) |entry| {
                entry.conn.running.store(false, .release);
                posix.shutdown(entry.conn.tunnel_fd, .recv) catch {};
            }
        }

        // Reap completed connections
        var idx: usize = 0;
        while (idx < connections.items.len) {
            const entry = connections.items[idx];
            if (!entry.conn.running.load(.acquire)) {
                entry.thread.join();
                entry.conn.destroy();
                _ = connections.swapRemove(idx);
                continue;
            }
            idx += 1;
        }

        // Accept with timeout (poll for shutdown and reload)
        var fds = [_]posix.pollfd{
            .{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 },
        };

        const ready = posix.poll(&fds, 1000) catch continue; // 1s timeout
        if (ready == 0) continue; // Timeout, check flags

        const tunnel_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
            std.debug.print("[SERVER] Accept error: {}\n", .{err});
            continue;
        };

        std.debug.print("[SERVER] Accepted tunnel connection: fd={}\n", .{tunnel_fd});
        tuneSocketBuffers(tunnel_fd, cfg.socket_buffer_size);
        applyTcpOptions(tunnel_fd, tcpOptionsFromConfig(&cfg));

        // Create tunnel connection (shares static identity across all connections)
        const tunnel_conn = TunnelConnection.create(allocator, tunnel_fd, &cfg, static_keypair) catch |err| {
            std.debug.print("[SERVER] Failed to create tunnel: {}\n", .{err});
            posix.close(tunnel_fd);
            continue;
        };

        // Spawn thread for this connection
        const thread = try std.Thread.spawn(.{
            .stack_size = 512 * 1024, // 512KB stack (sufficient for 256KB buffer + overhead)
        }, tunnelConnectionThread, .{tunnel_conn});

        connections.append(allocator, .{ .conn = tunnel_conn, .thread = thread }) catch |err| {
            std.debug.print("[SERVER] Failed to track connection: {}\n", .{err});
            tunnel_conn.running.store(false, .release);
            posix.shutdown(tunnel_conn.tunnel_fd, .recv) catch {};
            thread.join();
            tunnel_conn.destroy();
            continue;
        };
    }

    std.debug.print("\n[SHUTDOWN] Server stopped.\n", .{});
}

fn tunnelConnectionThread(conn: *TunnelConnection) void {
    conn.run();
    // Note: conn.destroy() is called by main thread on shutdown
}
