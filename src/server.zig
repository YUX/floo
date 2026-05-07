const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const build_options = @import("build_options");
const protocol = @import("protocol.zig");
const tunnel = @import("tunnel.zig");
const config = @import("config.zig");
const noise = @import("noise.zig");
const udp_server = @import("udp_server.zig");
const diagnostics = @import("diagnostics.zig");
const common = @import("common.zig");
const transport = @import("transport/channel.zig");

const tracePrint = common.tracePrint;
const tcpOptionsFromSettings = common.tcpOptionsFromSettings;
const tuneSocketBuffers = common.tuneSocketBuffers;
const applyTcpOptions = common.applyTcpOptions;
const formatAddress = common.formatAddress;

const CheckStatus = diagnostics.CheckStatus;

const DEFAULT_CONFIG_PATH = "floos.toml";
const enable_stream_trace = false;
const enable_tunnel_trace = false;

var global_allocator: std.mem.Allocator = undefined;
var global_io: std.Io = undefined;
var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var config_path_global: []const u8 = undefined; // Store config path for reload
var encrypt_total_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var encrypt_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_tx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_rx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var flush_stats_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Per-process gate for the encryption time profile.  Resolved on first
/// read into module-scope statics so we don't hit `getenv` per
/// Channel.init.  Set `FLOO_PROFILE_ENCRYPT=1` in the environment to
/// opt in.
var encrypt_profile_checked: std.atomic.Value(bool) = .init(false);
var encrypt_profile_value: bool = false;

fn encrypt_profile_enabled() bool {
    if (!encrypt_profile_checked.load(.acquire)) {
        const cstr = std.c.getenv("FLOO_PROFILE_ENCRYPT");
        encrypt_profile_value = if (cstr) |c| (c[0] != 0 and c[0] != '0') else false;
        encrypt_profile_checked.store(true, .release);
        std.debug.print("[PROFILE] encrypt-time profile {s}\n", .{if (encrypt_profile_value) "ENABLED via FLOO_PROFILE_ENCRYPT" else "disabled (set FLOO_PROFILE_ENCRYPT=1 to enable)"});
    }
    return encrypt_profile_value;
}
var sighup_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var cpu_assigner: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var cached_cpu_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

// Signal-pipe stubs (kept as no-ops so call sites in main don't have to gate).
// Zig 0.16 removed posix.pipe2; the self-pipe optimization is gone. Signals
// now just set atomic flags that the next 1s poll iteration picks up.
fn setupSignalPipe() !void {}
fn cleanupSignalPipe() void {}
fn drainSignalPipe() void {}
fn notifySignalPipe(sig: c_int) void {
    _ = sig;
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
    // cpu_set_t is an array of ulongs, zero it manually since CPU_ZERO macro not available
    var mask: linux.cpu_set_t = [_]c_ulong{0} ** 16;
    // Set the bit for this CPU (cpu_set_t is bit array)
    const limited = cpu_index % (16 * @bitSizeOf(c_ulong));
    const word_idx = limited / @bitSizeOf(c_ulong);
    const bit_idx = limited % @bitSizeOf(c_ulong);
    mask[word_idx] |= @as(c_ulong, 1) << @intCast(bit_idx);
    // sched_setaffinity in Zig takes (pid, mask_ptr) - size is implicit
    _ = linux.sched_setaffinity(0, &mask) catch {};
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

fn parseServerArgs(args_list: []const [:0]const u8, ctx: *ParseContext) ParseError!CliOptions {
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
    var cfg = try config.ServerConfig.loadFromFile(allocator, global_io, opts.config_path);
    errdefer cfg.deinit();
    applyServerOverrides(&cfg, opts);
    return cfg;
}

fn probeTcpTarget(host: []const u8, port: u16) !i128 {
    const addr = try common.resolveHostPort(global_io, host, port);
    const start = common.nanoTimestamp();
    var stream = addr.connect(global_io, .{ .mode = .stream }) catch |err| return err;
    const done = common.nanoTimestamp();
    stream.close(global_io);
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
            _ = common.resolveHostPort(global_io, service.address, service.port) catch |err| {
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
    Io.Dir.cwd().access(global_io, opts.config_path, .{}) catch {
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

    const listen_addr = common.resolveHostPort(global_io, cfg.bind, cfg.port) catch |err| {
        diagnostics.reportCheck(.fail, "Invalid listen address {s}:{d}: {}", .{ cfg.bind, cfg.port, err });
        return false;
    };

    const probe_listen = listen_addr.listen(global_io, .{ .reuse_address = true });
    if (probe_listen) |srv| {
        var srv_mut = srv;
        defer srv_mut.deinit(global_io);
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

fn handleSignal(sig: posix.SIG) callconv(.c) void {
    if (sig == posix.SIG.INT or sig == posix.SIG.TERM) {
        shutdown_flag.store(true, .release);
    } else if (@hasDecl(posix.SIG, "HUP") and sig == posix.SIG.HUP) {
        sighup_requested.store(true, .release);
    } else if (@hasDecl(posix.SIG, "USR1") and sig == posix.SIG.USR1) {
        flush_stats_requested.store(true, .release);
    }
    if (builtin.target.os.tag != .windows) {
        notifySignalPipe(@intCast(@intFromEnum(sig)));
    }
}

/// Reverse service listener - accepts connections and forwards through tunnel to client
const ReverseListener = struct {
    allocator: std.mem.Allocator,
    service: config.Service,
    server: Io.net.Server,
    thread: std.Thread,
    running: std.atomic.Value(bool),
    tunnel_conn: *TunnelConnection,
    thread_joined: std.atomic.Value(bool),

    fn create(
        allocator: std.mem.Allocator,
        service: config.Service,
        tunnel_conn: *TunnelConnection,
    ) !*ReverseListener {
        const addr = try common.resolveHostPort(global_io, service.address, service.port);
        // Reverse listeners are rebound on every tunnel reconnect — must NOT
        // use addr.listen(.reuse_address=true) which sets SO_REUSEPORT on POSIX
        // and lets the kernel load-balance to a stale listener mid-rebind.
        var server = try common.bindListener(addr, common.LISTEN_BACKLOG);
        errdefer server.deinit(global_io);

        const listener = try allocator.create(ReverseListener);
        listener.* = .{
            .allocator = allocator,
            .service = service,
            .server = server,
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

            const client_stream = self.server.accept(global_io) catch |err| {
                if (!self.running.load(.acquire)) break;
                if (err == error.SocketNotListening) break;
                if (err == error.WouldBlock or err == error.ConnectionAborted) continue;
                std.debug.print("[REVERSE] accept error: {}\n", .{err});
                continue;
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
                client_stream.close(global_io);
                continue;
            };

            self.tunnel_conn.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
                std.debug.print("[REVERSE] Failed to send REVERSE_CONNECT: {}\n", .{err});
                client_stream.close(global_io);
                continue;
            };

            std.debug.print("[REVERSE] Sent REVERSE_CONNECT service_id={} stream_id={}\n", .{ self.service.id, stream_id });

            // Create Stream for this connection
            const stream = Stream.create(self.allocator, self.service.id, stream_id, client_stream, self.tunnel_conn) catch |err| {
                std.debug.print("[REVERSE] Failed to create stream: {}\n", .{err});
                client_stream.close(global_io);
                continue;
            };

            // Add stream to tunnel's streams map (CRITICAL for reverse routing).
            // The create ref IS the map ref — no extra acquireRef. On put failure,
            // explicit releaseRef takes the count to 0 and destroys the stream.
            const key = StreamKey{ .service_id = self.service.id, .stream_id = stream_id };
            self.tunnel_conn.streams_mutex.lock();
            defer self.tunnel_conn.streams_mutex.unlock();

            self.tunnel_conn.streams.put(key, stream) catch |err| {
                std.debug.print("[REVERSE] Failed to register stream: {}\n", .{err});
                stream.stop();
                stream.releaseRef(); // drop create ref → destroys
                continue;
            };
            // Bump generation so the recv-loop poll-rebuild caches invalidate.
            _ = self.tunnel_conn.streams_generation.fetchAdd(1, .acq_rel);

            std.debug.print("[REVERSE] Stream {} registered and ready\n", .{stream_id});
        }

        std.debug.print("[REVERSE] Acceptor thread for {s}:{} exiting\n", .{ self.service.address, self.service.port });
    }

    fn stop(self: *ReverseListener) void {
        if (self.thread_joined.swap(true, .acq_rel)) return;
        self.running.store(false, .release);
        // Shutting down the server's underlying socket unblocks accept().
        _ = posix.system.shutdown(self.server.socket.handle, posix.SHUT.RD);
        self.thread.join();
        self.server.deinit(global_io);
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

/// Consolidated heartbeat ticker — one thread for the whole process, not one
/// per active tunnel connection. Audit P1-4: with N concurrent clients on a
/// 30s heartbeat interval, the previous design woke (N × 10) times/second
/// (each thread sleeping in 100ms increments to honor shutdown) just to send
/// 0.033 × N heartbeats/second. Now: one thread, one wakeup per 100ms,
/// regardless of N.
///
/// Lifecycle: register on TunnelConnection.create when heartbeat is enabled;
/// unregister on TunnelConnection.cleanup. The ticker thread is spawned
/// lazily on the first registration and joined once at process shutdown
/// (heartbeat_ticker.shutdown in main).
///
/// Concurrency: register / unregister / iteration all hold the same mutex.
/// During iteration the ticker calls conn.channel.sendCopy under the lock,
/// which prevents an unregister-and-destroy race (a conn unregistering
/// blocks until any in-flight iteration that observed it completes). Cost:
/// register / unregister are paused for the duration of one heartbeat
/// dispatch round (microseconds in the common case, bounded by per-conn
/// send_mutex contention in the worst case).
const HeartbeatEntry = struct {
    conn: *TunnelConnection,
    elapsed_ms: u32,
};

const HeartbeatTicker = struct {
    mutex: std.Io.Mutex = .init,
    entries: std.ArrayListUnmanaged(HeartbeatEntry) = .empty,
    thread: ?std.Thread = null,

    fn ensureRunning(self: *HeartbeatTicker) !void {
        // Caller holds mutex.
        if (self.thread != null) return;
        self.thread = try std.Thread.spawn(
            .{ .stack_size = common.DEFAULT_THREAD_STACK },
            tickerMain,
            .{self},
        );
        std.debug.print("[HEARTBEAT] Ticker started\n", .{});
    }

    pub fn register(self: *HeartbeatTicker, conn: *TunnelConnection) !void {
        self.mutex.lockUncancelable(global_io);
        defer self.mutex.unlock(global_io);
        try self.entries.append(global_allocator, .{ .conn = conn, .elapsed_ms = 0 });
        try self.ensureRunning();
    }

    pub fn unregister(self: *HeartbeatTicker, conn: *TunnelConnection) void {
        self.mutex.lockUncancelable(global_io);
        defer self.mutex.unlock(global_io);
        var i: usize = 0;
        while (i < self.entries.items.len) : (i += 1) {
            if (self.entries.items[i].conn == conn) {
                _ = self.entries.swapRemove(i);
                return;
            }
        }
    }

    /// Join the ticker thread and free entry storage. Called once at
    /// process shutdown after all TunnelConnections have been unregistered.
    pub fn shutdownAndJoin(self: *HeartbeatTicker) void {
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.mutex.lockUncancelable(global_io);
        defer self.mutex.unlock(global_io);
        self.entries.deinit(global_allocator);
    }

    fn tickerMain(self: *HeartbeatTicker) void {
        const tick_ms: u32 = 100;
        while (!shutdown_flag.load(.acquire)) {
            const ns = @as(u64, tick_ms) * std.time.ns_per_ms;
            Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};

            // Iterate under lock so unregister can't pull the rug out
            // mid-dispatch. sendCopy is held in the critical section,
            // bounded by the per-conn channel send_mutex.
            self.mutex.lockUncancelable(global_io);
            for (self.entries.items) |*entry| {
                entry.elapsed_ms +%= tick_ms;
                if (entry.elapsed_ms >= entry.conn.heartbeat_interval_ms) {
                    entry.elapsed_ms = 0;
                    if (!entry.conn.running.load(.acquire)) continue;
                    sendHeartbeatTo(entry.conn);
                }
            }
            self.mutex.unlock(global_io);
        }
        std.debug.print("[HEARTBEAT] Ticker exiting\n", .{});
    }
};

fn sendHeartbeatTo(conn: *TunnelConnection) void {
    const timestamp = common.milliTimestamp();
    const heartbeat_msg = tunnel.HeartbeatMsg{ .timestamp = timestamp };
    var encode_buf: [16]u8 = undefined; // Heartbeat is 9 bytes
    const encoded_len = heartbeat_msg.encodeInto(&encode_buf) catch return;
    conn.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
        std.debug.print("[HEARTBEAT] Send error to conn: {}\n", .{err});
    };
}

var heartbeat_ticker: HeartbeatTicker = .{};

/// Represents a forwarding stream (tunnel -> target)
const Stream = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
    target_stream: Io.net.Stream,
    tunnel: *TunnelConnection,
    fd_closed: std.atomic.Value(bool), // Track if target_stream is closed
    ref_count: std.atomic.Value(usize),
    frame_buffer: []u8,

    fn create(allocator: std.mem.Allocator, service_id: tunnel.ServiceId, stream_id: tunnel.StreamId, target_stream: Io.net.Stream, tunnel_conn: *TunnelConnection) !*Stream {
        const io_batch = tunnel_conn.cfg.advanced.io_batch_bytes;

        const header_len: usize = 7;
        const frame_capacity = header_len + io_batch + noise.TAG_LEN + 32;
        const frame_buffer = try allocator.alignedAlloc(u8, .@"64", frame_capacity);
        errdefer allocator.free(frame_buffer);

        const stream = try allocator.create(Stream);
        stream.* = .{
            .service_id = service_id,
            .stream_id = stream_id,
            .target_stream = target_stream,
            .tunnel = tunnel_conn,
            .fd_closed = std.atomic.Value(bool).init(false),
            .ref_count = std.atomic.Value(usize).init(1),
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
        if (self.frame_buffer.len > 0) global_allocator.free(self.frame_buffer);
        global_allocator.destroy(self);
    }

    fn stop(self: *Stream) void {
        if (!self.fd_closed.swap(true, .acq_rel)) {
            self.target_stream.close(global_io);
        }
    }

    /// Raw fd accessor for poll() and posix.read on the data path.
    fn handle(self: *const Stream) posix.fd_t {
        return self.target_stream.socket.handle;
    }
};

/// Tunnel connection handler (one per client connection)
const TunnelConnection = struct {
    tunnel_stream: Io.net.Stream,
    /// Caller-owned buffers backing the stream Reader/Writer the channel uses.
    /// Sized for the largest pre-encrypt control frame plus framing slack.
    tunnel_reader_buf: [8192]u8,
    tunnel_writer_buf: [8192]u8,
    tunnel_reader: Io.net.Stream.Reader,
    tunnel_writer: Io.net.Stream.Writer,
    streams: std.HashMap(StreamKey, *Stream, StreamKeyContext, 80),
    /// common.HotMutex (os_unfair_lock on Darwin, raw futex on Linux)
    /// instead of Io.Mutex; see transport/Channel.send_mutex for
    /// rationale. Held briefly per recv-DATA, send-DATA, CONNECT, CLOSE
    /// — every cycle of the data path.
    streams_mutex: common.HotMutex,
    /// Generation counter bumped under `streams_mutex` on every insert
    /// or remove from `streams`.  The recv-loop poll-rebuild path
    /// caches its `poll_fds` array and only rebuilds when this counter
    /// changes — see audit P-1 for the rationale.  `.acq_rel` so the
    /// reader (poll loop, no lock) sees the structural state of `streams`
    /// that produced the new value.
    streams_generation: std.atomic.Value(u64),
    channel: transport.Channel,
    running: std.atomic.Value(bool),

    // UDP support (only one forwarder per tunnel connection)
    udp_forwarder: ?*udp_server.UdpForwarder,
    udp_service_id: ?tunnel.ServiceId,

    // Heartbeat support
    heartbeat_interval_ms: u32, // Heartbeat interval in milliseconds (0 = disabled)

    // Stream ID allocation for reverse services
    next_stream_id: std.atomic.Value(u32),

    // Config reference for TCP tuning
    cfg: *const config.ServerConfig,

    fn create(allocator: std.mem.Allocator, tunnel_stream: Io.net.Stream, cfg: *const config.ServerConfig, static_keypair: std.crypto.dh.X25519.KeyPair) !*TunnelConnection {
        setSockOpts(tunnel_stream.socket.handle, cfg);

        const canonical_cipher = config.canonicalCipher(cfg);

        var stream_owned = true;
        errdefer if (stream_owned) tunnel_stream.close(global_io);

        // Allocate first so reader/writer can self-reference into stable storage.
        const conn = try allocator.create(TunnelConnection);
        errdefer allocator.destroy(conn);

        conn.* = .{
            .tunnel_stream = tunnel_stream,
            .tunnel_reader_buf = undefined,
            .tunnel_writer_buf = undefined,
            .tunnel_reader = undefined,
            .tunnel_writer = undefined,
            .streams = std.HashMap(StreamKey, *Stream, StreamKeyContext, 80).init(allocator),
            .streams_mutex = .{},
            .streams_generation = std.atomic.Value(u64).init(0),
            .channel = undefined,
            .running = std.atomic.Value(bool).init(true),
            .udp_forwarder = null,
            .udp_service_id = null,
            .heartbeat_interval_ms = cfg.advanced.heartbeat_interval_seconds * 1000,
            .next_stream_id = std.atomic.Value(u32).init(1),
            .cfg = cfg,
        };

        conn.tunnel_reader = tunnel_stream.reader(global_io, &conn.tunnel_reader_buf);
        conn.tunnel_writer = tunnel_stream.writer(global_io, &conn.tunnel_writer_buf);

        conn.channel = try transport.Channel.init(.{
            .allocator = allocator,
            .io = global_io,
            .stream = tunnel_stream,
            .reader = &conn.tunnel_reader.interface,
            .writer = &conn.tunnel_writer.interface,
            .cipher = canonical_cipher,
            .psk = cfg.psk,
            .static_keypair = static_keypair,
            .role = .server,
            .version = build_options.version,
            // Encryption profile is opt-in — wiring stats per-frame
            // costs two `clock_gettime` reads (cheap commpage/vDSO calls,
            // but real at multi-Gbps frame rates).  Set
            // `FLOO_PROFILE_ENCRYPT=1` in the environment to re-enable
            // the per-process `[PROFILE] server encryption ...` line at
            // exit.  Throughput byte counters stay on unconditionally
            // (single `.monotonic` fetchAdd per frame).
            .stats = if (encrypt_profile_enabled())
                transport.EncryptionStats{
                    .total_ns = &encrypt_total_ns,
                    .calls = &encrypt_calls,
                }
            else
                null,
            .throughput = transport.ThroughputStats{
                .tx_bytes = &tunnel_tx_bytes,
                .rx_bytes = &tunnel_rx_bytes,
            },
        });
        var channel_guard = true;
        errdefer if (channel_guard) conn.channel.deinit();

        stream_owned = false;

        // Register with the consolidated heartbeat ticker (P1-4). On
        // failure, fall back through the existing errdefers (channel_guard,
        // allocator.destroy(conn)).
        if (conn.heartbeat_interval_ms > 0) {
            heartbeat_ticker.register(conn) catch |err| {
                tunnel_stream.close(global_io);
                return err;
            };
        }

        channel_guard = false;
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
        // Recv hot path reads directly into the decoder buffer via
        // pendingTail/commitWrite — no intermediate stack buffer + memcpy.
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
        var poll_fds = std.ArrayListUnmanaged(posix.pollfd).empty;
        defer poll_fds.deinit(global_allocator);
        var poll_entries = std.ArrayListUnmanaged(PollEntry).empty;
        // Borrow refs held by the cached poll_entries are released either on
        // rebuild (below) or here at scope exit if we break out mid-loop.
        defer {
            for (poll_entries.items) |entry| switch (entry) {
                .stream => |stream_ptr| stream_ptr.releaseRef(),
                .tunnel => {},
            };
            poll_entries.deinit(global_allocator);
        }
        const poll_timeout_ms: i32 = 1000;

        // P-1: cache the poll_fds + poll_entries arrays.  The pre-fix code
        // rebuilt both on every poll cycle (O(streams) under streams_mutex
        // every wakeup) even though streams change rarely (per CONNECT/CLOSE).
        // Now we rebuild only when `streams_generation` changes — every
        // insert/remove bumps the counter under the same lock.  Borrow refs
        // taken during a build are kept until the next build (or scope exit).
        var last_built_generation: u64 = 0;
        var have_built = false;

        while (self.running.load(.acquire) and !shutdown_flag.load(.acquire)) {
            const current_generation = self.streams_generation.load(.acquire);
            if (!have_built or current_generation != last_built_generation) {
                // Release refs held by the previous build.
                for (poll_entries.items) |entry| switch (entry) {
                    .stream => |stream_ptr| stream_ptr.releaseRef(),
                    .tunnel => {},
                };
                poll_fds.clearRetainingCapacity();
                poll_entries.clearRetainingCapacity();

                poll_fds.append(global_allocator, .{
                    .fd = self.tunnel_stream.socket.handle,
                    .events = posix.POLL.IN,
                    .revents = 0,
                }) catch unreachable;
                poll_entries.append(global_allocator, .{ .tunnel = {} }) catch unreachable;

                self.streams_mutex.lock();
                // If a writer raced ahead of our generation read above, capture
                // the value we actually built against so we don't spuriously
                // rebuild next cycle.  Read it inside the lock so we and the
                // writer agree about which insertions/removals are reflected.
                last_built_generation = self.streams_generation.load(.acquire);
                var iter = self.streams.iterator();
                while (iter.next()) |entry| {
                    const stream_ptr = entry.value_ptr.*;
                    stream_ptr.acquireRef();
                    poll_entries.append(global_allocator, .{ .stream = stream_ptr }) catch {
                        stream_ptr.releaseRef();
                        continue;
                    };
                    poll_fds.append(global_allocator, .{
                        .fd = stream_ptr.target_stream.socket.handle,
                        .events = posix.POLL.IN,
                        .revents = 0,
                    }) catch unreachable;
                }
                self.streams_mutex.unlock();
                have_built = true;
            }

            const ready = posix.poll(poll_fds.items, poll_timeout_ms) catch |err| {
                std.debug.print("[TUNNEL] Poll error: {}\n", .{err});
                break;
            };

            if (ready == 0) continue;

            var fatal_error = false;
            var idx: usize = 0;
            loop: while (idx < poll_entries.items.len) : (idx += 1) {
                const entry = poll_entries.items[idx];
                const fd_info = poll_fds.items[idx];
                switch (entry) {
                    .tunnel => {
                        if ((fd_info.revents & posix.POLL.IN) == 0) continue;

                        // Zero-copy recv: read straight into the decoder's
                        // internal buffer.
                        const dst = decoder.pendingTail();
                        if (dst.len == 0) {
                            std.debug.print("[TUNNEL] Decoder buffer full; framing stalled\n", .{});
                            fatal_error = true;
                            break :loop;
                        }
                        const n = posix.read(self.tunnel_stream.socket.handle, dst) catch |err| {
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
                        decoder.commitWrite(n);

                        while (decoder.decodeMut() catch null) |frame_payload| {
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
                        // Stream entries hold a cached borrow ref — DON'T
                        // releaseRef per-iteration.  The ref stays alive
                        // until the next rebuild (which fires when
                        // handleStreamPollEvent → completeStream bumps the
                        // generation) or scope exit.
                        if (fd_info.revents != 0) {
                            self.handleStreamPollEvent(entry.stream, fd_info.revents);
                        }
                    },
                }
            }

            if (fatal_error) break;
        }

        std.debug.print("[TUNNEL] Connection handler stopping\n", .{});
        self.cleanup();
        self.running.store(false, .release);
    }

    fn handleMessage(self: *TunnelConnection, payload: []u8) !void {
        if (payload.len == 0) return;

        const message_slice = try self.channel.decryptFrameInPlace(payload);
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
                // Hot-ish path (per accepted stream): zero-alloc decodeRef
                // — handleConnect consumes the token synchronously
                // (constant-time-compares against the configured token).
                const connect_msg = try tunnel.ConnectMsg.decodeRef(message_slice);

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
                        error.NetworkUnreachable => .connection_timeout,
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
                        common.writeAllToHandle(s.target_stream.socket.handle, data_msg.data) catch |err| {
                            std.debug.print("[STREAM {}] Send to target failed: {}\n", .{ data_msg.stream_id, err });
                            self.completeStream(s, true);
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
                if (maybe_stream != null) {
                    _ = self.streams_generation.fetchAdd(1, .acq_rel);
                }
                self.streams_mutex.unlock();

                if (maybe_stream) |entry| {
                    // Stream still exists, stop and destroy it
                    entry.value.stop();
                    entry.value.releaseRef(); // drop map reference
                    std.debug.print("[TUNNEL] Stream {} cleaned up after CLOSE message\n", .{close_msg.stream_id});
                } else {
                    // Stream already cleaned itself up
                    tracePrint(enable_tunnel_trace, "[TUNNEL] Stream {} already removed (self-cleanup)\n", .{close_msg.stream_id});
                }
            },
            .udp_data => {
                // Hot path: decodeRef avoids the per-packet alloc+memcpy of
                // source_addr. Slices are valid until the next decoder feed,
                // and handleUdpData consumes synchronously (copies into the
                // session's [16]u8 source_addr field on insert).
                const udp_msg = try tunnel.UdpDataMsg.decodeRef(message_slice);

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
                const err_msg = try tunnel.ConnectErrorMsg.decodeRef(message_slice);
                std.debug.print("[TUNNEL-REVERSE] CONNECT_ERROR from client: stream_id={} error={s}\n", .{ err_msg.stream_id, err_msg.error_msg });

                const key = StreamKey{ .service_id = err_msg.service_id, .stream_id = err_msg.stream_id };
                self.streams_mutex.lock();
                const maybe_stream = self.streams.fetchRemove(key);
                if (maybe_stream != null) {
                    _ = self.streams_generation.fetchAdd(1, .acq_rel);
                }
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
        @setRuntimeSafety(false);
        const message_header_len: usize = 7;
        const io_batch = self.cfg.advanced.io_batch_bytes;

        // Ensure we don't overflow the buffer
        const max_read = @min(io_batch, stream.frame_buffer.len - message_header_len - noise.TAG_LEN);

        // Read directly into frame buffer at offset 7
        const recv_slice = stream.frame_buffer[message_header_len..][0..max_read];
        const n = posix.read(stream.target_stream.socket.handle, recv_slice) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        tracePrint(enable_stream_trace, "[STREAM {}] recv() returned {} bytes\n", .{ stream.stream_id, n });

        if (n == 0) {
            self.sendStreamClose(stream);
            return error.ConnectionClosed;
        }

        if (!self.channel.isEncrypted()) {
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

        // For encrypted channel, constructs DataMsg manually in the buffer to avoid copy
        // DataMsg format: [type:1][service_id:2][stream_id:4][data:n]
        stream.frame_buffer[0] = @intFromEnum(tunnel.MessageType.data);
        std.mem.writeInt(u16, stream.frame_buffer[1..3], stream.service_id, .big);
        std.mem.writeInt(u32, stream.frame_buffer[3..7], stream.stream_id, .big);
        // Data is already at offset 7

        const payload_len = message_header_len + n;
        const slice = stream.frame_buffer[0 .. payload_len + noise.TAG_LEN];

        self.channel.sendDataInPlace(slice, payload_len) catch |err| {
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
        if (removed != null) {
            _ = self.streams_generation.fetchAdd(1, .acq_rel);
        }
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
                const address = try common.resolveHostPort(global_io, service.address, service.port);
                var target_stream = try address.connect(global_io, .{ .mode = .stream });
                var target_stream_guard = true;
                defer if (target_stream_guard) target_stream.close(global_io);

                setSockOpts(target_stream.socket.handle, self.cfg);

                tracePrint(enable_stream_trace, "[STREAM {}] Connected to {s}:{}\n", .{ msg.stream_id, service.address, service.port });

                const stream = try Stream.create(global_allocator, msg.service_id, msg.stream_id, target_stream, self);
                target_stream_guard = false; // ownership transferred to Stream

                self.streams_mutex.lock();
                defer self.streams_mutex.unlock();

                const key = StreamKey{ .service_id = msg.service_id, .stream_id = msg.stream_id };
                // Create ref IS map ref — no extra acquire.
                self.streams.put(key, stream) catch |err| {
                    stream.stop();
                    stream.releaseRef(); // drop create ref → destroys
                    return err;
                };
                _ = self.streams_generation.fetchAdd(1, .acq_rel);
            },
            .udp => {
                if (self.udp_forwarder == null) {
                    std.debug.print("[UDP] Creating UDP forwarder for target {s}:{}\n", .{ service.address, service.port });

                    const forwarder = try udp_server.UdpForwarder.create(
                        global_allocator,
                        global_io,
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
        _ = posix.system.shutdown(self.tunnel_stream.socket.handle, posix.SHUT.RDWR);
    }

    fn cleanup(self: *TunnelConnection) void {
        // Detach from the consolidated heartbeat ticker. Blocks briefly if a
        // dispatch round is in flight; once unregister returns, no future
        // tick will dispatch to this conn (audit P1-4).
        if (self.heartbeat_interval_ms > 0) {
            heartbeat_ticker.unregister(self);
        }

        // Drain the streams map one entry at a time: pop under the lock, then
        // call blocking stop()+releaseRef without holding it.
        //
        // Invariant (B-14): once `running == false`, no thread inserts new
        // streams. The producers of `self.streams.put` are:
        //   - handleConnect / handleMessage on the run() loop (exits when
        //     running == false)
        //   - ReverseListener.acceptorThread (checks running every loop)
        //   - reverseServiceListener (checks running every loop)
        // All check `running` before insert. So the iterative pop here
        // converges; concurrent inserts during teardown are not observed.
        while (true) {
            self.streams_mutex.lock();
            var iter = self.streams.iterator();
            const entry = iter.next();
            if (entry) |e| {
                const key_copy = e.key_ptr.*;
                const stream_ptr = e.value_ptr.*;
                _ = self.streams.remove(key_copy);
                self.streams_mutex.unlock();
                stream_ptr.stop();
                stream_ptr.releaseRef();
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
    }

    fn destroy(self: *TunnelConnection) void {
        // Cleanup UDP forwarder if exists
        if (self.udp_forwarder) |forwarder| {
            forwarder.stop();
            forwarder.destroy();
            self.udp_forwarder = null;
            self.udp_service_id = null;
        }

        // Channel.deinit only frees its internal buffers — it does not close
        // the underlying stream (the caller owns it).
        self.channel.deinit();
        self.tunnel_stream.close(global_io);
        global_allocator.destroy(self);
    }
};

// Note: the previous "forwardTargetData sends plaintext frames" inline test
// depended on posix.socketpair / GeneralPurposeAllocator / common.sendAllToFd
// which were removed in 0.16. The integration test harness (WP-03 in the
// remediation plan) is the right replacement and will exercise this path
// end-to-end via real spawned floos+flooc processes.

pub fn main(init: std.process.Init) !void {
    // Zig 0.16: Init provides Io (Threaded backend by default) and the same gpa
    // start.zig used (DebugAllocator in debug, smp_allocator in release).
    const allocator = init.gpa;
    global_allocator = allocator;
    global_io = init.io;
    defer diagnostics.flushEncryptStats("server", &encrypt_total_ns, &encrypt_calls);
    defer diagnostics.flushThroughputStats("server", &tunnel_tx_bytes, &tunnel_rx_bytes);
    defer cleanupSignalPipe();

    // Ignore SIGPIPE to prevent process termination on write errors
    if (builtin.os.tag != .windows) {
        var act = posix.Sigaction{
            .handler = .{ .handler = posix.SIG.IGN },
            .mask = std.mem.zeroes(posix.sigset_t),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.PIPE, &act, null);
    }

    var exit_code: u8 = 0;
    defer if (exit_code != 0) std.process.exit(exit_code);

    // Zig 0.16: process.argsAlloc removed; use process.Args.Iterator instead.
    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();
    var args_list_arr: std.ArrayListUnmanaged([:0]const u8) = .empty;
    defer args_list_arr.deinit(allocator);
    while (args_iter.next()) |arg| {
        try args_list_arr.append(allocator, arg);
    }
    const args_list = args_list_arr.items;

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
        // SIGTERM was previously unbound — the handler at handleSignal()
        // already accepts it, but without sigaction it took the default
        // action (process kill, no defers run, no profile/stats flush).
        posix.sigaction(posix.SIG.TERM, &sig_action, null);
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

    // Create listen Server
    const listen_addr = try common.resolveHostPort(global_io, cfg.bind, port);
    var server = try listen_addr.listen(global_io, .{ .reuse_address = true });
    defer server.deinit(global_io);

    var addr_buf: [64]u8 = undefined;
    std.debug.print("[SERVER] Listening on {s}\n", .{formatAddress(listen_addr, &addr_buf)});
    std.debug.print("[READY] Server ready. Press Ctrl+C to stop.\n\n", .{});

    // Generate persistent static keypair for Noise XX authentication
    const static_keypair = std.crypto.dh.X25519.KeyPair.generate(global_io);

    const ConnectionEntry = struct {
        conn: *TunnelConnection,
        thread: std.Thread,
    };
    var connections = std.ArrayListUnmanaged(ConnectionEntry).empty;
    var reverse_listeners = std.ArrayListUnmanaged(*ReverseListener).empty;
    var reverse_listeners_conn: ?*TunnelConnection = null;
    defer {
        stopAllReverseListeners(&reverse_listeners);
        reverse_listeners.deinit(allocator);

        // Stop all connections
        for (connections.items) |entry| {
            entry.conn.running.store(false, .release);
            // Shutdown tunnel socket to unblock recv() in connection thread
            _ = posix.system.shutdown(entry.conn.tunnel_stream.socket.handle, posix.SHUT.RD);
        }
        // Wait for threads and cleanup
        for (connections.items) |entry| {
            entry.thread.join();
        }
        for (connections.items) |entry| {
            entry.conn.destroy();
        }
        connections.deinit(allocator);

        // Now that every TunnelConnection has been destroyed (and therefore
        // unregistered from the ticker via cleanup()), join the ticker
        // thread so it isn't holding any conn pointers when main exits.
        // shutdown_flag has already been set by the signal handler — the
        // ticker observes it on its next 100ms tick and exits.
        heartbeat_ticker.shutdownAndJoin();
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

        // Accept with timeout (poll listen-socket fd + signal pipe).
        // The Io.net.Server doesn't expose a poll-then-accept pattern, so we
        // poll on the underlying handle and then call Server.accept which
        // returns immediately because data is ready.
        var poll_buf: [1]posix.pollfd = undefined;
        poll_buf[0] = .{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 };

        const ready = posix.poll(&poll_buf, 1000) catch continue; // 1s timeout

        if (ready == 0) continue; // Timeout, check flags
        if ((poll_buf[0].revents & posix.POLL.IN) == 0) continue;

        const tunnel_stream = server.accept(global_io) catch |err| {
            if (err == error.SocketNotListening) break;
            if (err == error.WouldBlock or err == error.ConnectionAborted) continue;
            std.debug.print("[SERVER] Accept error: {}\n", .{err});
            continue;
        };

        // Apply rate limiting to prevent connection flood attacks
        if (!rate_limiter.tryAcquire()) {
            std.debug.print("[SERVER] Rate limit exceeded, rejecting connection\n", .{});
            tunnel_stream.close(global_io);
            continue;
        }

        const tunnel_fd = tunnel_stream.socket.handle;
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
        const tunnel_conn = TunnelConnection.create(allocator, tunnel_stream, &cfg, static_keypair) catch |err| {
            std.debug.print("[SERVER] Failed to create tunnel: {}\n", .{err});
            tunnel_stream.close(global_io);
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
            _ = posix.system.shutdown(tunnel_conn.tunnel_stream.socket.handle, posix.SHUT.RD);
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

    // Create listener via Io.net
    const local_addr = common.resolveHostPort(global_io, ctx.listen_host, ctx.listen_port) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to parse address for service_id={}: {}\n", .{ ctx.service_id, err });
        return;
    };

    var server = common.bindListener(local_addr, common.LISTEN_BACKLOG) catch |err| {
        std.debug.print("[REVERSE-SERVICE] Failed to listen on port {} for service_id={}: {}\n", .{ ctx.listen_port, ctx.service_id, err });
        return;
    };
    defer server.deinit(global_io);

    std.debug.print("[REVERSE-SERVICE] Listening on {s}:{} (service_id={}, reverse mode)\n", .{ ctx.listen_host, ctx.listen_port, ctx.service_id });

    // Accept loop
    while (!shutdown_flag.load(.acquire) and ctx.tunnel_conn.running.load(.acquire)) {
        // Poll on the underlying handle so we can honor the 1s shutdown check.
        var fds = [_]posix.pollfd{
            .{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 1000) catch continue;
        if (ready == 0) continue;

        const user_stream = server.accept(global_io) catch |err| {
            if (err == error.SocketNotListening) break;
            if (err == error.WouldBlock or err == error.ConnectionAborted) continue;
            std.debug.print("[REVERSE-SERVICE] Accept error for service_id={}: {}\n", .{ ctx.service_id, err });
            continue;
        };

        // Generate stream_id
        const stream_id = ctx.next_stream_id.fetchAdd(1, .acq_rel);

        std.debug.print("[REVERSE-SERVICE] External user connected, sending CONNECT to client (service_id={}, stream_id={})\n", .{ ctx.service_id, stream_id });

        // Apply socket tuning
        TunnelConnection.setSockOpts(user_stream.socket.handle, ctx.tunnel_conn.cfg);

        // Send CONNECT message to client through tunnel
        const connect_msg = tunnel.ConnectMsg{
            .service_id = ctx.service_id,
            .stream_id = stream_id,
            .token = "",
        };

        var encode_buf: [512]u8 = undefined;
        const encoded_len = connect_msg.encodeInto(&encode_buf) catch {
            std.debug.print("[REVERSE-SERVICE] Failed to encode CONNECT message\n", .{});
            user_stream.close(global_io);
            continue;
        };

        ctx.tunnel_conn.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
            std.debug.print("[REVERSE-SERVICE] Failed to send CONNECT to client: {}\n", .{err});
            ctx.tunnel_conn.handleSendFailure(err);
            user_stream.close(global_io);
            continue;
        };

        // Create Stream to forward user_stream <-> tunnel
        const stream = Stream.create(global_allocator, ctx.service_id, stream_id, user_stream, ctx.tunnel_conn) catch |err| {
            std.debug.print("[REVERSE-SERVICE] Failed to create stream: {}\n", .{err});
            user_stream.close(global_io);
            continue;
        };

        ctx.tunnel_conn.streams_mutex.lock();
        const key = StreamKey{ .service_id = ctx.service_id, .stream_id = stream_id };
        // Create ref IS map ref — no extra acquire.
        ctx.tunnel_conn.streams.put(key, stream) catch |err| {
            ctx.tunnel_conn.streams_mutex.unlock();
            std.debug.print("[REVERSE-SERVICE] Failed to register stream: {}\n", .{err});
            stream.stop();
            stream.releaseRef(); // drop create ref → destroys
            continue;
        };
        _ = ctx.tunnel_conn.streams_generation.fetchAdd(1, .acq_rel);
        ctx.tunnel_conn.streams_mutex.unlock();

        std.debug.print("[REVERSE-SERVICE] Stream {} created for reverse connection\n", .{stream_id});
    }

    std.debug.print("[REVERSE-SERVICE] Service listener stopped for service_id={}\n", .{ctx.service_id});
}
