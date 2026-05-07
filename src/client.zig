const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const build_options = @import("build_options");
const protocol = @import("protocol.zig");
const tunnel = @import("tunnel.zig");
const config = @import("config.zig");
const noise = @import("noise.zig");
const udp_client = @import("udp_client.zig");
const diagnostics = @import("diagnostics.zig");
const common = @import("common.zig");
const proxy = @import("proxy.zig");
const transport = @import("transport/channel.zig");
const builtin = @import("builtin");

const tracePrint = common.tracePrint;
const tcpOptionsFromSettings = common.tcpOptionsFromSettings;
const tuneSocketBuffers = common.tuneSocketBuffers;
const applyTcpOptions = common.applyTcpOptions;
const TcpOptions = common.TcpOptions;
const formatAddress = common.formatAddress;
const math = std.math;

const CheckStatus = diagnostics.CheckStatus;

const DEFAULT_CONFIG_PATH = "flooc.toml";
const enable_tunnel_trace = false;
const enable_listener_trace = false;

var global_allocator: std.mem.Allocator = undefined;
var global_io: std.Io = undefined;
var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var config_path_global: []const u8 = undefined; // Store config path for reload
var encrypt_total_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var encrypt_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_tx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var tunnel_rx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var flush_stats_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var sighup_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Per-process gate for the encryption time profile.  Resolved on first
/// read into module-scope statics.  Set `FLOO_PROFILE_ENCRYPT=1` in the
/// environment to opt in.
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
var tunnel_cpu_assigner: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var tunnel_cpu_cache: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

// Signal-pipe stubs (kept as no-ops so call sites in main don't have to gate).
// Zig 0.16 removed posix.pipe2; the self-pipe optimization is gone. Signals
// now just set atomic flags that the next 1s poll iteration picks up.
fn setupSignalPipe() !void {}
fn cleanupSignalPipe() void {}
fn drainSignalPipe() void {}
fn notifySignalPipe(sig: c_int) void {
    _ = sig;
}

fn clientCpuCountCached() usize {
    const cached = tunnel_cpu_cache.load(.acquire);
    if (cached != 0) return cached;
    const detected = std.Thread.getCpuCount() catch 1;
    tunnel_cpu_cache.store(detected, .release);
    return detected;
}

fn clientNextCpuIndex() usize {
    const count = clientCpuCountCached();
    const idx = tunnel_cpu_assigner.fetchAdd(1, .acq_rel);
    return idx % @max(count, 1);
}

fn clientApplyThreadAffinity(index_opt: ?usize) void {
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

fn processSignalNotifications(notice_printed: *bool) void {
    if (builtin.target.os.tag != .windows) {
        drainSignalPipe();
    }
    if (flush_stats_requested.swap(false, .acq_rel)) {
        diagnostics.flushEncryptStats("client", &encrypt_total_ns, &encrypt_calls);
        diagnostics.flushThroughputStats("client", &tunnel_tx_bytes, &tunnel_rx_bytes);
    }
    if (sighup_requested.swap(false, .acq_rel)) {
        std.debug.print("\n[INFO] Configuration reload via SIGHUP is currently disabled; restart flooc to apply changes.\n", .{});
    }
    if (!notice_printed.* and shutdown_flag.load(.acquire)) {
        std.debug.print("\n[SHUTDOWN] Received interrupt, stopping client...\n", .{});
        notice_printed.* = true;
    }
}

const CliMode = enum { run, help, version, doctor, ping };

const CliOptions = struct {
    mode: CliMode = .run,
    config_path: []const u8 = DEFAULT_CONFIG_PATH,
    config_path_set: bool = false,
    local_port_override: ?u16 = null,
    remote_host_override: ?[]const u8 = null,
    remote_port_override: ?u16 = null,
    proxy_url_override: ?[]const u8 = null,

    fn deinit(self: *CliOptions, allocator: std.mem.Allocator) void {
        if (self.remote_host_override) |host| allocator.free(host);
        if (self.proxy_url_override) |url| allocator.free(url);
    }
};

const ParseError = error{ UnknownFlag, MissingValue, ConflictingMode, TooManyPositionals, InvalidValue, OutOfMemory };

const ParseContext = struct {
    arg: []const u8 = "",
};

const CLIENT_USAGE =
    \\Usage: flooc [options] [config_path]
    \\Options:
    \\  -h, --help                 Show this help message and exit
    \\  -V, --version              Show version information and exit
    \\      --doctor              Run diagnostics using the provided config and exit
    \\      --ping                Measure handshake latency to the remote server and exit
    \\  -l, --local PORT          Override local listener port
    \\  -r, --remote HOST[:PORT]  Override remote server address
    \\  -x, --proxy URL           Connect via proxy (socks5://host:port or http://host:port)
    \\  config_path               Optional path to flooc.toml (defaults to ./flooc.toml)
    \\Examples:
    \\  flooc --ping
    \\  flooc --doctor custom-configs/client.toml
    \\  flooc -r tunnel.example.com:8443 --ping
    \\  flooc -x socks5://127.0.0.1:1080 --ping
    \\  flooc -x http://user:pass@proxy.corp.com:8080
    \\
;

fn printClientUsage() void {
    std.debug.print("{s}", .{CLIENT_USAGE});
}

fn setStringOverride(slot: *?[]const u8, allocator: std.mem.Allocator, value: []const u8) !void {
    if (slot.*) |prev| {
        allocator.free(prev);
    }
    slot.* = try allocator.dupe(u8, value);
}

fn setMode(opts: *CliOptions, new_mode: CliMode, ctx: *ParseContext, arg: []const u8) ParseError!void {
    if (opts.mode != .run and opts.mode != new_mode) {
        ctx.arg = arg;
        return ParseError.ConflictingMode;
    }
    opts.mode = new_mode;
}

fn parseHostPortOption(
    allocator: std.mem.Allocator,
    value: []const u8,
    host_slot: *?[]const u8,
    port_slot: *?u16,
    ctx: *ParseContext,
    flag: []const u8,
) ParseError!void {
    if (value.len == 0) {
        ctx.arg = flag;
        return ParseError.InvalidValue;
    }
    if (value[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, value, ']') orelse {
            ctx.arg = flag;
            return ParseError.InvalidValue;
        };
        const host_part = value[1..close_idx];
        if (close_idx + 1 >= value.len or value[close_idx + 1] != ':') {
            ctx.arg = flag;
            return ParseError.InvalidValue;
        }
        const port_str = value[close_idx + 2 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            ctx.arg = flag;
            return ParseError.InvalidValue;
        };
        try setStringOverride(host_slot, allocator, host_part);
        port_slot.* = port;
        return;
    }

    if (std.mem.indexOfScalar(u8, value, ':')) |colon_idx| {
        const host_part = value[0..colon_idx];
        const port_str = value[colon_idx + 1 ..];
        if (port_str.len == 0) {
            ctx.arg = flag;
            return ParseError.InvalidValue;
        }
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            ctx.arg = flag;
            return ParseError.InvalidValue;
        };
        try setStringOverride(host_slot, allocator, host_part);
        port_slot.* = port;
        return;
    }

    try setStringOverride(host_slot, allocator, value);
}

fn parseClientArgs(allocator: std.mem.Allocator, args_list: []const [:0]const u8, ctx: *ParseContext) ParseError!CliOptions {
    var opts = CliOptions{};
    errdefer opts.deinit(allocator);
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
        } else if (std.mem.eql(u8, arg, "--local") or std.mem.eql(u8, arg, "-l")) {
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
            opts.local_port_override = port;
        } else if (std.mem.eql(u8, arg, "--remote") or std.mem.eql(u8, arg, "-r")) {
            if (idx + 1 >= args_list.len) {
                ctx.arg = arg;
                return ParseError.MissingValue;
            }
            idx += 1;
            const value = std.mem.sliceTo(args_list[idx], 0);
            try parseHostPortOption(allocator, value, &opts.remote_host_override, &opts.remote_port_override, ctx, arg);
        } else if (std.mem.eql(u8, arg, "--proxy") or std.mem.eql(u8, arg, "-x")) {
            if (idx + 1 >= args_list.len) {
                ctx.arg = arg;
                return ParseError.MissingValue;
            }
            idx += 1;
            const value = std.mem.sliceTo(args_list[idx], 0);
            try setStringOverride(&opts.proxy_url_override, allocator, value);
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

fn applyClientOverrides(allocator: std.mem.Allocator, cfg: *config.ClientConfig, opts: *CliOptions) void {
    // Handle local port override for default service
    if (opts.local_port_override) |port| {
        if (cfg.default_service) |service_name| {
            if (cfg.services.getPtr(service_name)) |service| {
                service.port = port;
            }
        }
    }

    // Handle remote host/port override by rebuilding server string
    if (opts.remote_host_override != null or opts.remote_port_override != null) {
        const current_host = cfg.getServerHost() catch "localhost";
        const current_port = cfg.getServerPort() catch 8443;

        const new_host = opts.remote_host_override orelse current_host;
        const new_port = opts.remote_port_override orelse current_port;

        const new_server = std.fmt.allocPrint(allocator, "{s}:{d}", .{ new_host, new_port }) catch return;
        allocator.free(cfg.server);
        cfg.server = new_server;

        if (opts.remote_host_override) |_| {
            opts.remote_host_override = null;
        }
    }

    if (opts.proxy_url_override) |url| {
        allocator.free(cfg.advanced.proxy_url);
        cfg.advanced.proxy_url = url;
        opts.proxy_url_override = null;
    }
}

fn loadClientConfigWithOverrides(allocator: std.mem.Allocator, opts: *CliOptions) !config.ClientConfig {
    var cfg = try config.ClientConfig.loadFromFile(allocator, global_io, opts.config_path);
    errdefer cfg.deinit();
    applyClientOverrides(allocator, &cfg, opts);
    return cfg;
}

const PingResult = struct {
    remote_addr: Io.net.IpAddress,
    connect_ns: i128,
    handshake_ns: i128,
    total_ns: i128,
};

fn performClientPing(cfg: *const config.ClientConfig) !PingResult {
    const connect_start = common.nanoTimestamp();

    const remote_host = try cfg.getServerHost();
    const remote_port = try cfg.getServerPort();

    // Connect through proxy if configured
    var proxy_cfg_opt: ?proxy.ProxyConfig = null;
    if (cfg.advanced.proxy_url.len > 0) {
        proxy_cfg_opt = try proxy.ProxyConfig.parseUrl(global_allocator, cfg.advanced.proxy_url);
    }
    defer if (proxy_cfg_opt) |*p| p.deinit(global_allocator);

    const stream = try proxy.connectWithProxy(
        global_io,
        global_allocator,
        proxy_cfg_opt,
        remote_host,
        remote_port,
    );
    errdefer stream.close(global_io);

    const connect_done = common.nanoTimestamp();

    const canonical_cipher = config.canonicalCipher(cfg);
    var handshake_metrics = transport.HandshakeMetrics{};
    const static_keypair = std.crypto.dh.X25519.KeyPair.generate(global_io);
    var rdr_buf: [4096]u8 = undefined;
    var wtr_buf: [4096]u8 = undefined;
    var rdr = stream.reader(global_io, &rdr_buf);
    var wtr = stream.writer(global_io, &wtr_buf);
    const channel = try transport.Channel.init(.{
        .allocator = global_allocator,
        .io = global_io,
        .stream = stream,
        .reader = &rdr.interface,
        .writer = &wtr.interface,
        .cipher = canonical_cipher,
        .psk = cfg.psk,
        .static_keypair = static_keypair,
        .role = .client,
        .version = build_options.version,
        .handshake_metrics = &handshake_metrics,
    });
    {
        var tmp = channel;
        tmp.deinit();
    }

    const total_ns = common.nanoTimestamp() - connect_start;
    stream.close(global_io);
    const remote_addr = try common.resolveHostPort(global_io, remote_host, remote_port);
    return .{
        .remote_addr = remote_addr,
        .connect_ns = connect_done - connect_start,
        .handshake_ns = handshake_metrics.elapsed_ns,
        .total_ns = total_ns,
    };
}

const ServiceBinding = struct {
    host: []const u8,
    port: u16,
    token: []const u8,
};

fn getServiceBinding(cfg: *const config.ClientConfig, service_id: tunnel.ServiceId) !ServiceBinding {
    if (cfg.getServiceById(service_id)) |svc| {
        return .{
            .host = svc.address,
            .port = svc.port,
            .token = if (svc.token.len > 0) svc.token else cfg.token,
        };
    }
    return error.UnknownService;
}

fn runClientPing(allocator: std.mem.Allocator, opts: *CliOptions) !bool {
    var cfg = try loadClientConfigWithOverrides(allocator, opts);
    defer cfg.deinit();

    const host = try cfg.getServerHost();
    const port = try cfg.getServerPort();
    std.debug.print("Pinging {s}:{d}...\n", .{ host, port });
    const result = performClientPing(&cfg) catch |err| {
        diagnostics.reportCheck(.fail, "Connection attempt failed: {}", .{err});
        return false;
    };

    var addr_buf: [64]u8 = undefined;
    const addr_str = formatAddress(result.remote_addr, &addr_buf);

    const connect_ms = @as(f64, @floatFromInt(result.connect_ns)) / @as(f64, std.time.ns_per_ms);
    const handshake_ms = @as(f64, @floatFromInt(result.handshake_ns)) / @as(f64, std.time.ns_per_ms);
    const total_ms = @as(f64, @floatFromInt(result.total_ns)) / @as(f64, std.time.ns_per_ms);

    diagnostics.reportCheck(.ok, "Connected to {s}", .{addr_str});
    const canonical_cipher = config.canonicalCipher(&cfg);
    if (result.handshake_ns > 0) {
        diagnostics.reportCheck(.ok, "Handshake completed using cipher '{s}'", .{canonical_cipher});
        diagnostics.reportCheck(.ok, "Version check passed: {s}", .{build_options.version});
        std.debug.print("    connect:  {d:.2} ms\n", .{connect_ms});
        std.debug.print("    handshake:{d:.2} ms\n", .{handshake_ms});
        std.debug.print("    total:    {d:.2} ms\n", .{total_ms});
    } else {
        diagnostics.reportCheck(.warn, "Encryption disabled; only TCP connectivity verified", .{});
        std.debug.print("    connect:  {d:.2} ms\n", .{connect_ms});
    }
    return true;
}

fn runClientDoctor(allocator: std.mem.Allocator, opts: *CliOptions) !bool {
    std.debug.print("Floo Client Doctor\n===================\n", .{});

    var config_exists = true;
    Io.Dir.cwd().access(global_io, opts.config_path, .{}) catch {
        config_exists = false;
    };

    if (config_exists) {
        diagnostics.reportCheck(.ok, "Config file accessible at {s}", .{opts.config_path});
    } else {
        diagnostics.reportCheck(.warn, "Config file {s} not found; defaults will be used", .{opts.config_path});
    }

    var cfg = loadClientConfigWithOverrides(allocator, opts) catch |err| {
        diagnostics.reportCheck(.fail, "Failed to load config: {}", .{err});
        return false;
    };
    defer cfg.deinit();

    var had_fail = false;

    diagnostics.reportCheck(.ok, "Configuration parsed (services: {})", .{cfg.services.count()});
    diagnostics.reportCheck(.ok, "Client version: {s}", .{build_options.version});
    if (std.mem.eql(u8, cfg.psk, config.DEFAULT_PSK)) {
        diagnostics.reportCheck(.warn, "Using default PSK; replace with secret for production", .{});
    }
    if (cfg.token.len == 0 or std.mem.eql(u8, cfg.token, config.DEFAULT_TOKEN)) {
        diagnostics.reportCheck(.warn, "Default token is unset or placeholder; tighten authentication", .{});
    }

    const remote_host = try cfg.getServerHost();
    const remote_port = try cfg.getServerPort();
    const remote_addr = common.resolveHostPort(global_io, remote_host, remote_port) catch |err| {
        diagnostics.reportCheck(.fail, "Unable to resolve remote {s}:{d}: {}", .{ remote_host, remote_port, err });
        return false;
    };
    var addr_buf: [64]u8 = undefined;
    diagnostics.reportCheck(.ok, "Remote {s}:{d} resolves to {s}", .{ remote_host, remote_port, formatAddress(remote_addr, &addr_buf) });

    // Check local service ports
    var service_iter = cfg.services.valueIterator();
    while (service_iter.next()) |service| {
        const local_addr = common.resolveHostPort(global_io, service.address, service.port) catch |err| {
            diagnostics.reportCheck(.warn, "Failed to parse address for service '{s}': {}", .{ service.name, err });
            continue;
        };
        const probe = local_addr.listen(global_io, .{ .reuse_address = true });
        if (probe) |srv| {
            var srv_mut = srv;
            defer srv_mut.deinit(global_io);
            diagnostics.reportCheck(.ok, "Local port {} available for service '{s}' on {s}", .{ service.port, service.name, service.address });
        } else |err| {
            if (err == error.AddressInUse) {
                diagnostics.reportCheck(.warn, "Local port {} for service '{s}' is already in use", .{ service.port, service.name });
                had_fail = true;
            } else {
                diagnostics.reportCheck(.warn, "Unable to probe local port {} for service '{s}': {}", .{ service.port, service.name, err });
            }
        }
    }

    const ping_result = performClientPing(&cfg) catch |err| {
        diagnostics.reportCheck(.fail, "Ping failed: {}", .{err});
        had_fail = true;
        std.debug.print("\nDiagnostics complete (with failures).\n", .{});
        return false;
    };
    const connect_ms = @as(f64, @floatFromInt(ping_result.connect_ns)) / @as(f64, std.time.ns_per_ms);
    const handshake_ms = @as(f64, @floatFromInt(ping_result.handshake_ns)) / @as(f64, std.time.ns_per_ms);

    diagnostics.reportCheck(.ok, "Ping succeeded (connect {d:.2} ms, handshake {d:.2} ms)", .{ connect_ms, handshake_ms });
    if (had_fail) {
        std.debug.print("\nDiagnostics complete (with warnings).\n", .{});
    } else {
        std.debug.print("\nDiagnostics complete.\n", .{});
    }
    return !had_fail;
}

fn handleSignal(sig: posix.SIG) callconv(.c) void {
    if (sig == posix.SIG.INT or sig == posix.SIG.TERM) {
        shutdown_flag.store(true, .release);
    }
    if (builtin.target.os.tag != .windows) {
        notifySignalPipe(@intCast(@intFromEnum(sig)));
    }
}

/// Local connection being forwarded
const LocalConnection = struct {
    service_id: tunnel.ServiceId,
    stream_id: tunnel.StreamId,
    local_stream: Io.net.Stream,
    tunnel: *TunnelClient,
    fd_closed: std.atomic.Value(bool), // Track if local_stream is closed
    ref_count: std.atomic.Value(usize),
    send_buffer: []u8,

    fn create(allocator: std.mem.Allocator, service_id: tunnel.ServiceId, stream_id: tunnel.StreamId, local_stream: Io.net.Stream, tunnel_client: *TunnelClient) !*LocalConnection {
        const io_batch = tunnel_client.cfg.advanced.io_batch_bytes;

        const header_len: usize = 7;
        const send_capacity = header_len + io_batch + noise.TAG_LEN + 32;
        const send_buffer = try allocator.alignedAlloc(u8, .@"64", send_capacity);
        errdefer allocator.free(send_buffer);

        const conn = try allocator.create(LocalConnection);
        conn.* = .{
            .service_id = service_id,
            .stream_id = stream_id,
            .local_stream = local_stream,
            .tunnel = tunnel_client,
            .fd_closed = std.atomic.Value(bool).init(false),
            .ref_count = std.atomic.Value(usize).init(1),
            .send_buffer = send_buffer,
        };
        return conn;
    }

    fn acquireRef(self: *LocalConnection) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    fn releaseRef(self: *LocalConnection) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            self.destroyInternal();
        }
    }

    fn destroyInternal(self: *LocalConnection) void {
        self.stop();
        if (self.send_buffer.len > 0) global_allocator.free(self.send_buffer);
        global_allocator.destroy(self);
    }

    fn stop(self: *LocalConnection) void {
        if (!self.fd_closed.swap(true, .acq_rel)) {
            self.local_stream.close(global_io);
        }
    }

    fn handle(self: *const LocalConnection) posix.fd_t {
        return self.local_stream.socket.handle;
    }
};

/// Binds a UDP forwarder to whichever TunnelClient is currently connected on
/// its preferred tunnel index. The forwarder outlives any single tunnel
/// connection — when tunnel-0 disconnects and reconnects, main updates this
/// slot and the forwarder transparently routes through the new client.
///
/// Audit fix A-1: previously the forwarder pointed directly at a TunnelClient
/// that got destroyed on disconnect, killing the UDP service permanently.
const UdpAttachment = struct {
    forwarder: *udp_client.UdpForwarder,
    /// Currently-active tunnel for outbound packets; null while reconnecting.
    /// Loaded atomically on every send (per-packet); stored atomically by
    /// tunnelThreadWithReconnection on connect/disconnect.
    tunnel: std.atomic.Value(?*TunnelClient),

    pub fn init(forwarder: *udp_client.UdpForwarder) UdpAttachment {
        return .{
            .forwarder = forwarder,
            .tunnel = std.atomic.Value(?*TunnelClient).init(null),
        };
    }
};

/// Send shim used by udp_client.UdpForwarder. The opaque pointer is a
/// `*UdpAttachment`; the current TunnelClient is read atomically and used
/// for the actual sendDataInPlace.
fn sendTunnelPayload(att_ptr: *anyopaque, buffer: []u8, payload_len: usize) anyerror!void {
    const att: *UdpAttachment = @ptrCast(@alignCast(att_ptr));
    const client = att.tunnel.load(.acquire) orelse return error.NoTunnelAvailable;
    const slice = buffer[0 .. payload_len + noise.TAG_LEN];
    try client.channel.sendDataInPlace(slice, payload_len);
}

fn effectiveTunnelCount(settings: *config.AdvancedSettings) usize {
    if (settings.num_tunnels > 0) return settings.num_tunnels;
    const cpu_count = std.Thread.getCpuCount() catch 1;
    const clamped = math.clamp(cpu_count, 1, 64);
    settings.num_tunnels = clamped;
    return clamped;
}

/// Tunnel client
const TunnelClient = struct {
    tunnel_stream: Io.net.Stream,
    tunnel_reader_buf: [8192]u8,
    tunnel_writer_buf: [8192]u8,
    tunnel_reader: Io.net.Stream.Reader,
    tunnel_writer: Io.net.Stream.Writer,
    service_id: tunnel.ServiceId,
    connections: std.AutoHashMap(tunnel.StreamId, *LocalConnection),
    /// common.HotMutex (os_unfair_lock on Darwin, raw futex on Linux)
    /// instead of Io.Mutex; see transport/Channel.send_mutex for
    /// rationale. Hot on the data path (held per CONNECT/CONNECT_ACK
    /// /CLOSE/recv-DATA lookup).
    connections_mutex: common.HotMutex,
    channel: transport.Channel,
    next_stream_id: std.atomic.Value(u32),
    running: std.atomic.Value(bool),

    // UDP support — per-service-id inbound dispatch table (audit B-1).
    // Previously a single `?*UdpForwarder` field meant that with multiple
    // UDP services configured, only the LAST registered forwarder
    // received inbound .udp_data frames; earlier ones silently dropped
    // their replies. The map is non-owning: forwarders are owned by main
    // (via UdpAttachment), tunnel-client lifecycle just sets/clears
    // routes here on (re)connect.
    udp_forwarders: std.AutoHashMap(tunnel.ServiceId, *udp_client.UdpForwarder),
    transport: config.Transport,

    // Heartbeat support
    heartbeat_timeout_ms: u32, // Consider connection dead if no heartbeat for N milliseconds (0 = disabled)
    last_heartbeat_time: std.atomic.Value(i64), // Milliseconds since epoch of last received heartbeat

    // Authentication
    default_token: []const u8, // Default token for authentication (empty = no auth)

    // Config reference for TCP tuning (needed for reverse mode)
    cfg: *const config.ClientConfig,

    fn create(allocator: std.mem.Allocator, tunnel_stream: Io.net.Stream, service_id: tunnel.ServiceId, cfg: *const config.ClientConfig, static_keypair: std.crypto.dh.X25519.KeyPair) !*TunnelClient {
        setSockOpts(tunnel_stream.socket.handle, cfg);

        var stream_owned = true;
        errdefer if (stream_owned) tunnel_stream.close(global_io);

        const canonical_cipher = config.canonicalCipher(cfg);

        const client = try allocator.create(TunnelClient);
        errdefer allocator.destroy(client);

        client.* = .{
            .tunnel_stream = tunnel_stream,
            .tunnel_reader_buf = undefined,
            .tunnel_writer_buf = undefined,
            .tunnel_reader = undefined,
            .tunnel_writer = undefined,
            .service_id = service_id,
            .connections = std.AutoHashMap(tunnel.StreamId, *LocalConnection).init(allocator),
            .connections_mutex = .{},
            .channel = undefined,
            .next_stream_id = std.atomic.Value(u32).init(1),
            .running = std.atomic.Value(bool).init(true),
            .udp_forwarders = std.AutoHashMap(tunnel.ServiceId, *udp_client.UdpForwarder).init(allocator),
            .transport = .tcp,
            .heartbeat_timeout_ms = cfg.advanced.heartbeat_timeout_seconds * 1000,
            .last_heartbeat_time = std.atomic.Value(i64).init(common.milliTimestamp()),
            .default_token = cfg.token,
            .cfg = cfg,
        };

        client.tunnel_reader = tunnel_stream.reader(global_io, &client.tunnel_reader_buf);
        client.tunnel_writer = tunnel_stream.writer(global_io, &client.tunnel_writer_buf);

        client.channel = try transport.Channel.init(.{
            .allocator = allocator,
            .io = global_io,
            .stream = tunnel_stream,
            .reader = &client.tunnel_reader.interface,
            .writer = &client.tunnel_writer.interface,
            .cipher = canonical_cipher,
            .psk = cfg.psk,
            .static_keypair = static_keypair,
            .role = .client,
            .version = build_options.version,
            // Encryption profile is opt-in via FLOO_PROFILE_ENCRYPT — see
            // server.zig for rationale.
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
        stream_owned = false;

        if (client.heartbeat_timeout_ms > 0) {
            std.debug.print("[CLIENT] Heartbeat timeout enabled: {}s\n", .{cfg.advanced.heartbeat_timeout_seconds});
        }

        if (client.default_token.len > 0) {
            std.debug.print("[CLIENT] Authentication enabled with token\n", .{});
        }

        return client;
    }

    fn setSockOpts(fd: posix.fd_t, cfg: *const config.ClientConfig) void {
        const tcp_options = TcpOptions{
            .nodelay = cfg.advanced.tcp_nodelay,
            .keepalive = cfg.advanced.tcp_keepalive,
            .keepalive_idle = cfg.advanced.tcp_keepalive_idle,
            .keepalive_interval = cfg.advanced.tcp_keepalive_interval,
            .keepalive_count = cfg.advanced.tcp_keepalive_count,
        };
        applyTcpOptions(fd, tcp_options);
        tuneSocketBuffers(fd, cfg.advanced.socket_buffer_size);
    }

    fn run(self: *TunnelClient) void {
        // Recv hot path reads directly into the decoder buffer via
        // pendingTail/commitWrite — no intermediate stack buffer + memcpy.
        var decoder = protocol.FrameDecoder.init(global_allocator);
        defer decoder.deinit();

        // Check if decoder buffer was allocated
        if (decoder.buffer.len == 0) {
            std.debug.print("[CLIENT] Failed to allocate decoder buffer!\n", .{});
            self.cleanup();
            self.running.store(false, .release);
            return;
        }

        std.debug.print("[CLIENT] Tunnel handler started (buffer size: {})\n", .{decoder.buffer.len});

        // Poll timeout: check heartbeat every second if enabled, otherwise use 5 seconds
        const poll_timeout_ms: i32 = if (self.heartbeat_timeout_ms > 0) 1000 else 5000;

        const PollEntry = union(enum) {
            tunnel,
            local: *LocalConnection,
        };
        var poll_fds = std.ArrayListUnmanaged(posix.pollfd).empty;
        defer poll_fds.deinit(global_allocator);
        var poll_entries = std.ArrayListUnmanaged(PollEntry).empty;
        defer poll_entries.deinit(global_allocator);

        while (self.running.load(.acquire) and !shutdown_flag.load(.acquire)) {
            // Check heartbeat timeout if enabled
            if (self.heartbeat_timeout_ms > 0) {
                const now = common.milliTimestamp();
                const last_heartbeat = self.last_heartbeat_time.load(.acquire);
                // Compare in i64 — `now - last_heartbeat` can be negative (clock
                // skew / suspend-resume / NTP step) or exceed u32 (long pause).
                // The previous `@intCast(u32)` here trapped under either.
                const elapsed_ms = now - last_heartbeat;
                if (elapsed_ms > @as(i64, self.heartbeat_timeout_ms)) {
                    std.debug.print("[CLIENT] Heartbeat timeout! No heartbeat for {}ms (limit: {}ms)\n", .{ elapsed_ms, self.heartbeat_timeout_ms });
                    break; // Connection will be re-established by auto-reconnection logic
                }
            }

            // Build poll set: tunnel fd + current local connections
            poll_fds.clearRetainingCapacity();
            poll_entries.clearRetainingCapacity();

            poll_fds.append(global_allocator, .{
                .fd = self.tunnel_stream.socket.handle,
                .events = posix.POLL.IN,
                .revents = 0,
            }) catch unreachable;
            poll_entries.append(global_allocator, .{ .tunnel = {} }) catch unreachable;

            self.connections_mutex.lock();
            var iter = self.connections.iterator();
            while (iter.next()) |entry| {
                const conn_ptr = entry.value_ptr.*;
                conn_ptr.acquireRef();
                poll_entries.append(global_allocator, .{ .local = conn_ptr }) catch {
                    conn_ptr.releaseRef();
                    continue;
                };
                poll_fds.append(global_allocator, .{
                    .fd = conn_ptr.local_stream.socket.handle,
                    .events = posix.POLL.IN,
                    .revents = 0,
                }) catch {
                    _ = poll_entries.pop();
                    conn_ptr.releaseRef();
                    continue;
                };
            }
            self.connections_mutex.unlock();

            const ready = posix.poll(poll_fds.items, poll_timeout_ms) catch |err| {
                std.debug.print("[CLIENT] Poll error: {}\n", .{err});
                break;
            };

            if (ready == 0) {
                for (poll_entries.items) |entry| {
                    switch (entry) {
                        .local => |conn_ptr| conn_ptr.releaseRef(),
                        .tunnel => {},
                    }
                }
                continue; // Timeout, check heartbeat and loop
            }

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
                            std.debug.print("[CLIENT] Decoder buffer full; framing stalled\n", .{});
                            self.running.store(false, .release);
                            fatal_error = true;
                            break :loop;
                        }
                        const n = posix.read(self.tunnel_stream.socket.handle, dst) catch |err| {
                            std.debug.print("[CLIENT] Recv error: {}\n", .{err});
                            self.running.store(false, .release);
                            fatal_error = true;
                            break :loop;
                        };

                        if (n == 0) {
                            std.debug.print("[CLIENT] Tunnel server disconnected\n", .{});
                            self.running.store(false, .release);
                            fatal_error = true;
                            break :loop;
                        }

                        decoder.commitWrite(n);

                        // Process all complete frames
                        var decoder_had_error = false;
                        while (true) {
                            const maybe_frame = decoder.decodeMut() catch |decode_err| {
                                std.debug.print("[CLIENT] Decoder error: {}\n", .{decode_err});
                                decoder_had_error = true;
                                break;
                            };
                            if (maybe_frame) |frame_payload| {
                                self.handleMessage(frame_payload) catch |err| {
                                    std.debug.print("[CLIENT] Handle message error: {}\n", .{err});
                                };
                                continue;
                            }
                            break;
                        }

                        if (decoder_had_error) {
                            self.running.store(false, .release);
                            fatal_error = true;
                            break :loop;
                        }
                    },
                    .local => {
                        const conn = entry.local;
                        if (fd_info.revents != 0) {
                            self.handleLocalPollEvent(conn, fd_info.revents);
                        }
                        conn.releaseRef();
                    },
                }
            }

            if (fatal_error) {
                var release_idx = idx + 1;
                while (release_idx < poll_entries.items.len) : (release_idx += 1) {
                    switch (poll_entries.items[release_idx]) {
                        .local => |conn_ptr| conn_ptr.releaseRef(),
                        .tunnel => {},
                    }
                }
                break;
            }

            if (!self.running.load(.acquire)) break;
        }

        std.debug.print("[CLIENT] Tunnel handler stopping\n", .{});
        self.cleanup();
    }

    fn handleMessage(self: *TunnelClient, payload: []u8) !void {
        if (payload.len == 0) return;

        const message_slice = try self.channel.decryptFrameInPlace(payload);
        if (message_slice.len == 0) return;

        const msg_type: tunnel.MessageType = @enumFromInt(message_slice[0]);

        switch (msg_type) {
            .connect => {
                // Client doesn't receive CONNECT messages (only server does)
                // This would indicate a protocol error
                std.debug.print("[CLIENT] Unexpected CONNECT message (protocol error)\n", .{});
            },
            .connect_ack => {
                const ack = try tunnel.ConnectAckMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[CLIENT] CONNECT_ACK stream_id={}\n", .{ack.stream_id});
                // Connection established, local thread will start sending
            },
            .connect_error => {
                const err_msg = try tunnel.ConnectErrorMsg.decodeRef(message_slice);
                std.debug.print("[CLIENT] CONNECT_ERROR stream_id={} code={s} error={s}\n", .{ err_msg.stream_id, @tagName(err_msg.error_code), err_msg.error_msg });

                self.connections_mutex.lock();
                const maybe_conn = self.connections.fetchRemove(err_msg.stream_id);
                self.connections_mutex.unlock();

                if (maybe_conn) |entry| {
                    entry.value.stop();
                    entry.value.releaseRef();
                }
            },
            .data => {
                const data_msg = try tunnel.DataMsg.decode(message_slice);

                var conn_ref: ?*LocalConnection = null;
                self.connections_mutex.lock();
                if (self.connections.get(data_msg.stream_id)) |conn_entry| {
                    conn_entry.acquireRef();
                    conn_ref = conn_entry;
                }
                self.connections_mutex.unlock();

                if (conn_ref) |active_conn| {
                    defer active_conn.releaseRef();
                    if (!active_conn.fd_closed.load(.acquire)) {
                        common.writeAllToHandle(active_conn.local_stream.socket.handle, data_msg.data) catch |err| {
                            std.debug.print("[STREAM {}] Send to local failed: {}\n", .{ data_msg.stream_id, err });
                            self.completeLocalConnection(active_conn, true);
                        };
                    }
                }
            },
            .close => {
                const close_msg = try tunnel.CloseMsg.decode(message_slice);
                tracePrint(enable_tunnel_trace, "[CLIENT] CLOSE stream_id={}\n", .{close_msg.stream_id});

                self.connections_mutex.lock();
                const maybe_conn = self.connections.fetchRemove(close_msg.stream_id);
                self.connections_mutex.unlock();

                if (maybe_conn) |entry| {
                    entry.value.stop();
                    entry.value.releaseRef();
                    std.debug.print("[CLIENT] Connection {} cleaned up after CLOSE message\n", .{close_msg.stream_id});
                } else {
                    // Connection already cleaned itself up
                    tracePrint(enable_tunnel_trace, "[CLIENT] Connection {} already removed (self-cleanup)\n", .{close_msg.stream_id});
                }
            },
            .udp_data => {
                // Hot path: zero-alloc decode. Client.handleUdpData reads only
                // stream_id and data; source_addr is unused, so the slice
                // lifetime is trivially safe.
                const udp_msg = try tunnel.UdpDataMsg.decodeRef(message_slice);

                // Per-service-id routing (audit B-1). Map is read-only on
                // this thread once populated by tunnelThreadWithReconnection
                // before run() starts; no mutex needed.
                if (self.udp_forwarders.get(udp_msg.service_id)) |forwarder| {
                    forwarder.handleUdpData(udp_msg) catch |err| {
                        std.debug.print("[UDP-CLIENT] Failed to forward UDP data (service_id={}): {}\n", .{ udp_msg.service_id, err });
                    };
                } else {
                    tracePrint(enable_tunnel_trace, "[UDP-CLIENT] No forwarder for service_id={}, dropping {} bytes\n", .{ udp_msg.service_id, udp_msg.data.len });
                }
            },
            .heartbeat => {
                // Received heartbeat from server - update last heartbeat time
                const heartbeat_msg = try tunnel.HeartbeatMsg.decode(message_slice);
                self.last_heartbeat_time.store(common.milliTimestamp(), .release);
                tracePrint(enable_tunnel_trace, "[HEARTBEAT] Received from server: timestamp={}\n", .{heartbeat_msg.timestamp});
            },
            .version => {
                // Version exchange happens during handshake only
                // Receiving it here would be unexpected, just ignore
                tracePrint(enable_tunnel_trace, "[CLIENT] Unexpected VERSION message during operation (ignoring)\n", .{});
            },
            .reverse_connect => {
                // REVERSE MODE: Server requests reverse connection using new message format
                const msg = try tunnel.ReverseConnectMsg.decode(message_slice);

                std.debug.print("[CLIENT] REVERSE_CONNECT from server: service_id={} stream_id={}\n", .{
                    msg.service_id,
                    msg.stream_id,
                });

                // Look up reverse service configuration
                var found_service: ?config.Service = null;
                var iter = self.cfg.reverse_services.valueIterator();
                while (iter.next()) |svc| {
                    if (svc.id == msg.service_id) {
                        found_service = svc.*;
                        break;
                    }
                }

                const service = found_service orelse {
                    std.debug.print("[CLIENT] Unknown reverse service_id={}\n", .{msg.service_id});
                    // Send error back
                    const error_msg = tunnel.ConnectErrorMsg{
                        .service_id = msg.service_id,
                        .stream_id = msg.stream_id,
                        .error_code = .unknown_service,
                        .error_msg = "Unknown reverse service",
                    };
                    var encode_buf: [128]u8 = undefined;
                    const encoded_len = error_msg.encodeInto(&encode_buf) catch return;
                    self.channel.sendCopy(encode_buf[0..encoded_len]) catch {};
                    return;
                };

                // Connect to local service
                const address = common.resolveHostPort(global_io, service.address, service.port) catch |err| {
                    std.debug.print("[CLIENT] Failed to resolve reverse target {s}:{}: {}\n", .{ service.address, service.port, err });
                    return;
                };

                const local_stream = address.connect(global_io, .{ .mode = .stream }) catch |err| {
                    std.debug.print("[CLIENT] Failed to connect to local target {s}:{}: {}\n", .{ service.address, service.port, err });
                    const error_code: tunnel.ErrorCode = switch (err) {
                        error.ConnectionRefused => .connection_refused,
                        error.NetworkUnreachable => .connection_timeout,
                        else => .service_unavailable,
                    };
                    const error_msg = tunnel.ConnectErrorMsg{
                        .service_id = msg.service_id,
                        .stream_id = msg.stream_id,
                        .error_code = error_code,
                        .error_msg = "Failed to connect to local target",
                    };
                    var encode_buf: [128]u8 = undefined;
                    const encoded_len = error_msg.encodeInto(&encode_buf) catch return;
                    self.channel.sendCopy(encode_buf[0..encoded_len]) catch {};
                    return;
                };
                errdefer local_stream.close(global_io);
                setSockOpts(local_stream.socket.handle, self.cfg);

                std.debug.print("[CLIENT-REVERSE] Connected to local {s}:{} for stream {}\n", .{ service.address, service.port, msg.stream_id });

                // Create LocalConnection
                const conn = LocalConnection.create(global_allocator, msg.service_id, msg.stream_id, local_stream, self) catch |err| {
                    std.debug.print("[CLIENT] Failed to create reverse connection: {}\n", .{err});
                    local_stream.close(global_io);
                    return;
                };

                // Add to connections — create ref IS map ref.
                self.connections_mutex.lock();
                self.connections.put(msg.stream_id, conn) catch |err| {
                    self.connections_mutex.unlock();
                    std.debug.print("[CLIENT] Failed to store reverse connection: {}\n", .{err});
                    conn.stop();
                    conn.releaseRef(); // drop create ref → destroys
                    return;
                };
                self.connections_mutex.unlock();

                // Send CONNECT_ACK to server
                const ack_msg = tunnel.ConnectAckMsg{
                    .service_id = msg.service_id,
                    .stream_id = msg.stream_id,
                };
                var ack_buf: [64]u8 = undefined;
                const ack_len = ack_msg.encodeInto(&ack_buf) catch return;
                self.channel.sendCopy(ack_buf[0..ack_len]) catch {};
            },
        }
    }

    fn handleReverseConnect(self: *TunnelClient, msg: tunnel.ConnectMsg) !void {
        const binding = getServiceBinding(self.cfg, msg.service_id) catch {
            std.debug.print("[CLIENT-REVERSE] Unknown service_id={} requested by server\n", .{msg.service_id});
            return error.UnknownService;
        };

        std.debug.print("[CLIENT-REVERSE] Connecting to local target {s}:{} for stream_id={}\n", .{
            binding.host,
            binding.port,
            msg.stream_id,
        });

        const address = try common.resolveHostPort(global_io, binding.host, binding.port);
        const local_stream = try address.connect(global_io, .{ .mode = .stream });
        var stream_guard = true;
        errdefer if (stream_guard) local_stream.close(global_io);

        setSockOpts(local_stream.socket.handle, self.cfg);

        std.debug.print("[CLIENT-REVERSE] Connected to local target for stream_id={}\n", .{msg.stream_id});

        // Create LocalConnection to handle forwarding
        const conn = try LocalConnection.create(global_allocator, msg.service_id, msg.stream_id, local_stream, self);
        stream_guard = false;

        // Create ref IS map ref — no extra acquire.
        self.connections_mutex.lock();
        self.connections.put(msg.stream_id, conn) catch |err| {
            self.connections_mutex.unlock();
            conn.stop();
            conn.releaseRef(); // drop create ref → destroys
            return err;
        };
        self.connections_mutex.unlock();

        // Send CONNECT_ACK back to server
        const ack_msg = tunnel.ConnectAckMsg{
            .service_id = msg.service_id,
            .stream_id = msg.stream_id,
        };

        var encode_buf: [16]u8 = undefined; // ACK is 7 bytes
        const encoded_len = try ack_msg.encodeInto(&encode_buf);

        try self.channel.sendCopy(encode_buf[0..encoded_len]);

        std.debug.print("[CLIENT-REVERSE] Sent CONNECT_ACK to server for stream_id={}\n", .{msg.stream_id});
    }

    fn handleNewConnection(self: *TunnelClient, local_stream: Io.net.Stream) !void {
        return self.handleNewConnectionWithServiceId(local_stream, self.service_id);
    }

    fn handleNewConnectionWithServiceId(self: *TunnelClient, local_stream: Io.net.Stream, service_id: tunnel.ServiceId) !void {
        // Use TunnelClient's default token unless overridden by multi-service context
        return self.handleNewConnectionFull(local_stream, service_id, self.default_token);
    }

    fn handleNewConnectionFull(self: *TunnelClient, local_stream: Io.net.Stream, service_id: tunnel.ServiceId, token: []const u8) !void {
        const stream_id = self.next_stream_id.fetchAdd(1, .acq_rel);

        tracePrint(enable_tunnel_trace, "[CLIENT] New local connection, service_id={} stream_id={}\n", .{ service_id, stream_id });

        // Create local connection handler
        const conn = try LocalConnection.create(global_allocator, service_id, stream_id, local_stream, self);

        // Create ref IS map ref — no extra acquire.
        self.connections_mutex.lock();
        self.connections.put(stream_id, conn) catch |err| {
            self.connections_mutex.unlock();
            conn.stop();
            conn.releaseRef(); // drop create ref → destroys
            return err;
        };
        self.connections_mutex.unlock();

        // Send encrypted CONNECT message (no allocation - use stack buffer)
        const connect_msg = tunnel.ConnectMsg{
            .service_id = service_id,
            .stream_id = stream_id,
            .token = token,
        };

        // Use stack buffer for control message encoding
        var encode_buf: [512]u8 = undefined; // CONNECT messages are small (<100 bytes typically)
        const encoded_len = try connect_msg.encodeInto(&encode_buf);

        self.channel.sendCopy(encode_buf[0..encoded_len]) catch |err| {
            std.debug.print("[CLIENT] Failed to send CONNECT: {}\n", .{err});
            return err;
        };
    }

    fn handleLocalPollEvent(self: *TunnelClient, conn: *LocalConnection, revents: i16) void {
        var closed = false;
        if ((revents & posix.POLL.IN) != 0) {
            self.forwardLocalData(conn) catch |err| switch (err) {
                error.ConnectionClosed => {
                    self.completeLocalConnection(conn, false);
                    closed = true;
                },
                else => {
                    std.debug.print("[LOCAL {}] Forward error: {}\n", .{ conn.stream_id, err });
                    self.completeLocalConnection(conn, true);
                    closed = true;
                },
            };
        }

        const extra_error_mask: i16 = if (@hasDecl(posix.POLL, "NVAL")) posix.POLL.NVAL else 0;
        const error_mask: i16 = posix.POLL.HUP | posix.POLL.ERR | extra_error_mask;
        if (!closed and (revents & error_mask) != 0) {
            self.completeLocalConnection(conn, true);
        }
    }

    fn forwardLocalData(self: *TunnelClient, conn: *LocalConnection) anyerror!void {
        @setRuntimeSafety(false);
        const message_header_len: usize = 7;
        const io_batch = self.cfg.advanced.io_batch_bytes;

        // Ensure we don't overflow the buffer
        const max_read = @min(io_batch, conn.send_buffer.len - message_header_len - noise.TAG_LEN);

        const recv_slice = conn.send_buffer[message_header_len..][0..max_read];
        const n = posix.read(conn.local_stream.socket.handle, recv_slice) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };

        if (n == 0) {
            self.sendCloseFrame(conn.service_id, conn.stream_id);
            return error.ConnectionClosed;
        }

        if (!self.channel.isEncrypted()) {
            conn.send_buffer[0] = @intFromEnum(tunnel.MessageType.data);
            std.mem.writeInt(u16, conn.send_buffer[1..3], conn.service_id, .big);
            std.mem.writeInt(u32, conn.send_buffer[3..7], conn.stream_id, .big);

            const slice = conn.send_buffer[0 .. message_header_len + n];
            self.channel.sendDataInPlace(slice, message_header_len + n) catch |err| {
                std.debug.print("[LOCAL {}] send() error: {}\n", .{ conn.stream_id, err });
                self.handleSendFailure(err);
                return error.ConnectionClosed;
            };
            return;
        }

        // Zero-copy path for encrypted data
        conn.send_buffer[0] = @intFromEnum(tunnel.MessageType.data);
        std.mem.writeInt(u16, conn.send_buffer[1..3], conn.service_id, .big);
        std.mem.writeInt(u32, conn.send_buffer[3..7], conn.stream_id, .big);
        // Data is already at offset 7

        const payload_len = message_header_len + n;
        const slice = conn.send_buffer[0 .. payload_len + noise.TAG_LEN];
        self.channel.sendDataInPlace(slice, payload_len) catch |err| {
            std.debug.print("[LOCAL {}] send() error: {}\n", .{ conn.stream_id, err });
            self.handleSendFailure(err);
            return error.ConnectionClosed;
        };
    }

    fn completeLocalConnection(self: *TunnelClient, conn: *LocalConnection, send_close: bool) void {
        const already_closed = conn.fd_closed.load(.acquire);
        if (send_close and !already_closed) {
            self.sendCloseFrame(conn.service_id, conn.stream_id);
        }

        self.connections_mutex.lock();
        const removed = self.connections.fetchRemove(conn.stream_id);
        self.connections_mutex.unlock();
        if (removed) |_| {
            conn.releaseRef(); // drop map-held reference
        }

        conn.stop();
    }

    fn sendCloseFrame(self: *TunnelClient, service_id: tunnel.ServiceId, stream_id: tunnel.StreamId) void {
        var encode_buf: [16]u8 = undefined;
        const close_msg = tunnel.CloseMsg{ .service_id = service_id, .stream_id = stream_id };
        const encoded_len = close_msg.encodeInto(&encode_buf) catch return;
        self.channel.sendCopy(encode_buf[0..encoded_len]) catch {};
    }

    fn handleSendFailure(self: *TunnelClient, err: anyerror) void {
        if (!self.running.load(.acquire)) return;
        std.debug.print("[CLIENT] Tunnel send failure: {}\n", .{err});
        self.running.store(false, .release);
        _ = posix.system.shutdown(self.tunnel_stream.socket.handle, posix.SHUT.RDWR);
    }

    fn cleanup(self: *TunnelClient) void {
        // The udp_forwarders map is non-owning. Forwarders are owned by main
        // via UdpAttachment; clear the routing table here, the next
        // TunnelClient will be repopulated by tunnelThreadWithReconnection.
        self.udp_forwarders.clearRetainingCapacity();

        // Stop all connections
        while (true) {
            self.connections_mutex.lock();
            var iter = self.connections.iterator();
            const entry = iter.next();
            if (entry) |e| {
                const key_copy = e.key_ptr.*;
                const conn_ptr = e.value_ptr.*;
                _ = self.connections.remove(key_copy);
                self.connections_mutex.unlock();
                conn_ptr.stop();
                conn_ptr.releaseRef();
            } else {
                self.connections_mutex.unlock();
                break;
            }
        }
        self.connections.deinit();
    }

    fn destroy(self: *TunnelClient) void {
        // udp_forwarders map is non-owning — main owns the forwarders (see
        // UdpAttachment). Free only the map's internal storage.
        self.udp_forwarders.deinit();
        // Channel.deinit only frees its internal buffers — it does not close
        // the underlying stream (the caller owns it).
        self.channel.deinit();
        self.tunnel_stream.close(global_io);
        global_allocator.destroy(self);
    }
};

const TcpServiceListenerContext = struct {
    allocator: std.mem.Allocator,
    service_id: tunnel.ServiceId,
    local_host: []const u8,
    local_port: u16,
    token: []const u8,
    tunnel_clients: []?*TunnelClient,
    tunnel_clients_mutex: *std.Io.Mutex,
    num_tunnels: usize,
    socket_buffer_size: u32,
    tcp_options: TcpOptions,

    fn destroy(self: *TcpServiceListenerContext) void {
        self.allocator.free(self.local_host);
        self.allocator.free(self.token);
        self.allocator.destroy(self);
    }
};

inline fn loadTunnelClient(
    tunnel_clients: []?*TunnelClient,
    mutex: *std.Io.Mutex,
    index: usize,
) ?*TunnelClient {
    mutex.lockUncancelable(global_io);
    const client_opt = tunnel_clients[index];
    mutex.unlock(global_io);
    if (client_opt) |client| {
        if (!client.running.load(.acquire)) return null;
        return client;
    }
    return null;
}

fn joinServiceThreads(list: *std.ArrayListUnmanaged(std.Thread)) void {
    var idx: usize = list.items.len;
    while (idx > 0) {
        idx -= 1;
        list.items[idx].join();
    }
    list.clearRetainingCapacity();
}

fn joinTunnelThreads(threads: []?std.Thread) void {
    var idx: usize = 0;
    while (idx < threads.len) : (idx += 1) {
        if (threads[idx]) |thread| {
            thread.join();
            threads[idx] = null;
        }
    }
}

/// TCP service listener thread - handles one service
fn tcpServiceListener(ctx_ptr: *anyopaque) void {
    const ctx: *TcpServiceListenerContext = @ptrCast(@alignCast(ctx_ptr));
    defer ctx.destroy();

    const local_addr = common.resolveHostPort(global_io, ctx.local_host, ctx.local_port) catch |err| {
        std.debug.print("[TCP-SERVICE] Failed to parse address for service_id={}: {}\n", .{ ctx.service_id, err });
        return;
    };

    // Create listener via Io.net
    var server = local_addr.listen(global_io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("[TCP-SERVICE] Failed to listen on {s}:{} for service_id={}: {}\n", .{ ctx.local_host, ctx.local_port, ctx.service_id, err });
        return;
    };
    defer server.deinit(global_io);

    std.debug.print("[TCP-SERVICE] Listening on {s}:{} (service_id={})\n", .{ ctx.local_host, ctx.local_port, ctx.service_id });

    // Accept loop with round-robin distribution
    var next_tunnel: usize = 0;
    while (!shutdown_flag.load(.acquire)) {
        // Poll on the underlying handle so we can honor 1s shutdown checks.
        var fds = [_]posix.pollfd{
            .{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 },
        };
        const ready = posix.poll(&fds, 1000) catch continue;
        if (ready == 0) continue;

        const local_stream = server.accept(global_io) catch |err| {
            if (err == error.SocketNotListening) break;
            if (err == error.WouldBlock or err == error.ConnectionAborted) continue;
            std.debug.print("[TCP-SERVICE] Accept error for service_id={}: {}\n", .{ ctx.service_id, err });
            continue;
        };
        const local_fd = local_stream.socket.handle;

        tracePrint(enable_listener_trace, "[TCP-SERVICE] Accepted connection on service_id={}: fd={} -> tunnel {}\n", .{ ctx.service_id, local_fd, next_tunnel });
        tuneSocketBuffers(local_fd, ctx.socket_buffer_size);
        applyTcpOptions(local_fd, ctx.tcp_options);

        // Handle new connection via round-robin tunnel selection (skip null tunnels during reconnection)
        var attempts: usize = 0;
        var dispatched = false;
        while (attempts < ctx.num_tunnels) : (attempts += 1) {
            if (loadTunnelClient(ctx.tunnel_clients, ctx.tunnel_clients_mutex, next_tunnel)) |client| {
                client.handleNewConnectionFull(local_stream, ctx.service_id, ctx.token) catch |err| {
                    std.debug.print("[TCP-SERVICE] Failed to handle connection for service_id={}: {}\n", .{ ctx.service_id, err });
                    local_stream.close(global_io);
                };
                dispatched = true;
                break;
            }
            // Tunnel is reconnecting, try next one
            next_tunnel = (next_tunnel + 1) % ctx.num_tunnels;
        }
        if (!dispatched) {
            std.debug.print("[TCP-SERVICE] All tunnels down, rejecting connection\n", .{});
            local_stream.close(global_io);
        }

        // Round-robin to next tunnel
        next_tunnel = (next_tunnel + 1) % ctx.num_tunnels;
    }

    std.debug.print("[TCP-SERVICE] Service listener stopped for service_id={}\n", .{ctx.service_id});
}

/// Parameters for tunnel connection thread
const TunnelConnectionParams = struct {
    tunnel_index: usize,
    service_id: tunnel.ServiceId,
    remote_host: []const u8,
    remote_port: u16,
    cfg: *const config.ClientConfig,
    static_keypair: std.crypto.dh.X25519.KeyPair,
    tunnel_client_slot: *?*TunnelClient, // Pointer to store the created client
    tunnel_clients_mutex: *std.Io.Mutex,
    cpu_index: ?usize,
    /// Pointer to a list of UDP forwarder attachments owned by main. Read
    /// under `tunnel_clients_mutex` on each (re)connect so the tunnel picks
    /// up forwarders added after threads spawned. Null for tunnel indices
    /// that don't own UDP forwarding (i.e., everything except tunnel 0).
    udp_attachments: ?*std.ArrayListUnmanaged(*UdpAttachment) = null,
};

/// Tunnel connection thread with auto-reconnection
fn tunnelThreadWithReconnection(params_ptr: *TunnelConnectionParams) void {
    const params = params_ptr.*;
    clientApplyThreadAffinity(params.cpu_index);
    var retry_delay_ms = params.cfg.advanced.reconnect_initial_delay_ms;
    var attempt: usize = 0;

    while (!shutdown_flag.load(.acquire)) {
        attempt += 1;

        // Parse proxy config if provided
        var proxy_cfg_opt: ?proxy.ProxyConfig = null;
        if (params.cfg.advanced.proxy_url.len > 0) {
            proxy_cfg_opt = proxy.ProxyConfig.parseUrl(global_allocator, params.cfg.advanced.proxy_url) catch |err| {
                std.debug.print("[TUNNEL {}] Invalid proxy URL: {}\n", .{ params.tunnel_index, err });
                const ns = retry_delay_ms * std.time.ns_per_ms;
                Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
                retry_delay_ms = @min(retry_delay_ms * params.cfg.advanced.reconnect_backoff_multiplier, params.cfg.advanced.reconnect_max_delay_ms);
                continue;
            };
        }
        defer if (proxy_cfg_opt) |*cfg| cfg.deinit(global_allocator);

        if (proxy_cfg_opt) |proxy_cfg| {
            if (proxy_cfg.proxy_type != .none) {
                std.debug.print("[TUNNEL {}] Connecting via {s} proxy {s}:{}\n", .{
                    params.tunnel_index,
                    @tagName(proxy_cfg.proxy_type),
                    proxy_cfg.host,
                    proxy_cfg.port,
                });
            }
        }

        const tunnel_stream = proxy.connectWithProxy(
            global_io,
            global_allocator,
            proxy_cfg_opt,
            params.remote_host,
            params.remote_port,
        ) catch |err| {
            std.debug.print("[TUNNEL {}] Connection failed (attempt {}): {}, retrying in {}ms...\n", .{ params.tunnel_index, attempt, err, retry_delay_ms });
            {
                const ns = retry_delay_ms * std.time.ns_per_ms;
                Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
            }
            retry_delay_ms = @min(retry_delay_ms * params.cfg.advanced.reconnect_backoff_multiplier, params.cfg.advanced.reconnect_max_delay_ms);
            continue;
        };

        const tcp_options = TcpOptions{
            .nodelay = params.cfg.advanced.tcp_nodelay,
            .keepalive = params.cfg.advanced.tcp_keepalive,
            .keepalive_idle = params.cfg.advanced.tcp_keepalive_idle,
            .keepalive_interval = params.cfg.advanced.tcp_keepalive_interval,
            .keepalive_count = params.cfg.advanced.tcp_keepalive_count,
        };
        applyTcpOptions(tunnel_stream.socket.handle, tcp_options);
        tuneSocketBuffers(tunnel_stream.socket.handle, params.cfg.advanced.socket_buffer_size);

        // Successfully connected
        std.debug.print("[TUNNEL {}] Connected to {s}:{} (attempt {})\n", .{ params.tunnel_index, params.remote_host, params.remote_port, attempt });

        // Create tunnel client
        const tunnel_client = TunnelClient.create(
            global_allocator,
            tunnel_stream,
            params.service_id,
            params.cfg,
            params.static_keypair,
        ) catch |err| {
            std.debug.print("[TUNNEL {}] Failed to create client: {}\n", .{ params.tunnel_index, err });
            {
                const ns = retry_delay_ms * std.time.ns_per_ms;
                Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
            }
            retry_delay_ms = @min(retry_delay_ms * params.cfg.advanced.reconnect_backoff_multiplier, params.cfg.advanced.reconnect_max_delay_ms);
            continue;
        };

        // Store client reference for connection handling
        params.tunnel_clients_mutex.lockUncancelable(global_io);
        params.tunnel_client_slot.* = tunnel_client;
        params.tunnel_clients_mutex.unlock(global_io);

        // (Re)attach UDP forwarders to this fresh tunnel client. Outbound
        // routing reads `att.tunnel` atomically per-packet; inbound
        // dispatch uses `tunnel_client.udp_forwarders[service_id]`,
        // populated here. The attachment list is owned by main and can
        // grow over the process's lifetime — re-read on every reconnect.
        if (params.udp_attachments) |attachments_ptr| {
            params.tunnel_clients_mutex.lockUncancelable(global_io);
            for (attachments_ptr.items) |att| {
                tunnel_client.udp_forwarders.put(att.forwarder.service_id, att.forwarder) catch |err| {
                    std.debug.print("[CLIENT] Failed to register UDP route service_id={}: {}\n", .{ att.forwarder.service_id, err });
                    continue;
                };
                att.tunnel.store(tunnel_client, .release);
            }
            params.tunnel_clients_mutex.unlock(global_io);
        }

        // Reset retry delay on successful connection
        retry_delay_ms = params.cfg.advanced.reconnect_initial_delay_ms;

        // Run client (blocks until disconnection)
        tunnel_client.run();

        // Detach UDP forwarders before tearing down the tunnel client. The
        // forwarders themselves stay alive — main owns them.
        if (params.udp_attachments) |attachments_ptr| {
            params.tunnel_clients_mutex.lockUncancelable(global_io);
            for (attachments_ptr.items) |att| {
                att.tunnel.store(null, .release);
            }
            params.tunnel_clients_mutex.unlock(global_io);
        }

        // Cleanup after disconnection
        params.tunnel_clients_mutex.lockUncancelable(global_io);
        params.tunnel_client_slot.* = null;
        params.tunnel_clients_mutex.unlock(global_io);
        tunnel_client.destroy();

        // Check if reconnection is enabled
        if (!params.cfg.advanced.reconnect_enabled or shutdown_flag.load(.acquire)) {
            std.debug.print("[TUNNEL {}] Reconnection disabled or shutting down\n", .{params.tunnel_index});
            break;
        }

        std.debug.print("[TUNNEL {}] Disconnected, reconnecting in {}ms...\n", .{ params.tunnel_index, retry_delay_ms });
        {
            const ns = retry_delay_ms * std.time.ns_per_ms;
            Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
        }
    }

    std.debug.print("[TUNNEL {}] Thread exiting\n", .{params.tunnel_index});
}

// Note: the previous "forwardLocalData sends plaintext frames" inline test
// depended on posix.socketpair / GeneralPurposeAllocator / common.sendAllToFd
// which were removed in 0.16. The integration test harness (WP-03 in the
// remediation plan) will replace this coverage end-to-end.

pub fn main(init: std.process.Init) !void {
    // Zig 0.16: Init provides Io (Threaded backend by default) and the same gpa
    // start.zig used (DebugAllocator in debug, smp_allocator in release).
    const allocator = init.gpa;
    global_allocator = allocator;
    global_io = init.io;
    defer diagnostics.flushEncryptStats("client", &encrypt_total_ns, &encrypt_calls);
    defer diagnostics.flushThroughputStats("client", &tunnel_tx_bytes, &tunnel_rx_bytes);
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
    var cli_opts = parseClientArgs(allocator, args_list, &parse_ctx) catch |err| {
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
            ParseError.OutOfMemory => {
                std.debug.print("error: out of memory while parsing arguments\n", .{});
            },
        }
        printClientUsage();
        exit_code = 1;
        return;
    };
    defer cli_opts.deinit(allocator);

    // Store config path globally for reload / doctor modes
    config_path_global = cli_opts.config_path;

    switch (cli_opts.mode) {
        .help => {
            printClientUsage();
            return;
        },
        .version => {
            std.debug.print("flooc {s}\n", .{build_options.version});
            return;
        },
        .doctor => {
            const ok = try runClientDoctor(allocator, &cli_opts);
            if (!ok) exit_code = 1;
            return;
        },
        .ping => {
            const ok = try runClientPing(allocator, &cli_opts);
            if (!ok) exit_code = 1;
            return;
        },
        .run => {},
    }

    // Load config with any CLI overrides applied
    var cfg = try loadClientConfigWithOverrides(allocator, &cli_opts);
    defer cfg.deinit();
    const tunnels_were_auto = cfg.advanced.num_tunnels == 0;
    _ = effectiveTunnelCount(&cfg.advanced);

    const canonical_cipher = config.canonicalCipher(&cfg);
    if (std.mem.eql(u8, canonical_cipher, "none")) {
        std.debug.print("[WARN] Client encryption disabled; ensure tokens are treated as secrets.\n", .{});
    } else if (cfg.psk.len == 0) {
        std.debug.print("[WARN] Client PSK is empty; connection attempts will fail.\n", .{});
    } else if (std.mem.eql(u8, cfg.psk, config.DEFAULT_PSK)) {
        std.debug.print("[WARN] Client is using the placeholder PSK '{s}'. Change this before deployment.\n", .{config.DEFAULT_PSK});
    }

    var default_token_required = cfg.services.count() == 0;
    if (!default_token_required) {
        var iter = cfg.services.valueIterator();
        while (iter.next()) |service| {
            if (service.token.len == 0) {
                default_token_required = true;
                break;
            }
        }
    }

    if (default_token_required and cfg.token.len == 0) {
        std.debug.print("[WARN] Client default token is empty; server access control will fail.\n", .{});
    } else if (cfg.token.len > 0 and std.mem.eql(u8, cfg.token, config.DEFAULT_TOKEN)) {
        std.debug.print("[WARN] Client is using the placeholder token '{s}'. Update configs to a secret value.\n", .{config.DEFAULT_TOKEN});
    }

    const remote_host = try cfg.getServerHost();
    const remote_port = try cfg.getServerPort();

    // Get default service for single-service mode
    var default_service_id: tunnel.ServiceId = 0;
    var local_host: []const u8 = "127.0.0.1";
    var local_port: u16 = 9001;
    var default_transport: config.Transport = .tcp; // Default to TCP for single-service mode

    if (cfg.default_service) |service_name| {
        if (cfg.services.get(service_name)) |service| {
            default_service_id = service.id;
            local_host = service.address;
            local_port = service.port;
            default_transport = service.transport;
        }
    }

    std.debug.print("Floo Tunnel Client (flooc-blocking)\n", .{});
    std.debug.print("====================================\n\n", .{});
    std.debug.print("[CONFIG] Local:  {s}:{}\n", .{ local_host, local_port });
    std.debug.print("[CONFIG] Remote: {s}:{}\n", .{ remote_host, remote_port });
    if (default_service_id != 0) {
        std.debug.print("[CONFIG] Default Service ID: {}\n", .{default_service_id});
    } else {
        std.debug.print("[CONFIG] Default Service ID: (unset)\n", .{});
    }
    std.debug.print("[CONFIG] Services: {}\n", .{cfg.services.count()});
    const tunnels_note: []const u8 = if (tunnels_were_auto) " (auto)" else "";
    std.debug.print("[CONFIG] Parallel Tunnels: {}{s}\n", .{ cfg.advanced.num_tunnels, tunnels_note });
    std.debug.print("[CONFIG] Thread Pinning: {s}\n", .{if (cfg.advanced.pin_threads) "enabled" else "disabled"});
    std.debug.print("[CONFIG] IO Batch Bytes: {}\n", .{cfg.advanced.io_batch_bytes});
    std.debug.print("[CONFIG] Mode: Blocking I/O + Threads\n", .{});
    std.debug.print("[CONFIG] Hot Reload: Disabled (restart flooc to apply configuration changes)\n\n", .{});

    // Register signal handlers (POSIX only)
    if (@hasDecl(posix, "Sigaction") and @hasDecl(posix, "sigaction")) {
        if (builtin.target.os.tag != .windows) try setupSignalPipe();
        const sig_action = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = std.mem.zeroes(posix.sigset_t),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &sig_action, null);
        // SIGTERM previously unbound — handleSignal already accepts it,
        // but without sigaction the default action (process kill) runs
        // and `defer diagnostics.flush*` never fires.
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

    // Connect to tunnel server with parallel tunnels
    const num_tunnels = cfg.advanced.num_tunnels;
    std.debug.print("[CLIENT] Connecting {} parallel tunnels to {s}:{}...\n", .{ num_tunnels, remote_host, remote_port });

    // Generate persistent static keypair for Noise XX authentication
    const static_keypair = std.crypto.dh.X25519.KeyPair.generate(global_io);

    // Create array to hold tunnel clients (nullable since they reconnect)
    const tunnel_clients = try allocator.alloc(?*TunnelClient, num_tunnels);
    defer allocator.free(tunnel_clients);

    // Initialize all slots to null
    for (tunnel_clients) |*slot| {
        slot.* = null;
    }

    var tunnel_clients_mutex: std.Io.Mutex = .init;

    // Track tunnel and service threads so we can join them before cleanup
    const tunnel_threads = try allocator.alloc(?std.Thread, num_tunnels);
    defer allocator.free(tunnel_threads);
    for (tunnel_threads) |*thread_slot| {
        thread_slot.* = null;
    }

    var service_threads = std.ArrayListUnmanaged(std.Thread).empty;
    defer service_threads.deinit(allocator);
    try service_threads.ensureTotalCapacity(allocator, cfg.services.count());

    var threads_joined = false;
    errdefer {
        if (!threads_joined) {
            shutdown_flag.store(true, .release);
            joinServiceThreads(&service_threads);
            joinTunnelThreads(tunnel_threads);
            threads_joined = true;
        }
    }

    // UDP forwarder attachments shared across reconnects. Owned by main;
    // tunnel-0's reconnection thread reads this list under
    // `tunnel_clients_mutex` on every (re)connect to (re-)bind UDP routing
    // (audit fix A-1 / plan P3-1).
    var udp_attachments = std.ArrayListUnmanaged(*UdpAttachment).empty;
    defer {
        // Stop and free every forwarder + attachment we own. Tunnel threads
        // have already exited at this point (their joins are above this
        // defer in the cleanup ordering, see joinTunnelThreads paths).
        for (udp_attachments.items) |att| {
            att.forwarder.stop();
            att.forwarder.destroy();
            allocator.destroy(att);
        }
        udp_attachments.deinit(allocator);
    }

    // Create connection parameters for each tunnel
    const tunnel_params = try allocator.alloc(TunnelConnectionParams, num_tunnels);
    defer allocator.free(tunnel_params);

    // Connect each tunnel (all share the same static identity)
    for (0..num_tunnels) |i| {
        const cpu_index = if (cfg.advanced.pin_threads) clientNextCpuIndex() else null;
        tunnel_params[i] = .{
            .tunnel_index = i,
            .service_id = default_service_id,
            .remote_host = remote_host,
            .remote_port = remote_port,
            .cfg = &cfg,
            .static_keypair = static_keypair,
            .tunnel_client_slot = &tunnel_clients[i],
            .tunnel_clients_mutex = &tunnel_clients_mutex,
            .cpu_index = cpu_index,
            // Only tunnel 0 owns UDP forwarding today.
            .udp_attachments = if (i == 0) &udp_attachments else null,
        };

        // Spawn tunnel handler thread with reconnection
        const tunnel_thread = try std.Thread.spawn(.{
            .stack_size = common.TUNNEL_THREAD_STACK,
        }, tunnelThreadWithReconnection, .{&tunnel_params[i]});
        tunnel_threads[i] = tunnel_thread;
    }

    std.debug.print("[CLIENT] All tunnel threads started (reconnection: {})\n", .{cfg.advanced.reconnect_enabled});
    var shutdown_notice_printed = false;

    // Track UDP forwarders created in multi-service mode so we can periodically
    // prune expired sessions (otherwise UdpSessionManager grows unbounded under
    // long-lived processes with churn).
    var multi_service_udp_forwarders = std.ArrayListUnmanaged(*udp_client.UdpForwarder).empty;
    defer multi_service_udp_forwarders.deinit(allocator);

    // Check if multi-service mode is enabled
    if (cfg.services.count() > 0) {
        std.debug.print("\n[MULTI-SERVICE] Starting {} services...\n", .{cfg.services.count()});

        // Create listeners/forwarders for each service
        var service_iter = cfg.services.valueIterator();
        while (service_iter.next()) |service| {
            std.debug.print("[SERVICE] Starting service '{s}' (id={}, transport={any}, local={s}:{})\n", .{
                service.name,
                service.id,
                service.transport,
                service.address,
                service.port,
            });

            if (service.transport == .tcp) {
                // Create TCP listener thread for this service
                const effective_token = if (service.token.len > 0) service.token else cfg.token;
                const token_copy = try allocator.dupe(u8, effective_token);
                errdefer allocator.free(token_copy);
                const local_host_copy = try allocator.dupe(u8, service.address);
                errdefer allocator.free(local_host_copy);

                const ctx = try allocator.create(TcpServiceListenerContext);
                ctx.* = .{
                    .allocator = allocator,
                    .service_id = service.id,
                    .local_host = local_host_copy,
                    .local_port = service.port,
                    .token = token_copy,
                    .tunnel_clients = tunnel_clients,
                    .tunnel_clients_mutex = &tunnel_clients_mutex,
                    .num_tunnels = num_tunnels,
                    .socket_buffer_size = cfg.advanced.socket_buffer_size,
                    .tcp_options = TcpOptions{
                        .nodelay = cfg.advanced.tcp_nodelay,
                        .keepalive = cfg.advanced.tcp_keepalive,
                        .keepalive_idle = cfg.advanced.tcp_keepalive_idle,
                        .keepalive_interval = cfg.advanced.tcp_keepalive_interval,
                        .keepalive_count = cfg.advanced.tcp_keepalive_count,
                    },
                };
                // Ownership transferred to ctx
                const thread = try std.Thread.spawn(.{}, tcpServiceListener, .{ctx});
                service_threads.appendAssumeCapacity(thread);
            } else if (service.transport == .udp) {
                // Wait for first tunnel to be available
                while (loadTunnelClient(tunnel_clients, &tunnel_clients_mutex, 0) == null and !shutdown_flag.load(.acquire)) {
                    const ns = 100 * std.time.ns_per_ms;
                    Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
                }

                if (loadTunnelClient(tunnel_clients, &tunnel_clients_mutex, 0)) |first_client| {
                    const effective_token = if (service.token.len > 0) service.token else cfg.token;
                    // Allocate attachment first; the forwarder needs its
                    // address (used as opaque pointer in send_fn) at create.
                    const att = try allocator.create(UdpAttachment);
                    errdefer allocator.destroy(att);
                    att.* = UdpAttachment.init(undefined);

                    const forwarder = try udp_client.UdpForwarder.create(
                        allocator,
                        global_io,
                        service.id,
                        service.address,
                        service.port,
                        @ptrCast(att),
                        sendTunnelPayload,
                        cfg.advanced.udp_timeout_seconds,
                    );
                    att.forwarder = forwarder;
                    att.tunnel.store(first_client, .release);

                    // Register attachment so the tunnel-0 reconnection thread
                    // re-binds it on every reconnect (audit fix A-1).
                    tunnel_clients_mutex.lockUncancelable(global_io);
                    udp_attachments.append(allocator, att) catch {};
                    tunnel_clients_mutex.unlock(global_io);

                    // Inbound dispatch on the current tunnel client (B-1:
                    // multiple UDP services route by service_id).
                    try first_client.udp_forwarders.put(service.id, forwarder);
                    // Tracked separately for periodic session eviction.
                    multi_service_udp_forwarders.append(allocator, forwarder) catch {};

                    // Send initial CONNECT message for UDP service
                    const stream_id = first_client.next_stream_id.fetchAdd(1, .acq_rel);
                    const connect_msg = tunnel.ConnectMsg{
                        .service_id = service.id,
                        .stream_id = stream_id,
                        .token = effective_token,
                    };

                    var encode_buf: [512]u8 = undefined;
                    const encoded_len = try connect_msg.encodeInto(&encode_buf);
                    try first_client.channel.sendCopy(encode_buf[0..encoded_len]);

                    std.debug.print("[UDP-SERVICE] Service '{s}' ready on {s}:{}\n", .{ service.name, service.address, service.port });
                }
            }
        }

        std.debug.print("\n[READY] All services ready. Press Ctrl+C to stop.\n\n", .{});

        // Wait for shutdown signal. Tick every 250ms; once per second we run
        // UDP session eviction across all forwarders.
        var udp_evict_counter: u8 = 0;
        while (!shutdown_flag.load(.acquire)) {
            processSignalNotifications(&shutdown_notice_printed);
            {
                const ns = 250 * std.time.ns_per_ms;
                Io.sleep(global_io, .fromNanoseconds(@intCast(ns)), .awake) catch {};
            }
            udp_evict_counter +%= 1;
            if (udp_evict_counter >= 4) { // ~1s
                udp_evict_counter = 0;
                for (multi_service_udp_forwarders.items) |fwd| {
                    fwd.cleanupExpiredSessions() catch {};
                }
            }
        }
    } else {
        // TCP mode: create local listener via Io.net
        const local_addr = try common.resolveHostPort(global_io, local_host, local_port);
        var server = try local_addr.listen(global_io, .{ .reuse_address = true });
        defer server.deinit(global_io);

        std.debug.print("[LISTENER] Listening on {s}:{}\n", .{ local_host, local_port });
        std.debug.print("[READY] Client ready. Press Ctrl+C to stop.\n\n", .{});

        // Accept loop with round-robin distribution
        var next_tunnel: usize = 0;
        while (!shutdown_flag.load(.acquire)) {
            processSignalNotifications(&shutdown_notice_printed);
            var fds = [_]posix.pollfd{
                .{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 },
            };
            const ready = posix.poll(&fds, 1000) catch continue;
            if (ready == 0) continue;

            const local_stream = server.accept(global_io) catch |err| {
                if (err == error.SocketNotListening) break;
                if (err == error.WouldBlock or err == error.ConnectionAborted) continue;
                std.debug.print("[LISTENER] Accept error: {}\n", .{err});
                continue;
            };
            const local_fd = local_stream.socket.handle;

            tracePrint(enable_listener_trace, "[LISTENER] Accepted local connection: fd={} -> tunnel {}\n", .{ local_fd, next_tunnel });
            tuneSocketBuffers(local_fd, cfg.advanced.socket_buffer_size);
            const tcp_opts = TcpOptions{
                .nodelay = cfg.advanced.tcp_nodelay,
                .keepalive = cfg.advanced.tcp_keepalive,
                .keepalive_idle = cfg.advanced.tcp_keepalive_idle,
                .keepalive_interval = cfg.advanced.tcp_keepalive_interval,
                .keepalive_count = cfg.advanced.tcp_keepalive_count,
            };
            applyTcpOptions(local_fd, tcp_opts);

            // Handle new connection via round-robin tunnel selection
            var attempts: usize = 0;
            var dispatched = false;
            while (attempts < num_tunnels) : (attempts += 1) {
                if (loadTunnelClient(tunnel_clients, &tunnel_clients_mutex, next_tunnel)) |client| {
                    client.handleNewConnection(local_stream) catch |err| {
                        std.debug.print("[LISTENER] Failed to handle connection: {}\n", .{err});
                        local_stream.close(global_io);
                    };
                    dispatched = true;
                    break;
                }
                next_tunnel = (next_tunnel + 1) % num_tunnels;
            }
            if (!dispatched) {
                std.debug.print("[LISTENER] All tunnels down, rejecting connection\n", .{});
                local_stream.close(global_io);
            }

            next_tunnel = (next_tunnel + 1) % num_tunnels;
        }
    }

    if (!threads_joined) {
        shutdown_flag.store(true, .release);
        joinServiceThreads(&service_threads);
        joinTunnelThreads(tunnel_threads);
        threads_joined = true;
    }

    std.debug.print("\n[SHUTDOWN] Client stopped.\n", .{});
}
