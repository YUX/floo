const std = @import("std");
const tunnel = @import("tunnel.zig");

pub const DEFAULT_PSK = "change-me-psk";
pub const DEFAULT_TOKEN = "change-me-token";

pub const Transport = enum {
    tcp,
    udp,

    pub fn fromString(s: []const u8) ?Transport {
        if (std.mem.eql(u8, s, "tcp")) return .tcp;
        if (std.mem.eql(u8, s, "udp")) return .udp;
        return null;
    }
};

pub const ServiceMode = enum {
    forward,  // Server connects to target (default, current behavior)
    reverse,  // Server listens, client connects to target (new!)

    pub fn fromString(s: []const u8) ?ServiceMode {
        if (std.mem.eql(u8, s, "forward")) return .forward;
        if (std.mem.eql(u8, s, "reverse")) return .reverse;
        return null;
    }
};

fn dupString(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return allocator.dupe(u8, value);
}

pub const ServerServiceConfig = struct {
    name: []const u8,
    service_id: tunnel.ServiceId,
    transport: Transport,
    mode: ServiceMode,
    target_host: []const u8,
    target_port: u16,
    local_port: u16,  // For reverse mode: port server listens on
    token: []const u8,

    fn deinit(self: *ServerServiceConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.target_host);
        allocator.free(self.token);
    }
};

pub const ServiceConfig = struct {
    name: []const u8,
    service_id: tunnel.ServiceId,
    transport: Transport,
    local_port: u16,
    target_host: []const u8,
    target_port: u16,
    token: []const u8,

    fn deinit(self: *ServiceConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.target_host);
        allocator.free(self.token);
    }
};

pub const ServerConfig = struct {
    allocator: std.mem.Allocator,
    port: u16,
    host: []const u8,
    transport: Transport,
    udp_timeout_seconds: u64,
    socket_buffer_size: u32,
    tcp_nodelay: bool,
    tcp_keepalive: bool,
    tcp_keepalive_idle: u32,
    tcp_keepalive_interval: u32,
    tcp_keepalive_count: u32,
    heartbeat_interval_seconds: u32,
    cipher: []const u8,
    psk: []const u8,
    default_token: []const u8,
    services: std.AutoHashMap(tunnel.ServiceId, ServerServiceConfig),
    has_services: bool,

    pub fn init(allocator: std.mem.Allocator) !ServerConfig {
        var config = ServerConfig{
            .allocator = allocator,
            .port = 8000,
            .host = undefined,
            .transport = .tcp,
            .udp_timeout_seconds = 60,
            .socket_buffer_size = 4 * 1024 * 1024,
            .tcp_nodelay = true,
            .tcp_keepalive = true,
            .tcp_keepalive_idle = 60,
            .tcp_keepalive_interval = 10,
            .tcp_keepalive_count = 3,
            .heartbeat_interval_seconds = 30,
            .cipher = undefined,
            .psk = undefined,
            .default_token = undefined,
            .services = std.AutoHashMap(tunnel.ServiceId, ServerServiceConfig).init(allocator),
            .has_services = false,
        };
        errdefer config.services.deinit();

        config.host = try dupString(allocator, "0.0.0.0");
        errdefer allocator.free(config.host);

        config.cipher = try dupString(allocator, "aes256gcm");
        errdefer allocator.free(config.cipher);

        config.psk = try dupString(allocator, DEFAULT_PSK);
        errdefer allocator.free(config.psk);

        config.default_token = try dupString(allocator, DEFAULT_TOKEN);
        errdefer allocator.free(config.default_token);

        try config.validateSecurity();
        return config;
    }

    pub fn deinit(self: *ServerConfig) void {
        var it = self.services.valueIterator();
        while (it.next()) |service| {
            service.deinit(self.allocator);
        }
        self.services.deinit();
        self.allocator.free(self.host);
        self.allocator.free(self.cipher);
        self.allocator.free(self.psk);
        self.allocator.free(self.default_token);
        self.* = undefined;
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !ServerConfig {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Using defaults with placeholder secrets; update psk/token before production.\n", .{path});
                var defaults = try ServerConfig.init(allocator);
                try defaults.validateSecurity();
                return defaults;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        return try parseServerConfig(allocator, content);
    }

    fn parseServerConfig(allocator: std.mem.Allocator, content: []const u8) !ServerConfig {
        var config = try ServerConfig.init(allocator);
        errdefer config.deinit();

        var lines = std.mem.splitScalar(u8, content, '\n');
        var current_section: []const u8 = "server";
        var current_service_name: ?[]const u8 = null;
        var current_service: ?ServerServiceConfig = null;
        errdefer if (current_service) |*svc| svc.deinit(allocator);

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                try finalizePendingService(&config, &current_service_name, &current_service);

                const section = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
                if (std.mem.startsWith(u8, section, "server.services.")) {
                    const name = section["server.services.".len..];
                    const service = ServerServiceConfig{
                        .name = try dupString(allocator, name),
                        .service_id = 0,
                        .transport = config.transport,
                        .mode = .forward,  // Default to forward mode
                        .target_host = try dupString(allocator, ""),
                        .target_port = 0,
                        .local_port = 0,  // For reverse mode
                        .token = try dupString(allocator, ""),
                    };
                    current_section = "server.services";
                    current_service_name = service.name;
                    current_service = service;
                } else if (std.mem.eql(u8, section, "server")) {
                    current_section = "server";
                } else {
                    return error.UnknownSection;
                }
                continue;
            }

            const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value_with_comment = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t\"");
            const value = if (std.mem.indexOfScalar(u8, value_with_comment, '#')) |comment_pos|
                std.mem.trim(u8, value_with_comment[0..comment_pos], " \t\"")
            else
                value_with_comment;

            if (std.mem.eql(u8, current_section, "server.services")) {
                if (current_service) |*service| {
                    if (std.mem.eql(u8, key, "id")) {
                        service.service_id = std.fmt.parseInt(tunnel.ServiceId, value, 10) catch service.service_id;
                    } else if (std.mem.eql(u8, key, "mode")) {
                        service.mode = ServiceMode.fromString(value) orelse service.mode;
                    } else if (std.mem.eql(u8, key, "transport")) {
                        service.transport = Transport.fromString(value) orelse service.transport;
                    } else if (std.mem.eql(u8, key, "local_port")) {
                        service.local_port = std.fmt.parseInt(u16, value, 10) catch service.local_port;
                    } else if (std.mem.eql(u8, key, "target_host")) {
                        allocator.free(service.target_host);
                        service.target_host = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "target_port")) {
                        service.target_port = std.fmt.parseInt(u16, value, 10) catch service.target_port;
                    } else if (std.mem.eql(u8, key, "token")) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, value);
                    }
                }
            } else {
                if (std.mem.eql(u8, key, "port")) {
                    config.port = std.fmt.parseInt(u16, value, 10) catch config.port;
                } else if (std.mem.eql(u8, key, "host")) {
                    allocator.free(config.host);
                    config.host = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "transport")) {
                    config.transport = Transport.fromString(value) orelse config.transport;
                } else if (std.mem.eql(u8, key, "udp_timeout_seconds")) {
                    config.udp_timeout_seconds = std.fmt.parseInt(u64, value, 10) catch config.udp_timeout_seconds;
                } else if (std.mem.eql(u8, key, "socket_buffer_size")) {
                    config.socket_buffer_size = std.fmt.parseInt(u32, value, 10) catch config.socket_buffer_size;
                } else if (std.mem.eql(u8, key, "tcp_nodelay")) {
                    config.tcp_nodelay = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "tcp_keepalive")) {
                    config.tcp_keepalive = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "tcp_keepalive_idle")) {
                    config.tcp_keepalive_idle = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_idle;
                } else if (std.mem.eql(u8, key, "tcp_keepalive_interval")) {
                    config.tcp_keepalive_interval = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_interval;
                } else if (std.mem.eql(u8, key, "tcp_keepalive_count")) {
                    config.tcp_keepalive_count = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_count;
                } else if (std.mem.eql(u8, key, "heartbeat_interval_seconds")) {
                    config.heartbeat_interval_seconds = std.fmt.parseInt(u32, value, 10) catch config.heartbeat_interval_seconds;
                } else if (std.mem.eql(u8, key, "cipher")) {
                    allocator.free(config.cipher);
                    config.cipher = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "psk")) {
                    allocator.free(config.psk);
                    config.psk = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "default_token")) {
                    allocator.free(config.default_token);
                    config.default_token = try dupString(allocator, value);
                }
            }
        }

        try finalizePendingService(&config, &current_service_name, &current_service);

        if (!config.has_services) return error.NoServicesConfigured;

        try config.validateSecurity();
        return config;
    }

    fn finalizePendingService(config: *ServerConfig, service_name: *?[]const u8, service: *?ServerServiceConfig) !void {
        if (service.*) |*svc| {
            if (svc.service_id == 0) {
                svc.deinit(config.allocator);
                service.* = null;
                service_name.* = null;
                return error.ServiceMissingId;
            }
            if (svc.target_host.len == 0 or svc.target_port == 0) {
                svc.deinit(config.allocator);
                service.* = null;
                service_name.* = null;
                return error.ServiceMissingTarget;
            }
            if (config.services.get(svc.service_id) != null) {
                svc.deinit(config.allocator);
                service.* = null;
                service_name.* = null;
                return error.DuplicateServiceId;
            }

            try config.services.put(svc.service_id, svc.*);
            config.has_services = true;
            service.* = null;
            service_name.* = null;
        }
    }

    pub fn getService(self: *const ServerConfig, id: tunnel.ServiceId) ?*const ServerServiceConfig {
        return self.services.getPtr(id);
    }

    fn validateSecurity(self: *ServerConfig) !void {
        const encryption_enabled = !std.ascii.eqlIgnoreCase(self.cipher, "none");
        if (encryption_enabled and self.psk.len == 0) return error.MissingPsk;

        var requires_default = false;
        var iter = self.services.valueIterator();
        while (iter.next()) |service| {
            if (service.token.len == 0) {
                requires_default = true;
                break;
            }
        }

        if (requires_default and self.default_token.len == 0) return error.MissingToken;
    }
};

pub const ClientConfig = struct {
    allocator: std.mem.Allocator,
    local_host: []const u8,
    local_port: u16,
    target_host: []const u8,
    target_port: u16,
    transport: Transport,
    remote_host: []const u8,
    remote_port: u16,
    service_id: tunnel.ServiceId,
    services: std.StringHashMap(ServiceConfig),
    has_services: bool,
    udp_timeout_seconds: u64,
    num_tunnels: usize,
    socket_buffer_size: u32,
    tcp_nodelay: bool,
    tcp_keepalive: bool,
    tcp_keepalive_idle: u32,
    tcp_keepalive_interval: u32,
    tcp_keepalive_count: u32,
    heartbeat_timeout_seconds: u32,
    reconnect_enabled: bool,
    reconnect_initial_delay_ms: u64,
    reconnect_max_delay_ms: u64,
    reconnect_backoff_multiplier: u64,
    cipher: []const u8,
    psk: []const u8,
    default_token: []const u8,
    proxy_url: []const u8, // Proxy URL (e.g., "socks5://127.0.0.1:1080" or "http://proxy:8080")

    pub fn init(allocator: std.mem.Allocator) !ClientConfig {
        var config = ClientConfig{
            .allocator = allocator,
            .local_host = undefined,
            .local_port = 9001,
            .target_host = undefined,
            .target_port = 8080,
            .transport = .tcp,
            .remote_host = undefined,
            .remote_port = 8000,
            .service_id = 0,
            .services = std.StringHashMap(ServiceConfig).init(allocator),
            .has_services = false,
            .udp_timeout_seconds = 60,
            .num_tunnels = 4,
            .socket_buffer_size = 4 * 1024 * 1024,
            .tcp_nodelay = true,
            .tcp_keepalive = true,
            .tcp_keepalive_idle = 60,
            .tcp_keepalive_interval = 10,
            .tcp_keepalive_count = 3,
            .heartbeat_timeout_seconds = 40,
            .reconnect_enabled = true,
            .reconnect_initial_delay_ms = 1000,
            .reconnect_max_delay_ms = 30000,
            .reconnect_backoff_multiplier = 2,
            .cipher = undefined,
            .psk = undefined,
            .default_token = undefined,
            .proxy_url = undefined,
        };
        errdefer config.services.deinit();

        config.local_host = try dupString(allocator, "127.0.0.1");
        errdefer allocator.free(config.local_host);

        config.target_host = try dupString(allocator, "127.0.0.1");
        errdefer allocator.free(config.target_host);

        config.remote_host = try dupString(allocator, "127.0.0.1");
        errdefer allocator.free(config.remote_host);

        config.cipher = try dupString(allocator, "aes256gcm");
        errdefer allocator.free(config.cipher);

        config.psk = try dupString(allocator, DEFAULT_PSK);
        errdefer allocator.free(config.psk);

        config.default_token = try dupString(allocator, DEFAULT_TOKEN);
        errdefer allocator.free(config.default_token);

        config.proxy_url = try dupString(allocator, "");
        errdefer allocator.free(config.proxy_url);

        return config;
    }

    pub fn deinit(self: *ClientConfig) void {
        var iter = self.services.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.services.deinit();
        self.allocator.free(self.local_host);
        self.allocator.free(self.target_host);
        self.allocator.free(self.remote_host);
        self.allocator.free(self.cipher);
        self.allocator.free(self.psk);
        self.allocator.free(self.default_token);
        self.allocator.free(self.proxy_url);
        self.* = undefined;
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !ClientConfig {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Using defaults with placeholder secrets; update psk/token before production.\n", .{path});
                var defaults = try ClientConfig.init(allocator);
                try defaults.validateSecurity();
                return defaults;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        return try parseClientConfig(allocator, content);
    }

    fn parseClientConfig(allocator: std.mem.Allocator, content: []const u8) !ClientConfig {
        var config = try ClientConfig.init(allocator);
        errdefer config.deinit();

        var lines = std.mem.splitScalar(u8, content, '\n');
        var current_section: []const u8 = "client";
        var current_service_name: ?[]const u8 = null;
        var current_service: ?ServiceConfig = null;
        errdefer if (current_service) |*svc| svc.deinit(allocator);

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                try finalizePendingService(&config, &current_service_name, &current_service);

                const section = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
                if (std.mem.startsWith(u8, section, "client.services.")) {
                    const name = section["client.services.".len..];
                    const service = ServiceConfig{
                        .name = try dupString(allocator, name),
                        .service_id = 0,
                        .transport = .tcp,
                        .local_port = 0,
                        .target_host = try dupString(allocator, ""),
                        .target_port = 0,
                        .token = try dupString(allocator, ""),
                    };
                    current_section = "client.services";
                    current_service_name = service.name;
                    current_service = service;
                } else if (std.mem.eql(u8, section, "client")) {
                    current_section = "client";
                } else {
                    return error.UnknownSection;
                }
                continue;
            }

            const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value_with_comment = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t\"");
            const value = if (std.mem.indexOfScalar(u8, value_with_comment, '#')) |comment_pos|
                std.mem.trim(u8, value_with_comment[0..comment_pos], " \t\"")
            else
                value_with_comment;

            if (std.mem.eql(u8, current_section, "client.services")) {
                if (current_service) |*service| {
                    if (std.mem.eql(u8, key, "type")) {
                        service.transport = Transport.fromString(value) orelse service.transport;
                    } else if (std.mem.eql(u8, key, "local_port")) {
                        service.local_port = std.fmt.parseInt(u16, value, 10) catch service.local_port;
                    } else if (std.mem.eql(u8, key, "target_host")) {
                        allocator.free(service.target_host);
                        service.target_host = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "target_port")) {
                        service.target_port = std.fmt.parseInt(u16, value, 10) catch service.target_port;
                    } else if (std.mem.eql(u8, key, "token")) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "service_id") or std.mem.eql(u8, key, "id")) {
                        service.service_id = std.fmt.parseInt(tunnel.ServiceId, value, 10) catch service.service_id;
                    }
                }
            } else {
                if (std.mem.eql(u8, key, "local_host")) {
                    allocator.free(config.local_host);
                    config.local_host = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "local_port")) {
                    config.local_port = std.fmt.parseInt(u16, value, 10) catch config.local_port;
                } else if (std.mem.eql(u8, key, "remote_host")) {
                    allocator.free(config.remote_host);
                    config.remote_host = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "remote_port")) {
                    config.remote_port = std.fmt.parseInt(u16, value, 10) catch config.remote_port;
                } else if (std.mem.eql(u8, key, "target_host")) {
                    allocator.free(config.target_host);
                    config.target_host = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "target_port")) {
                    config.target_port = std.fmt.parseInt(u16, value, 10) catch config.target_port;
                } else if (std.mem.eql(u8, key, "transport")) {
                    config.transport = Transport.fromString(value) orelse config.transport;
                } else if (std.mem.eql(u8, key, "udp_timeout_seconds")) {
                    config.udp_timeout_seconds = std.fmt.parseInt(u64, value, 10) catch config.udp_timeout_seconds;
                } else if (std.mem.eql(u8, key, "num_tunnels")) {
                    config.num_tunnels = std.fmt.parseInt(usize, value, 10) catch config.num_tunnels;
                } else if (std.mem.eql(u8, key, "socket_buffer_size")) {
                    config.socket_buffer_size = std.fmt.parseInt(u32, value, 10) catch config.socket_buffer_size;
                } else if (std.mem.eql(u8, key, "tcp_nodelay")) {
                    config.tcp_nodelay = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "tcp_keepalive")) {
                    config.tcp_keepalive = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "tcp_keepalive_idle")) {
                    config.tcp_keepalive_idle = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_idle;
                } else if (std.mem.eql(u8, key, "tcp_keepalive_interval")) {
                    config.tcp_keepalive_interval = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_interval;
                } else if (std.mem.eql(u8, key, "tcp_keepalive_count")) {
                    config.tcp_keepalive_count = std.fmt.parseInt(u32, value, 10) catch config.tcp_keepalive_count;
                } else if (std.mem.eql(u8, key, "heartbeat_timeout_seconds")) {
                    config.heartbeat_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch config.heartbeat_timeout_seconds;
                } else if (std.mem.eql(u8, key, "reconnect_enabled")) {
                    config.reconnect_enabled = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "reconnect_initial_delay_ms")) {
                    config.reconnect_initial_delay_ms = std.fmt.parseInt(u64, value, 10) catch config.reconnect_initial_delay_ms;
                } else if (std.mem.eql(u8, key, "reconnect_max_delay_ms")) {
                    config.reconnect_max_delay_ms = std.fmt.parseInt(u64, value, 10) catch config.reconnect_max_delay_ms;
                } else if (std.mem.eql(u8, key, "reconnect_backoff_multiplier")) {
                    config.reconnect_backoff_multiplier = std.fmt.parseInt(u64, value, 10) catch config.reconnect_backoff_multiplier;
                } else if (std.mem.eql(u8, key, "cipher")) {
                    allocator.free(config.cipher);
                    config.cipher = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "psk")) {
                    allocator.free(config.psk);
                    config.psk = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "default_token")) {
                    allocator.free(config.default_token);
                    config.default_token = try dupString(allocator, value);
                } else if (std.mem.eql(u8, key, "service_id")) {
                    config.service_id = std.fmt.parseInt(tunnel.ServiceId, value, 10) catch config.service_id;
                } else if (std.mem.eql(u8, key, "proxy_url")) {
                    allocator.free(config.proxy_url);
                    config.proxy_url = try dupString(allocator, value);
                }
            }
        }

        try finalizePendingService(&config, &current_service_name, &current_service);

        if (config.has_services) {
            const count = config.services.count();
            const service_names = try allocator.alloc([]const u8, count);
            defer allocator.free(service_names);

            var idx: usize = 0;
            var key_iter = config.services.keyIterator();
            while (key_iter.next()) |key_ptr| : (idx += 1) {
                service_names[idx] = key_ptr.*;
            }

            std.mem.sort([]const u8, service_names, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);

            var next_id: tunnel.ServiceId = 1;
            for (service_names) |name| {
                const service_ptr = config.services.getPtr(name).?;
                if (service_ptr.service_id == 0) {
                    service_ptr.service_id = next_id;
                    next_id += 1;
                } else {
                    next_id = @max(next_id, service_ptr.service_id + 1);
                }
            }
        }

        return config;
    }

    fn finalizePendingService(config: *ClientConfig, service_name: *?[]const u8, service: *?ServiceConfig) !void {
        if (service.*) |*svc| {
            if (svc.local_port == 0) {
                svc.deinit(config.allocator);
                service.* = null;
                service_name.* = null;
                return error.ServiceMissingLocalPort;
            }
            if (svc.target_host.len == 0 or svc.target_port == 0) {
                svc.deinit(config.allocator);
                service.* = null;
                service_name.* = null;
                return error.ServiceMissingTarget;
            }
            if (service_name.*) |name| {
                if (config.services.get(name) != null) {
                    svc.deinit(config.allocator);
                    service.* = null;
                    service_name.* = null;
                    return error.DuplicateServiceName;
                }
                try config.services.put(name, svc.*);
                config.has_services = true;
                service.* = null;
                service_name.* = null;
            } else {
                svc.deinit(config.allocator);
                service.* = null;
            }
        }
    }

    fn validateSecurity(self: *ClientConfig) !void {
        const encryption_enabled = !std.ascii.eqlIgnoreCase(self.cipher, "none");
        if (encryption_enabled and self.psk.len == 0) return error.MissingPsk;

        var requires_default = !self.has_services;
        if (self.has_services) {
            var iter = self.services.valueIterator();
            while (iter.next()) |service| {
                if (service.token.len == 0) {
                    requires_default = true;
                    break;
                }
            }
        }

        if (requires_default and self.default_token.len == 0) return error.MissingToken;
    }
};

test "parse server config with services" {
    const allocator = std.testing.allocator;

    const content =
        \\port = 9000
        \\psk = "test-psk"
        \\[server.services.web]
        \\id = 1
        \\transport = "tcp"
        \\target_host = "127.0.0.1"
        \\target_port = 8080
        \\token = "secret"
    ;

    var config = try ServerConfig.parseServerConfig(allocator, content);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 9000), config.port);
    try std.testing.expect(config.getService(1) != null);
    const service = config.getService(1).?;
    try std.testing.expectEqualStrings("web", service.name);
    try std.testing.expectEqual(@as(u16, 8080), service.target_port);
}

test "server config requires psk when encryption enabled" {
    const allocator = std.testing.allocator;

    const content =
        \\cipher = "aes256gcm"
        \\psk = ""
        \\default_token = "tok"
        \\[server.services.web]
        \\id = 1
        \\transport = "tcp"
        \\target_host = "127.0.0.1"
        \\target_port = 8080
        \\token = "tok"
    ;

    try std.testing.expectError(error.MissingPsk, ServerConfig.parseServerConfig(allocator, content));
}

test "server config requires token for tokenless services" {
    const allocator = std.testing.allocator;

    const content =
        \\cipher = "none"
        \\default_token = ""
        \\[server.services.web]
        \\id = 1
        \\transport = "tcp"
        \\target_host = "127.0.0.1"
        \\target_port = 8080
        \\token = ""
    ;

    try std.testing.expectError(error.MissingToken, ServerConfig.parseServerConfig(allocator, content));
}

test "server config allows per-service tokens without default" {
    const allocator = std.testing.allocator;

    const content =
        \\cipher = "none"
        \\default_token = ""
        \\[server.services.web]
        \\id = 1
        \\transport = "tcp"
        \\target_host = "127.0.0.1"
        \\target_port = 8080
        \\token = "webtok"
        \\[server.services.dns]
        \\id = 2
        \\transport = "udp"
        \\target_host = "127.0.0.1"
        \\target_port = 53
        \\token = "dnstok"
    ;

    var config = try ServerConfig.parseServerConfig(allocator, content);
    defer config.deinit();
    try std.testing.expect(config.getService(1) != null);
    try std.testing.expect(config.getService(2) != null);
}

test "parse client config" {
    const allocator = std.testing.allocator;

    const content =
        \\local_port = 3000
        \\remote_host = "tunnel.example.com"
        \\remote_port = 8000
        \\target_host = "localhost"
        \\target_port = 8080
        \\service_id = 5
        \\reconnect_initial_delay_ms = 2000
    ;

    var config = try ClientConfig.parseClientConfig(allocator, content);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 3000), config.local_port);
    try std.testing.expectEqual(@as(u16, 8000), config.remote_port);
    try std.testing.expectEqual(@as(u64, 2000), config.reconnect_initial_delay_ms);
    try std.testing.expectEqual(@as(tunnel.ServiceId, 5), config.service_id);
    try std.testing.expect(!config.has_services);
}

test "client config requires psk when encryption enabled" {
    const allocator = std.testing.allocator;

    const content =
        \\cipher = "aes256gcm"
        \\psk = ""
        \\default_token = "tok"
        \\local_port = 1000
        \\target_host = "127.0.0.1"
        \\target_port = 2000
    ;

    try std.testing.expectError(error.MissingPsk, ClientConfig.parseClientConfig(allocator, content));
}

test "client config requires default token when services omit tokens" {
    const allocator = std.testing.allocator;

    const content =
        \\[client]
        \\cipher = "none"
        \\psk = ""
        \\default_token = ""
        \\
        \\[client.services.web]
        \\type = "tcp"
        \\local_port = 8080
        \\target_host = "127.0.0.1"
        \\target_port = 80
        \\token = ""
    ;

    try std.testing.expectError(error.MissingToken, ClientConfig.parseClientConfig(allocator, content));
}

test "client config allows per-service tokens without default" {
    const allocator = std.testing.allocator;

    const content =
        \\[client]
        \\cipher = "none"
        \\psk = ""
        \\default_token = ""
        \\
        \\[client.services.web]
        \\type = "tcp"
        \\local_port = 8080
        \\target_host = "127.0.0.1"
        \\target_port = 80
        \\token = "webtok"
        \\
        \\[client.services.dns]
        \\type = "udp"
        \\local_port = 5353
        \\target_host = "127.0.0.1"
        \\target_port = 53
        \\token = "dnstok"
    ;

    var config = try ClientConfig.parseClientConfig(allocator, content);
    defer config.deinit();
    try std.testing.expectEqual(@as(usize, 2), config.services.count());
}

test "parse multi-service client config" {
    const allocator = std.testing.allocator;

    const content =
        \\[client]
        \\remote_host = "server.example.com"
        \\remote_port = 8000
        \\num_tunnels = 4
        \\cipher = "aes256gcm"
        \\
        \\[client.services.dns]
        \\type = "udp"
        \\local_port = 5353
        \\target_host = "127.0.0.1"
        \\target_port = 53
        \\token = "dns-token"
        \\
        \\[client.services.ssh]
        \\type = "tcp"
        \\local_port = 2222
        \\target_host = "127.0.0.1"
        \\target_port = 22
        \\token = "ssh-token"
    ;

    var config = try ClientConfig.parseClientConfig(allocator, content);
    defer config.deinit();

    try std.testing.expect(config.has_services);
    try std.testing.expectEqual(@as(usize, 2), config.services.count());

    const dns = config.services.get("dns").?;
    try std.testing.expectEqual(Transport.udp, dns.transport);
    try std.testing.expectEqual(@as(u16, 5353), dns.local_port);
    try std.testing.expectEqual(@as(u16, 53), dns.target_port);
    try std.testing.expectEqualStrings("dns-token", dns.token);

    const ssh = config.services.get("ssh").?;
    try std.testing.expectEqual(Transport.tcp, ssh.transport);
    try std.testing.expectEqual(@as(u16, 2222), ssh.local_port);
    try std.testing.expectEqual(@as(u16, 22), ssh.target_port);
    try std.testing.expectEqualStrings("ssh-token", ssh.token);

    // Service IDs are assigned deterministically when not provided.
    try std.testing.expectEqual(@as(tunnel.ServiceId, 1), dns.service_id);
    try std.testing.expectEqual(@as(tunnel.ServiceId, 2), ssh.service_id);
}
