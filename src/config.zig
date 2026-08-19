const std = @import("std");
const Io = std.Io;
const tunnel = @import("tunnel.zig");
const common = @import("common.zig");
const protocol = @import("protocol.zig");

// Simple defaults that users can understand
pub const DEFAULT_PSK = "change-me-psk";
pub const DEFAULT_TOKEN = "change-me-token";
pub const DEFAULT_PORT = 8443;
pub const DEFAULT_CIPHER = "aegis128l";

pub const Transport = enum {
    tcp,
    udp,

    pub fn fromString(value: []const u8) ?Transport {
        if (std.mem.eql(u8, value, "tcp")) return .tcp;
        if (std.mem.eql(u8, value, "udp")) return .udp;
        return null;
    }
};

// Simplified service structure - no more modes, just expose or access
pub const Service = struct {
    name: []const u8, // User-friendly name
    id: tunnel.ServiceId, // Auto-generated from name hash
    address: []const u8, // Target address (server) or bind address (client)
    port: u16, // Port number
    transport: Transport, // tcp or udp
    token: []const u8, // Service-specific token (optional)

    fn deinit(self: *Service, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.address);
        allocator.free(self.token);
    }
};

// Advanced tuning options - with sensible defaults
pub const AdvancedSettings = struct {
    // Network tuning
    socket_buffer_size: u32 = 4 * 1024 * 1024, // 4MB default
    udp_timeout_seconds: u64 = 60,
    io_batch_bytes: usize = 512 * 1024, // side→tunnel read / DATA frame size
    pin_threads: bool = true, // pin tunnel threads to CPU cores when available

    // TCP tuning
    tcp_nodelay: bool = true,
    tcp_keepalive: bool = true,
    tcp_keepalive_idle: u32 = 60,
    tcp_keepalive_interval: u32 = 10,
    tcp_keepalive_count: u32 = 3,

    // Connection management
    heartbeat_interval_seconds: u32 = 30,
    heartbeat_timeout_seconds: u32 = 40,

    // Client-specific
    num_tunnels: usize = 0, // 0 = auto (parallel connections)
    reconnect_enabled: bool = true,
    reconnect_initial_delay_ms: u64 = 1000,
    reconnect_max_delay_ms: u64 = 30000,
    reconnect_backoff_multiplier: u64 = 2,

    // Proxy support (client-only)
    proxy_url: []const u8 = "",
};

// Server configuration - simplified
pub const ServerConfig = struct {
    allocator: std.mem.Allocator,

    // Part 1: Tunnel settings
    port: u16, // Listen port
    bind: []const u8, // Bind address (default: 0.0.0.0)
    cipher: []const u8, // Encryption cipher
    psk: []const u8, // Pre-shared key
    token: []const u8, // Default service token

    // Part 2: Services to expose
    services: std.StringHashMap(Service),
    reverse_services: std.StringHashMap(Service),
    service_by_id: std.AutoHashMap(tunnel.ServiceId, *Service),

    // Part 3: Advanced settings (optional)
    advanced: AdvancedSettings,

    pub fn init(allocator: std.mem.Allocator) !ServerConfig {
        var services = std.StringHashMap(Service).init(allocator);
        errdefer services.deinit();

        var reverse_services = std.StringHashMap(Service).init(allocator);
        errdefer reverse_services.deinit();
        var service_by_id = std.AutoHashMap(tunnel.ServiceId, *Service).init(allocator);
        errdefer service_by_id.deinit();

        const bind = try dupString(allocator, "0.0.0.0");
        errdefer allocator.free(bind);
        const cipher = try dupString(allocator, DEFAULT_CIPHER);
        errdefer allocator.free(cipher);
        const psk = try dupString(allocator, DEFAULT_PSK);
        errdefer allocator.free(psk);
        const token = try dupString(allocator, DEFAULT_TOKEN);
        errdefer allocator.free(token);
        const proxy = try dupString(allocator, "");
        errdefer allocator.free(proxy);

        var advanced = AdvancedSettings{};
        advanced.proxy_url = proxy;

        return ServerConfig{
            .allocator = allocator,
            .port = DEFAULT_PORT,
            .bind = bind,
            .cipher = cipher,
            .psk = psk,
            .token = token,
            .services = services,
            .reverse_services = reverse_services,
            .service_by_id = service_by_id,
            .advanced = advanced,
        };
    }

    pub fn deinit(self: *ServerConfig) void {
        var iter = self.services.valueIterator();
        while (iter.next()) |service| {
            service.deinit(self.allocator);
        }
        self.services.deinit();

        var rev_iter = self.reverse_services.valueIterator();
        while (rev_iter.next()) |service| {
            service.deinit(self.allocator);
        }
        self.reverse_services.deinit();
        self.service_by_id.deinit();

        self.allocator.free(self.bind);
        self.allocator.free(self.cipher);
        self.allocator.free(self.psk);
        self.allocator.free(self.token);
        self.allocator.free(self.advanced.proxy_url);
        self.* = undefined;
    }

    pub fn validate(self: *const ServerConfig) !void {
        // Validate port
        if (self.port == 0) {
            std.debug.print("[CONFIG] Error: port cannot be 0\n", .{});
            return error.InvalidPort;
        }

        const canonical_cipher = canonicalizeCipher(self.cipher) orelse {
            std.debug.print("[CONFIG] Error: invalid cipher '{s}'\n", .{self.cipher});
            std.debug.print("[CONFIG] Valid ciphers: ChaChaPoly, AES128GCM, AES256GCM, AEGIS128L, AEGIS128X2, AEGIS128X4, AEGIS256, AEGIS256X2, AEGIS256X4, none\n", .{});
            return error.InvalidCipher;
        };

        const encryption_enabled = !std.mem.eql(u8, canonical_cipher, "none");
        if (encryption_enabled and self.psk.len < 16) {
            std.debug.print("[CONFIG] Error: PSK must be at least 16 characters when encryption is enabled\n", .{});
            return error.WeakPSK;
        }

        try validateHeartbeat(&self.advanced);

        // Validate services
        if (self.services.count() == 0 and self.reverse_services.count() == 0) {
            std.debug.print("[CONFIG] Warning: no services or reverse_services configured\n", .{});
        }

        try validateIoBatch(self.advanced.io_batch_bytes);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, io: Io, path: []const u8) !ServerConfig {
        // Zig 0.16: std.fs.cwd() is gone; readFileAlloc moved to Io.Dir with
        // signature (io, sub_path, gpa, limit).
        const cwd = Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, path, allocator, @enumFromInt(1024 * 1024)) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Create it using examples/ or configs/ templates.\n", .{path});
                return error.FileNotFound;
            }
            return err;
        };
        defer allocator.free(content);

        var config = try parseServerConfig(allocator, content);
        errdefer config.deinit();

        // Validate configuration before returning
        try config.validate();

        return config;
    }

    fn parseServerConfig(allocator: std.mem.Allocator, content: []const u8) !ServerConfig {
        var config = try ServerConfig.init(allocator);
        errdefer config.deinit();

        var used_service_ids = std.AutoHashMap(tunnel.ServiceId, []const u8).init(allocator);
        defer used_service_ids.deinit();

        const Section = enum { none, tunnel, services, reverse_services, advanced };
        var section: Section = .none;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Handle section headers
            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
                if (std.mem.eql(u8, name, "tunnel")) {
                    section = .tunnel;
                } else if (std.mem.eql(u8, name, "services")) {
                    section = .services;
                } else if (std.mem.eql(u8, name, "reverse_services")) {
                    section = .reverse_services;
                } else if (std.mem.eql(u8, name, "advanced")) {
                    section = .advanced;
                } else {
                    std.debug.print("[CONFIG] Warning: Unknown section [{s}]\n", .{name});
                }
                continue;
            }

            const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value_raw = trimmed[eq_pos + 1 ..];
            const value = extractTomlValue(value_raw);

            switch (section) {
                .none, .tunnel => {
                    // Treat root-level keys as tunnel settings for minimal configs
                    if (std.mem.eql(u8, key, "port")) {
                        config.port = try parseAdvancedInt(u16, key, value);
                    } else if (std.mem.eql(u8, key, "bind")) {
                        allocator.free(config.bind);
                        config.bind = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "cipher")) {
                        allocator.free(config.cipher);
                        config.cipher = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "psk")) {
                        allocator.free(config.psk);
                        config.psk = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "token")) {
                        allocator.free(config.token);
                        config.token = try dupString(allocator, value);
                    }
                },

                .services => {
                    if (try applyServiceProperty(allocator, &config.services, key, value)) {
                        continue;
                    }
                    // Parse service definitions: name = "address:port" or "address:port/transport"
                    var service = try parseServiceDefinition(allocator, key, value);

                    // Generate ID from name hash and ensure uniqueness
                    service.id = try generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.services.put(service.name, service);
                },

                .reverse_services => {
                    if (try applyServiceProperty(allocator, &config.reverse_services, key, value)) {
                        continue;
                    }
                    // Parse reverse service definitions (same format as services)
                    var service = try parseServiceDefinition(allocator, key, value);

                    // Generate ID from name hash and ensure uniqueness
                    service.id = try generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.reverse_services.put(service.name, service);
                },

                .advanced => {
                    _ = try applyAdvancedKey(allocator, &config.advanced, key, value, .server);
                },
            }
        }

        // Validate configuration
        if (config.services.count() == 0 and config.reverse_services.count() == 0) {
            return error.NoServicesConfigured;
        }

        try validateSecurity(&config);
        try indexServices(&config);

        return config;
    }

    pub fn getServiceById(self: *const ServerConfig, id: tunnel.ServiceId) ?*const Service {
        return self.service_by_id.get(id);
    }

    pub fn getServiceByName(self: *const ServerConfig, name: []const u8) ?*const Service {
        return self.services.getPtr(name);
    }
};

// Client configuration - simplified
pub const ClientConfig = struct {
    allocator: std.mem.Allocator,

    // Part 1: Tunnel settings
    server: []const u8, // Server address:port
    cipher: []const u8, // Encryption cipher
    psk: []const u8, // Pre-shared key
    token: []const u8, // Default service token

    // Part 2: Services to access
    services: std.StringHashMap(Service),
    default_service: ?[]const u8, // Default service when single mode
    reverse_services: std.StringHashMap(Service),
    service_by_id: std.AutoHashMap(tunnel.ServiceId, *Service),

    // Part 3: Advanced settings (optional)
    advanced: AdvancedSettings,

    pub fn init(allocator: std.mem.Allocator) !ClientConfig {
        var services = std.StringHashMap(Service).init(allocator);
        errdefer services.deinit();

        var reverse_services = std.StringHashMap(Service).init(allocator);
        errdefer reverse_services.deinit();
        var service_by_id = std.AutoHashMap(tunnel.ServiceId, *Service).init(allocator);
        errdefer service_by_id.deinit();

        const server = try dupString(allocator, "localhost:8443");
        errdefer allocator.free(server);
        const cipher = try dupString(allocator, DEFAULT_CIPHER);
        errdefer allocator.free(cipher);
        const psk = try dupString(allocator, DEFAULT_PSK);
        errdefer allocator.free(psk);
        const token = try dupString(allocator, DEFAULT_TOKEN);
        errdefer allocator.free(token);
        const proxy = try dupString(allocator, "");
        errdefer allocator.free(proxy);

        var advanced = AdvancedSettings{};
        advanced.proxy_url = proxy;

        return ClientConfig{
            .allocator = allocator,
            .server = server,
            .cipher = cipher,
            .psk = psk,
            .token = token,
            .services = services,
            .default_service = null,
            .reverse_services = reverse_services,
            .service_by_id = service_by_id,
            .advanced = advanced,
        };
    }

    pub fn deinit(self: *ClientConfig) void {
        var iter = self.services.valueIterator();
        while (iter.next()) |service| {
            service.deinit(self.allocator);
        }
        self.services.deinit();

        var rev_iter = self.reverse_services.valueIterator();
        while (rev_iter.next()) |service| {
            service.deinit(self.allocator);
        }
        self.reverse_services.deinit();
        self.service_by_id.deinit();

        self.allocator.free(self.server);
        self.allocator.free(self.cipher);
        self.allocator.free(self.psk);
        self.allocator.free(self.token);
        self.allocator.free(self.advanced.proxy_url);
        if (self.default_service) |ds| {
            self.allocator.free(ds);
        }
        self.* = undefined;
    }

    pub fn validate(self: *const ClientConfig) !void {
        // Validate server address
        if (self.server.len == 0) {
            std.debug.print("[CONFIG] Error: server address not specified\n", .{});
            return error.MissingServerAddress;
        }

        // Must have host:port format
        if (std.mem.indexOfScalar(u8, self.server, ':') == null) {
            std.debug.print("[CONFIG] Error: server must be in format 'host:port', got '{s}'\n", .{self.server});
            return error.InvalidServerAddress;
        }

        const canonical_cipher = canonicalizeCipher(self.cipher) orelse {
            std.debug.print("[CONFIG] Error: invalid cipher '{s}'\n", .{self.cipher});
            std.debug.print("[CONFIG] Valid ciphers: ChaChaPoly, AES128GCM, AES256GCM, AEGIS128L, AEGIS128X2, AEGIS128X4, AEGIS256, AEGIS256X2, AEGIS256X4, none\n", .{});
            return error.InvalidCipher;
        };

        const encryption_enabled = !std.mem.eql(u8, canonical_cipher, "none");
        if (encryption_enabled and self.psk.len < 16) {
            std.debug.print("[CONFIG] Error: PSK must be at least 16 characters when encryption is enabled\n", .{});
            return error.WeakPSK;
        }

        // Validate num_tunnels
        if (self.advanced.num_tunnels == 0) {
            std.debug.print("[CONFIG] Info: num_tunnels=0 → auto scale based on CPU count\n", .{});
        } else {
            if (self.advanced.num_tunnels > 64) {
                std.debug.print("[CONFIG] Warning: num_tunnels > 64 may cause excessive overhead\n", .{});
            }
        }

        // Validate reconnect settings
        if (self.advanced.reconnect_enabled) {
            if (self.advanced.reconnect_max_delay_ms < self.advanced.reconnect_initial_delay_ms) {
                std.debug.print("[CONFIG] Error: reconnect_max_delay must be >= reconnect_initial_delay\n", .{});
                return error.InvalidReconnectConfig;
            }
        }

        // Validate default_service if specified
        if (self.default_service) |ds| {
            if (self.services.get(ds) == null) {
                std.debug.print("[CONFIG] Error: default_service '{s}' not found in services\n", .{ds});
                return error.InvalidDefaultService;
            }
        }

        try validateHeartbeat(&self.advanced);

        try validateIoBatch(self.advanced.io_batch_bytes);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, io: Io, path: []const u8) !ClientConfig {
        // Zig 0.16: std.fs.cwd() is gone; readFileAlloc moved to Io.Dir with
        // signature (io, sub_path, gpa, limit).
        const cwd = Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, path, allocator, @enumFromInt(1024 * 1024)) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Create it using examples/ or configs/ templates.\n", .{path});
                return error.FileNotFound;
            }
            return err;
        };
        defer allocator.free(content);

        var config = try parseClientConfig(allocator, content);
        errdefer config.deinit();

        // Validate configuration before returning
        try config.validate();

        return config;
    }

    fn parseClientConfig(allocator: std.mem.Allocator, content: []const u8) !ClientConfig {
        var config = try ClientConfig.init(allocator);
        errdefer config.deinit();

        var used_service_ids = std.AutoHashMap(tunnel.ServiceId, []const u8).init(allocator);
        defer used_service_ids.deinit();

        const Section = enum { none, tunnel, services, reverse_services, advanced };
        var section: Section = .none;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Handle section headers
            if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
                if (std.mem.eql(u8, name, "tunnel")) {
                    section = .tunnel;
                } else if (std.mem.eql(u8, name, "services")) {
                    section = .services;
                } else if (std.mem.eql(u8, name, "reverse_services")) {
                    section = .reverse_services;
                } else if (std.mem.eql(u8, name, "advanced")) {
                    section = .advanced;
                } else {
                    std.debug.print("[CONFIG] Warning: Unknown section [{s}]\n", .{name});
                }
                continue;
            }

            const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value_raw = trimmed[eq_pos + 1 ..];
            const value = extractTomlValue(value_raw);

            switch (section) {
                .none, .tunnel => {
                    // Treat root-level keys as tunnel settings for minimal configs
                    if (std.mem.eql(u8, key, "server")) {
                        allocator.free(config.server);
                        config.server = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "cipher")) {
                        allocator.free(config.cipher);
                        config.cipher = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "psk")) {
                        allocator.free(config.psk);
                        config.psk = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "token")) {
                        allocator.free(config.token);
                        config.token = try dupString(allocator, value);
                    } else if (std.mem.eql(u8, key, "default_service")) {
                        if (config.default_service) |ds| {
                            allocator.free(ds);
                        }
                        config.default_service = try dupString(allocator, value);
                    }
                },

                .services => {
                    if (try applyServiceProperty(allocator, &config.services, key, value)) {
                        continue;
                    }
                    // Parse service definitions for client
                    // Format: service_name = port or "address:port"
                    var service = try parseClientServiceDefinition(allocator, key, value);

                    // Generate ID from name hash (must match server) and ensure uniqueness
                    service.id = try generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.services.put(service.name, service);

                    // First service becomes default if not set
                    if (config.default_service == null) {
                        config.default_service = try dupString(allocator, service.name);
                    }
                },

                .reverse_services => {
                    if (try applyServiceProperty(allocator, &config.reverse_services, key, value)) {
                        continue;
                    }
                    // Parse reverse service definitions for client
                    var service = try parseClientServiceDefinition(allocator, key, value);

                    // Generate ID from name hash (must match server) and ensure uniqueness
                    service.id = try generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.reverse_services.put(service.name, service);
                },

                .advanced => {
                    _ = try applyAdvancedKey(allocator, &config.advanced, key, value, .client);
                },
            }
        }

        try validateSecurity(&config);
        try indexServices(&config);

        return config;
    }

    pub fn getServiceById(self: *const ClientConfig, id: tunnel.ServiceId) ?*const Service {
        return self.service_by_id.get(id);
    }

    pub fn getServiceByName(self: *const ClientConfig, name: []const u8) ?*const Service {
        return self.services.getPtr(name);
    }

    pub fn getServerHost(self: *const ClientConfig) ![]const u8 {
        return (try common.parseHostPort(self.server)).host;
    }

    pub fn getServerPort(self: *const ClientConfig) !u16 {
        return (try common.parseHostPort(self.server)).port;
    }
};

// Helper functions

fn dupString(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return allocator.dupe(u8, value);
}

/// Extract the value portion of a `key = value` line, honoring quoted
/// strings. Audit B-9: previously the parser stripped inline `#` comments
/// before checking for quotes, so a value like `psk = "abc#def"` was
/// silently truncated to `abc` (followed by a quote-trim that ate the
/// leading `"`). For credential fields this is silent corruption.
///
/// Behavior:
///   - If the trimmed value starts with `"`, look for the next `"`.
///     Content between the quotes is returned verbatim (no comment
///     stripping inside, so `#`, `=`, whitespace are all preserved).
///     If no closing `"` is found, treat as unquoted (best-effort).
///   - Otherwise, strip an inline `#` comment, then trim whitespace.
fn extractTomlValue(value_raw: []const u8) []const u8 {
    const left_trimmed = std.mem.trimStart(u8, value_raw, " \t");
    if (left_trimmed.len > 0 and left_trimmed[0] == '"') {
        if (std.mem.indexOfScalarPos(u8, left_trimmed, 1, '"')) |close_pos| {
            return left_trimmed[1..close_pos];
        }
        // No closing quote — fall through to unquoted handling so the user
        // gets *something* parsable rather than silently empty.
    }
    var v = left_trimmed;
    if (std.mem.indexOfScalar(u8, v, '#')) |comment_pos| {
        v = v[0..comment_pos];
    }
    return std.mem.trim(u8, v, " \t\"");
}

test "extractTomlValue preserves `#` inside quotes" {
    try std.testing.expectEqualStrings("abc#def", extractTomlValue("\"abc#def\""));
    try std.testing.expectEqualStrings("a b c", extractTomlValue("\"a b c\""));
    // Comment stripping still works outside quotes
    try std.testing.expectEqualStrings("plain", extractTomlValue("plain # comment"));
    // Trim whitespace and strip surrounding quotes for unquoted-looking values
    try std.testing.expectEqualStrings("v", extractTomlValue("  v  "));
    // No closing quote: best-effort
    try std.testing.expectEqualStrings("ab", extractTomlValue("\"ab"));
}

/// Helper for parsing integers in `[advanced]` blocks. Audit B-10: the
/// previous `parseInt catch default` pattern silently swallowed typos
/// (`socket_buffer_size = 8MB` → kept the default with no warning).
/// This surfaces a named error so the user finds the issue at startup.
fn parseAdvancedInt(comptime T: type, key: []const u8, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10) catch |err| {
        std.debug.print("[CONFIG] Invalid integer for '{s}' = '{s}': {}\n", .{ key, value, err });
        return error.InvalidConfigValue;
    };
}

fn applyAdvancedKey(
    allocator: std.mem.Allocator,
    advanced: *AdvancedSettings,
    key: []const u8,
    value: []const u8,
    role: enum { server, client },
) !bool {
    if (std.mem.eql(u8, key, "socket_buffer_size")) {
        advanced.socket_buffer_size = try parseAdvancedInt(u32, key, value);
    } else if (std.mem.eql(u8, key, "udp_timeout_seconds")) {
        advanced.udp_timeout_seconds = try parseAdvancedInt(u64, key, value);
    } else if (std.mem.eql(u8, key, "io_batch_bytes")) {
        advanced.io_batch_bytes = try parseAdvancedInt(usize, key, value);
    } else if (std.mem.eql(u8, key, "pin_threads")) {
        advanced.pin_threads = try parseAdvancedBool(key, value);
    } else if (std.mem.eql(u8, key, "tcp_nodelay")) {
        advanced.tcp_nodelay = try parseAdvancedBool(key, value);
    } else if (std.mem.eql(u8, key, "tcp_keepalive")) {
        advanced.tcp_keepalive = try parseAdvancedBool(key, value);
    } else if (std.mem.eql(u8, key, "tcp_keepalive_idle")) {
        advanced.tcp_keepalive_idle = try parseAdvancedInt(u32, key, value);
    } else if (std.mem.eql(u8, key, "tcp_keepalive_interval")) {
        advanced.tcp_keepalive_interval = try parseAdvancedInt(u32, key, value);
    } else if (std.mem.eql(u8, key, "tcp_keepalive_count")) {
        advanced.tcp_keepalive_count = try parseAdvancedInt(u32, key, value);
    } else if (std.mem.eql(u8, key, "heartbeat_interval_seconds")) {
        advanced.heartbeat_interval_seconds = try parseAdvancedInt(u32, key, value);
    } else if (std.mem.eql(u8, key, "heartbeat_timeout_seconds")) {
        advanced.heartbeat_timeout_seconds = try parseAdvancedInt(u32, key, value);
    } else if (role == .client and std.mem.eql(u8, key, "num_tunnels")) {
        advanced.num_tunnels = try parseAdvancedInt(usize, key, value);
    } else if (role == .client and std.mem.eql(u8, key, "reconnect_enabled")) {
        advanced.reconnect_enabled = try parseAdvancedBool(key, value);
    } else if (role == .client and std.mem.eql(u8, key, "reconnect_initial_delay_ms")) {
        advanced.reconnect_initial_delay_ms = try parseAdvancedInt(u64, key, value);
    } else if (role == .client and std.mem.eql(u8, key, "reconnect_max_delay_ms")) {
        advanced.reconnect_max_delay_ms = try parseAdvancedInt(u64, key, value);
    } else if (role == .client and std.mem.eql(u8, key, "reconnect_backoff_multiplier")) {
        advanced.reconnect_backoff_multiplier = try parseAdvancedInt(u64, key, value);
    } else if (role == .client and std.mem.eql(u8, key, "proxy_url")) {
        allocator.free(advanced.proxy_url);
        advanced.proxy_url = try dupString(allocator, value);
    } else {
        return false;
    }
    return true;
}

fn parseAdvancedBool(key: []const u8, value: []const u8) !bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    std.debug.print("[CONFIG] Invalid boolean for '{s}' = '{s}': expected 'true' or 'false'\n", .{ key, value });
    return error.InvalidConfigValue;
}

fn canonicalizeCipher(value: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(value, "none")) return "none";
    if (std.ascii.eqlIgnoreCase(value, "chachapoly") or std.ascii.eqlIgnoreCase(value, "chacha20poly1305")) {
        return "chacha20poly1305";
    }
    if (std.ascii.eqlIgnoreCase(value, "aesgcm") or std.ascii.eqlIgnoreCase(value, "aes256gcm")) {
        return "aes256gcm";
    }
    if (std.ascii.eqlIgnoreCase(value, "aes128gcm")) {
        return "aes128gcm";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis128l")) {
        return "aegis128l";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis128x2")) {
        return "aegis128x2";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis128x4")) {
        return "aegis128x4";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis256")) {
        return "aegis256";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis256x2")) {
        return "aegis256x2";
    }
    if (std.ascii.eqlIgnoreCase(value, "aegis256x4")) {
        return "aegis256x4";
    }
    return null;
}

pub fn canonicalCipher(config: anytype) []const u8 {
    return canonicalizeCipher(config.cipher) orelse config.cipher;
}

// Generate service ID from name using cryptographic hash to prevent collisions
fn generateServiceId(name: []const u8) !tunnel.ServiceId {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(name);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    const id = std.mem.readInt(u32, hash[0..4], .little);
    if (id == 0) {
        std.debug.print("[CONFIG] Error: service '{s}' hashed to reserved id 0\n", .{name});
        return error.InvalidServiceId;
    }
    return id;
}

fn indexServices(config: anytype) !void {
    config.service_by_id.clearRetainingCapacity();
    var iter = config.services.iterator();
    while (iter.next()) |entry| {
        try config.service_by_id.put(entry.value_ptr.id, entry.value_ptr);
    }
    var rev = config.reverse_services.iterator();
    while (rev.next()) |entry| {
        try config.service_by_id.put(entry.value_ptr.id, entry.value_ptr);
    }
}

fn registerServiceId(
    used_ids: *std.AutoHashMap(tunnel.ServiceId, []const u8),
    id: tunnel.ServiceId,
    name: []const u8,
) !void {
    if (used_ids.get(id)) |existing| {
        if (!std.mem.eql(u8, existing, name)) {
            std.debug.print(
                "[CONFIG] Error: service '{s}' shares ID {} with '{s}'. Rename one of them or set explicit IDs.\n",
                .{ name, id, existing },
            );
            return error.ServiceIdCollision;
        }
        return;
    }
    try used_ids.put(id, name);
}

// Parse service definition for server: "address:port[/transport]"
fn parseServiceDefinition(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !Service {
    var transport: Transport = .tcp;
    var addr_port = value;

    // Check for transport suffix. Audit B-12: previously a typo like
    // `dns = "10.0.0.5:53/udq"` silently became tcp; surface the error
    // instead so users notice their misconfiguration.
    if (std.mem.lastIndexOfScalar(u8, value, '/')) |slash_pos| {
        const transport_str = value[slash_pos + 1 ..];
        transport = Transport.fromString(transport_str) orelse {
            std.debug.print("[CONFIG] Unknown transport '{s}' for service '{s}'; expected 'tcp' or 'udp'\n", .{ transport_str, name });
            return error.InvalidTransport;
        };
        addr_port = value[0..slash_pos];
    }

    const parsed = common.parseHostPort(addr_port) catch {
        std.debug.print("[CONFIG] Invalid address:port '{s}' for service '{s}'\n", .{ addr_port, name });
        return error.InvalidServiceDefinition;
    };
    const address = parsed.host;
    const port = parsed.port;

    // Audit B-15: build dupes step-by-step with errdefer so a late OOM
    // doesn't leak earlier dupes. The previous struct-literal `try` chain
    // dropped name+address allocations if `try dupString(allocator, "")`
    // for the empty token failed.
    const name_dup = try dupString(allocator, name);
    errdefer allocator.free(name_dup);
    const address_dup = try dupString(allocator, address);
    errdefer allocator.free(address_dup);
    const token_dup = try dupString(allocator, "");
    errdefer allocator.free(token_dup);

    return Service{
        .name = name_dup,
        .id = 0, // Will be set later
        .address = address_dup,
        .port = port,
        .transport = transport,
        .token = token_dup,
    };
}

// Parse client service definition: port number or "address:port[/transport]"
fn parseClientServiceDefinition(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !Service {
    // Simple case: just a port number
    if (std.fmt.parseInt(u16, value, 10)) |port| {
        // Same B-15 errdefer discipline as parseServiceDefinition.
        const name_dup = try dupString(allocator, name);
        errdefer allocator.free(name_dup);
        const address_dup = try dupString(allocator, "127.0.0.1");
        errdefer allocator.free(address_dup);
        const token_dup = try dupString(allocator, "");
        errdefer allocator.free(token_dup);
        return Service{
            .name = name_dup,
            .id = 0, // Will be set later
            .address = address_dup,
            .port = port,
            .transport = .tcp,
            .token = token_dup,
        };
    } else |_| {
        // Complex case: address:port[/transport]
        return parseServiceDefinition(allocator, name, value);
    }
}

fn applyServiceProperty(
    allocator: std.mem.Allocator,
    services: *std.StringHashMap(Service),
    key: []const u8,
    value: []const u8,
) !bool {
    const dot_index = std.mem.indexOfScalar(u8, key, '.') orelse return false;
    if (dot_index == 0 or dot_index + 1 >= key.len) return false;

    const service_name = key[0..dot_index];
    const field = key[dot_index + 1 ..];
    if (field.len == 0) return false;

    const service = services.getPtr(service_name) orelse {
        std.debug.print("[CONFIG] Warning: property '{s}' references unknown service '{s}'\n", .{ key, service_name });
        return true;
    };

    if (std.mem.eql(u8, field, "token")) {
        // Allocate first; if it fails the existing token is preserved
        // (audit B-15: previous `free → try dup` left the field
        // dangling on dupString OOM, then deinit would double-free).
        const new_token = try dupString(allocator, value);
        allocator.free(service.token);
        service.token = new_token;
        return true;
    }

    std.debug.print("[CONFIG] Warning: unknown property '{s}' for service '{s}'\n", .{ field, service_name });
    return true;
}

/// Detect example/placeholder credentials shipped in configs/ and README.md
/// quickstarts. README claims "no default credentials — refuses to start with
/// example passwords"; this check makes that claim true for the actual
/// example strings users copy-paste.
fn isPlaceholderCredential(value: []const u8) bool {
    if (value.len == 0) return false;
    // Prefix-based: catches REPLACE_WITH_*, REPLACE_ME, YOUR_GENERATED_*, YOUR_*.
    if (std.ascii.startsWithIgnoreCase(value, "REPLACE_")) return true;
    if (std.ascii.startsWithIgnoreCase(value, "REPLACE-")) return true;
    if (std.ascii.eqlIgnoreCase(value, "REPLACE")) return true;
    if (std.ascii.startsWithIgnoreCase(value, "YOUR_GENERATED")) return true;
    if (std.ascii.startsWithIgnoreCase(value, "YOUR-GENERATED")) return true;
    if (std.ascii.eqlIgnoreCase(value, "changeme") or std.ascii.eqlIgnoreCase(value, "change-me")) return true;
    return false;
}

/// Count distinct byte values in `value`.  Cheap proxy for "is this string
/// plausibly random vs. obviously low-entropy".  Used as a coarse weak-PSK
/// gate alongside the `len >= 16` and placeholder-prefix checks.
fn distinctByteCount(value: []const u8) usize {
    var seen = [_]bool{false} ** 256;
    var count: usize = 0;
    for (value) |b| {
        if (!seen[b]) {
            seen[b] = true;
            count += 1;
        }
    }
    return count;
}

/// Reject obvious low-entropy credentials that pass the >=16-char gate but
/// are clearly fat-finger inputs ("AAAAAAAAAAAAAAAA", "abababababababab",
/// "passwordpassword").  Threshold is intentionally lenient — a 32-byte
/// base64 string from `openssl rand` has ~28 distinct chars; a 16-char
/// passphrase typically has 10+.  Anything with fewer than 8 distinct
/// bytes in a 16+ char string has at most ~3 bits of Shannon entropy per
/// char, which is well below "couldn't plausibly be random".  We don't
/// try to catch every weak password — the README says "use openssl rand",
/// the >=16-char gate filters fat-finger, and this catches the long tail.
fn isLowEntropyCredential(value: []const u8) bool {
    if (value.len < 16) return false; // Already caught by the length gate
    const distinct = distinctByteCount(value);
    return distinct < 8;
}

fn validateIoBatch(io_batch: usize) !void {
    if (io_batch < 4096) {
        std.debug.print("[CONFIG] Error: io_batch_bytes must be at least 4096\n", .{});
        return error.InvalidBatchSize;
    }
    if (io_batch > protocol.MAX_DATA_PAYLOAD) {
        std.debug.print("[CONFIG] Error: io_batch_bytes cannot exceed {} (max DATA payload in a {}-byte frame)\n", .{
            protocol.MAX_DATA_PAYLOAD,
            protocol.MAX_FRAME_SIZE,
        });
        return error.InvalidBatchSize;
    }
}

fn validateHeartbeat(advanced: *const AdvancedSettings) !void {
    if (advanced.heartbeat_interval_seconds == 0) {
        std.debug.print("[CONFIG] Error: heartbeat_interval_seconds must be greater than 0\n", .{});
        return error.InvalidHeartbeatConfig;
    }
    if (advanced.heartbeat_timeout_seconds <= advanced.heartbeat_interval_seconds) {
        std.debug.print("[CONFIG] Error: heartbeat_timeout ({}) must be greater than heartbeat_interval ({})\n", .{
            advanced.heartbeat_timeout_seconds,
            advanced.heartbeat_interval_seconds,
        });
        return error.InvalidHeartbeatConfig;
    }
}

fn validateSecurity(config: anytype) !void {
    const canonical = canonicalizeCipher(config.cipher) orelse return error.InvalidCipher;
    const encryption_enabled = !std.mem.eql(u8, canonical, "none");

    // Always reject default PSK if present, even if encryption is currently disabled
    if (config.psk.len > 0 and std.ascii.eqlIgnoreCase(config.psk, DEFAULT_PSK)) {
        std.debug.print("[SECURITY] Cannot use default PSK '{s}' - change it in config file\n", .{DEFAULT_PSK});
        return error.DefaultCredentials;
    }

    // Always reject default token if present, even if not currently needed
    if (config.token.len > 0 and std.ascii.eqlIgnoreCase(config.token, DEFAULT_TOKEN)) {
        std.debug.print("[SECURITY] Cannot use default token '{s}' - change it in config file\n", .{DEFAULT_TOKEN});
        return error.DefaultCredentials;
    }

    // Reject README/example placeholders that pass the >=16-char weak-PSK gate.
    if (isPlaceholderCredential(config.psk)) {
        std.debug.print("[SECURITY] PSK is a placeholder ('{s}'); replace with `openssl rand -base64 32` output\n", .{config.psk});
        return error.DefaultCredentials;
    }
    if (isPlaceholderCredential(config.token)) {
        std.debug.print("[SECURITY] Token is a placeholder ('{s}'); replace with `openssl rand -base64 24` output\n", .{config.token});
        return error.DefaultCredentials;
    }

    // PSK is required regardless of cipher.  Even with `cipher = "none"` the
    // channel layer now runs a plaintext PSK proof-of-knowledge handshake
    // (audit S-1) so an attacker without the PSK can't speak the protocol.
    // Without a PSK, that handshake would fail with `error.MissingPsk` at
    // connect time — easier to surface here.
    if (config.psk.len == 0) {
        std.debug.print("[SECURITY] PSK is required (even with cipher=\"none\", PSK is used for mutual authentication)\n", .{});
        return error.MissingPsk;
    }
    if (encryption_enabled and config.psk.len < 16) {
        return error.WeakPSK;
    }
    if (encryption_enabled and isLowEntropyCredential(config.psk)) {
        std.debug.print(
            "[SECURITY] PSK appears low-entropy (only {} distinct byte values); use `openssl rand -base64 32`\n",
            .{distinctByteCount(config.psk)},
        );
        return error.WeakPSK;
    }
    if (config.token.len > 0 and isLowEntropyCredential(config.token)) {
        std.debug.print(
            "[SECURITY] Token appears low-entropy (only {} distinct byte values); use `openssl rand -base64 24`\n",
            .{distinctByteCount(config.token)},
        );
        return error.WeakPSK;
    }

    // Check if any service needs default token
    var needs_token = false;
    var iter = config.services.valueIterator();
    while (iter.next()) |service| {
        if (service.token.len == 0) {
            needs_token = true;
            break;
        }
    }
    if (!needs_token) {
        var rev = config.reverse_services.valueIterator();
        while (rev.next()) |service| {
            if (service.token.len == 0) {
                needs_token = true;
                break;
            }
        }
    }

    if (needs_token and config.token.len == 0) {
        return error.MissingToken;
    }
}

// Tests

test "parse simplified server config" {
    const allocator = std.testing.allocator;
    const content =
        \\[tunnel]
        \\port = 8443
        \\psk = "my-secret-key-123456"
        \\token = "my-auth-token"
        \\
        \\[services]
        \\web = "localhost:8080"
        \\database = "localhost:5432/tcp"
        \\dns = "localhost:53/udp"
    ;

    var config = try ServerConfig.parseServerConfig(allocator, content);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8443), config.port);
    try std.testing.expectEqualStrings("my-secret-key-123456", config.psk);
    try std.testing.expect(config.services.contains("web"));
    try std.testing.expect(config.services.contains("database"));
    try std.testing.expect(config.services.contains("dns"));

    const web = config.services.get("web").?;
    try std.testing.expectEqual(@as(u16, 8080), web.port);
    try std.testing.expectEqualStrings("localhost", web.address);
}

test "parse simplified client config" {
    const allocator = std.testing.allocator;
    const content =
        \\[tunnel]
        \\server = "example.com:8443"
        \\psk = "my-secret-key-123456"
        \\token = "my-auth-token"
        \\
        \\[services]
        \\web = 8080
        \\database = "127.0.0.1:5432"
    ;

    var config = try ClientConfig.parseClientConfig(allocator, content);
    defer config.deinit();

    try std.testing.expectEqualStrings("example.com:8443", config.server);
    try std.testing.expectEqualStrings("my-secret-key-123456", config.psk);
    try std.testing.expect(config.services.contains("web"));
    try std.testing.expect(config.services.contains("database"));

    const web = config.services.get("web").?;
    try std.testing.expectEqual(@as(u16, 8080), web.port);
    try std.testing.expectEqualStrings("127.0.0.1", web.address);
}

test "service ID generation is consistent" {
    const id1 = try generateServiceId("web");
    const id2 = try generateServiceId("web");
    const id3 = try generateServiceId("database");

    try std.testing.expectEqual(id1, id2);
    try std.testing.expect(id1 != id3);
    try std.testing.expect(id1 > 0);
    try std.testing.expect(id3 > 0);
}

test "service definition parses bracketed IPv6" {
    const allocator = std.testing.allocator;
    var service = try parseServiceDefinition(allocator, "v6", "[::1]:8080");
    defer service.deinit(allocator);
    try std.testing.expectEqualStrings("::1", service.address);
    try std.testing.expectEqual(@as(u16, 8080), service.port);
}

test "getServiceById covers reverse_services" {
    const allocator = std.testing.allocator;
    const content =
        \\[tunnel]
        \\port = 8443
        \\psk = "my-secret-key-123456"
        \\token = "my-auth-token"
        \\
        \\[reverse_services]
        \\media = "0.0.0.0:8096"
    ;
    var cfg = try ServerConfig.parseServerConfig(allocator, content);
    defer cfg.deinit();
    const media = cfg.reverse_services.get("media").?;
    try std.testing.expect(cfg.getServiceById(media.id) != null);
    try std.testing.expectEqualStrings("media", cfg.getServiceById(media.id).?.name);
}

test "canonicalize cipher names is case-insensitive" {
    try std.testing.expectEqualStrings("aes256gcm", canonicalizeCipher("AES256GCM").?);
    try std.testing.expectEqualStrings("aegis128l", canonicalizeCipher("AeGiS128L").?);
    try std.testing.expectEqualStrings("chacha20poly1305", canonicalizeCipher("ChaChaPoly").?);
    try std.testing.expectEqualStrings("none", canonicalizeCipher("NONE").?);
}

test "validateSecurity rejects default PSK" {
    var cfg = try ServerConfig.init(std.testing.allocator);
    defer cfg.deinit();
    try std.testing.expectError(error.DefaultCredentials, validateSecurity(&cfg));
}

test "validateSecurity rejects example placeholder PSK" {
    var cfg = try ServerConfig.init(std.testing.allocator);
    defer cfg.deinit();
    // Replace defaults so we test the placeholder path, not the default-cred path.
    cfg.allocator.free(cfg.psk);
    cfg.psk = try dupString(cfg.allocator, "REPLACE_WITH_OPENSSL_RAND_BASE64_32_OUTPUT");
    cfg.allocator.free(cfg.token);
    cfg.token = try dupString(cfg.allocator, "real-token-that-passes-checks");
    try std.testing.expectError(error.DefaultCredentials, validateSecurity(&cfg));
}

test "validateSecurity rejects example placeholder token" {
    var cfg = try ServerConfig.init(std.testing.allocator);
    defer cfg.deinit();
    cfg.allocator.free(cfg.psk);
    cfg.psk = try dupString(cfg.allocator, "real-psk-that-passes-length-checks-32-chars");
    cfg.allocator.free(cfg.token);
    cfg.token = try dupString(cfg.allocator, "REPLACE_ME");
    try std.testing.expectError(error.DefaultCredentials, validateSecurity(&cfg));
}

test "isPlaceholderCredential prefix matching" {
    try std.testing.expect(isPlaceholderCredential("REPLACE_WITH_ANYTHING"));
    try std.testing.expect(isPlaceholderCredential("REPLACE_ME"));
    try std.testing.expect(isPlaceholderCredential("replace_me"));
    try std.testing.expect(isPlaceholderCredential("YOUR_GENERATED_PSK_HERE"));
    try std.testing.expect(isPlaceholderCredential("changeme"));
    try std.testing.expect(!isPlaceholderCredential(""));
    try std.testing.expect(!isPlaceholderCredential("a-real-strong-secret-from-openssl"));
    try std.testing.expect(!isPlaceholderCredential("REPLACEMENT-PARTS")); // doesn't start with REPLACE_ or REPLACE-
}

test "isLowEntropyCredential catches obvious low-entropy strings" {
    try std.testing.expect(isLowEntropyCredential("AAAAAAAAAAAAAAAA")); // 1 distinct
    try std.testing.expect(isLowEntropyCredential("abababababababab")); // 2 distinct
    try std.testing.expect(isLowEntropyCredential("0000000011111111")); // 2 distinct
    try std.testing.expect(isLowEntropyCredential("aaaabbbbccccdddd")); // 4 distinct, 16 chars
    // Strings with 8+ distinct bytes — accept (this is the floor; we don't
    // try to catch all weak passphrases, just fat-finger inputs).
    try std.testing.expect(!isLowEntropyCredential("abcdefgh01234567")); // 16 distinct
    try std.testing.expect(!isLowEntropyCredential("a1b2c3d4e5f6g7h8")); // 16 distinct
    // Length gate: short strings are caught by the length check, not this one.
    try std.testing.expect(!isLowEntropyCredential("AA"));
    try std.testing.expect(!isLowEntropyCredential(""));
}

test "validateSecurity rejects low-entropy PSK" {
    var cfg = try ServerConfig.init(std.testing.allocator);
    defer cfg.deinit();
    cfg.allocator.free(cfg.psk);
    cfg.psk = try dupString(cfg.allocator, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 32 chars, 1 distinct
    cfg.allocator.free(cfg.token);
    cfg.token = try dupString(cfg.allocator, "a-real-token-that-passes-checks");
    try std.testing.expectError(error.WeakPSK, validateSecurity(&cfg));
}

test "validateHeartbeat rejects interval 0 and timeout <= interval" {
    var ok = AdvancedSettings{};
    try validateHeartbeat(&ok);

    var zero = AdvancedSettings{};
    zero.heartbeat_interval_seconds = 0;
    try std.testing.expectError(error.InvalidHeartbeatConfig, validateHeartbeat(&zero));

    var inverted = AdvancedSettings{};
    inverted.heartbeat_interval_seconds = 40;
    inverted.heartbeat_timeout_seconds = 30;
    try std.testing.expectError(error.InvalidHeartbeatConfig, validateHeartbeat(&inverted));

    var equal = AdvancedSettings{};
    equal.heartbeat_interval_seconds = 30;
    equal.heartbeat_timeout_seconds = 30;
    try std.testing.expectError(error.InvalidHeartbeatConfig, validateHeartbeat(&equal));
}
