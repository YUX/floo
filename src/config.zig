const std = @import("std");
const tunnel = @import("tunnel.zig");

// Simple defaults that users can understand
pub const DEFAULT_PSK = "change-me-psk";
pub const DEFAULT_TOKEN = "change-me-token";
pub const DEFAULT_PORT = 8443;
pub const DEFAULT_CIPHER = "aes256gcm";

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
    io_batch_bytes: usize = 64 * 1024, // size of per-stream IO buffers
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

    // Part 3: Advanced settings (optional)
    advanced: AdvancedSettings,

    pub fn init(allocator: std.mem.Allocator) !ServerConfig {
        var services = std.StringHashMap(Service).init(allocator);
        errdefer services.deinit();

        var reverse_services = std.StringHashMap(Service).init(allocator);
        errdefer reverse_services.deinit();

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
            std.debug.print("[CONFIG] Valid ciphers: ChaChaPoly, AES128GCM, AES256GCM, AEGIS128L, AEGIS256, none\n", .{});
            return error.InvalidCipher;
        };

        const encryption_enabled = !std.mem.eql(u8, canonical_cipher, "none");
        if (encryption_enabled and self.psk.len < 16) {
            std.debug.print("[CONFIG] Error: PSK must be at least 16 characters when encryption is enabled\n", .{});
            return error.WeakPSK;
        }

        // Validate heartbeat configuration
        if (self.advanced.heartbeat_timeout_seconds <= self.advanced.heartbeat_interval_seconds) {
            std.debug.print("[CONFIG] Error: heartbeat_timeout ({}) must be greater than heartbeat_interval ({})\n", .{ self.advanced.heartbeat_timeout_seconds, self.advanced.heartbeat_interval_seconds });
            return error.InvalidHeartbeatConfig;
        }

        // Validate services
        if (self.services.count() == 0 and self.reverse_services.count() == 0) {
            std.debug.print("[CONFIG] Warning: no services or reverse_services configured\n", .{});
        }

        if (self.advanced.io_batch_bytes < 4096) {
            std.debug.print("[CONFIG] Error: io_batch_bytes must be at least 4096\n", .{});
            return error.InvalidBatchSize;
        }
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !ServerConfig {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Create it using examples/ templates.\n", .{path});
                var cfg = try ServerConfig.init(allocator);
                errdefer cfg.deinit();
                try cfg.validate();
                try validateSecurity(&cfg);
                return cfg;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
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
            var value_raw = trimmed[eq_pos + 1 ..];

            // Handle inline comments
            if (std.mem.indexOfScalar(u8, value_raw, '#')) |comment_pos| {
                value_raw = value_raw[0..comment_pos];
            }

            const value = std.mem.trim(u8, value_raw, " \t\"");

            switch (section) {
                .none, .tunnel => {
                    // Treat root-level keys as tunnel settings for minimal configs
                    if (std.mem.eql(u8, key, "port")) {
                        config.port = std.fmt.parseInt(u16, value, 10) catch config.port;
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
                    service.id = generateServiceId(service.name);
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
                    service.id = generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.reverse_services.put(service.name, service);
                },

                .advanced => {
                    if (std.mem.eql(u8, key, "socket_buffer_size")) {
                        config.advanced.socket_buffer_size = std.fmt.parseInt(u32, value, 10) catch config.advanced.socket_buffer_size;
                    } else if (std.mem.eql(u8, key, "udp_timeout_seconds")) {
                        config.advanced.udp_timeout_seconds = std.fmt.parseInt(u64, value, 10) catch config.advanced.udp_timeout_seconds;
                    } else if (std.mem.eql(u8, key, "io_batch_bytes")) {
                        config.advanced.io_batch_bytes = std.fmt.parseInt(usize, value, 10) catch config.advanced.io_batch_bytes;
                    } else if (std.mem.eql(u8, key, "pin_threads")) {
                        config.advanced.pin_threads = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_nodelay")) {
                        config.advanced.tcp_nodelay = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_keepalive")) {
                        config.advanced.tcp_keepalive = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_idle")) {
                        config.advanced.tcp_keepalive_idle = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_idle;
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_interval")) {
                        config.advanced.tcp_keepalive_interval = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_interval;
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_count")) {
                        config.advanced.tcp_keepalive_count = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_count;
                    } else if (std.mem.eql(u8, key, "heartbeat_interval_seconds")) {
                        config.advanced.heartbeat_interval_seconds = std.fmt.parseInt(u32, value, 10) catch config.advanced.heartbeat_interval_seconds;
                    } else if (std.mem.eql(u8, key, "heartbeat_timeout_seconds")) {
                        config.advanced.heartbeat_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch config.advanced.heartbeat_timeout_seconds;
                    }
                },
            }
        }

        // Validate configuration
        if (config.services.count() == 0 and config.reverse_services.count() == 0) {
            return error.NoServicesConfigured;
        }

        try validateSecurity(&config);

        return config;
    }

    pub fn getServiceById(self: *const ServerConfig, id: tunnel.ServiceId) ?*const Service {
        var iter = self.services.valueIterator();
        while (iter.next()) |service| {
            if (service.id == id) return service;
        }
        return null;
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

    // Part 3: Advanced settings (optional)
    advanced: AdvancedSettings,

    pub fn init(allocator: std.mem.Allocator) !ClientConfig {
        var services = std.StringHashMap(Service).init(allocator);
        errdefer services.deinit();

        var reverse_services = std.StringHashMap(Service).init(allocator);
        errdefer reverse_services.deinit();

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
            std.debug.print("[CONFIG] Valid ciphers: ChaChaPoly, AES128GCM, AES256GCM, AEGIS128L, AEGIS256, none\n", .{});
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

        if (self.advanced.io_batch_bytes < 4096) {
            std.debug.print("[CONFIG] Error: io_batch_bytes must be at least 4096\n", .{});
            return error.InvalidBatchSize;
        }
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !ClientConfig {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("[CONFIG] File not found: {s}. Create it using examples/ templates.\n", .{path});
                var cfg = try ClientConfig.init(allocator);
                errdefer cfg.deinit();
                try cfg.validate();
                try validateSecurity(&cfg);
                return cfg;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
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
            var value_raw = trimmed[eq_pos + 1 ..];

            // Handle inline comments
            if (std.mem.indexOfScalar(u8, value_raw, '#')) |comment_pos| {
                value_raw = value_raw[0..comment_pos];
            }

            const value = std.mem.trim(u8, value_raw, " \t\"");

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
                    service.id = generateServiceId(service.name);
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
                    service.id = generateServiceId(service.name);
                    try registerServiceId(&used_service_ids, service.id, service.name);

                    // Use default token if not specified
                    if (service.token.len == 0) {
                        allocator.free(service.token);
                        service.token = try dupString(allocator, "");
                    }

                    try config.reverse_services.put(service.name, service);
                },

                .advanced => {
                    if (std.mem.eql(u8, key, "socket_buffer_size")) {
                        config.advanced.socket_buffer_size = std.fmt.parseInt(u32, value, 10) catch config.advanced.socket_buffer_size;
                    } else if (std.mem.eql(u8, key, "udp_timeout_seconds")) {
                        config.advanced.udp_timeout_seconds = std.fmt.parseInt(u64, value, 10) catch config.advanced.udp_timeout_seconds;
                    } else if (std.mem.eql(u8, key, "io_batch_bytes")) {
                        config.advanced.io_batch_bytes = std.fmt.parseInt(usize, value, 10) catch config.advanced.io_batch_bytes;
                    } else if (std.mem.eql(u8, key, "pin_threads")) {
                        config.advanced.pin_threads = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_nodelay")) {
                        config.advanced.tcp_nodelay = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_keepalive")) {
                        config.advanced.tcp_keepalive = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_idle")) {
                        config.advanced.tcp_keepalive_idle = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_idle;
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_interval")) {
                        config.advanced.tcp_keepalive_interval = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_interval;
                    } else if (std.mem.eql(u8, key, "tcp_keepalive_count")) {
                        config.advanced.tcp_keepalive_count = std.fmt.parseInt(u32, value, 10) catch config.advanced.tcp_keepalive_count;
                    } else if (std.mem.eql(u8, key, "heartbeat_timeout_seconds")) {
                        config.advanced.heartbeat_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch config.advanced.heartbeat_timeout_seconds;
                    } else if (std.mem.eql(u8, key, "num_tunnels")) {
                        config.advanced.num_tunnels = std.fmt.parseInt(usize, value, 10) catch config.advanced.num_tunnels;
                    } else if (std.mem.eql(u8, key, "reconnect_enabled")) {
                        config.advanced.reconnect_enabled = std.mem.eql(u8, value, "true");
                    } else if (std.mem.eql(u8, key, "reconnect_initial_delay_ms")) {
                        config.advanced.reconnect_initial_delay_ms = std.fmt.parseInt(u64, value, 10) catch config.advanced.reconnect_initial_delay_ms;
                    } else if (std.mem.eql(u8, key, "reconnect_max_delay_ms")) {
                        config.advanced.reconnect_max_delay_ms = std.fmt.parseInt(u64, value, 10) catch config.advanced.reconnect_max_delay_ms;
                    } else if (std.mem.eql(u8, key, "reconnect_backoff_multiplier")) {
                        config.advanced.reconnect_backoff_multiplier = std.fmt.parseInt(u64, value, 10) catch config.advanced.reconnect_backoff_multiplier;
                    } else if (std.mem.eql(u8, key, "proxy_url")) {
                        allocator.free(config.advanced.proxy_url);
                        config.advanced.proxy_url = try dupString(allocator, value);
                    }
                },
            }
        }

        try validateSecurity(&config);

        return config;
    }

    pub fn getServiceById(self: *const ClientConfig, id: tunnel.ServiceId) ?*const Service {
        var iter = self.services.valueIterator();
        while (iter.next()) |service| {
            if (service.id == id) return service;
        }
        return null;
    }

    pub fn getServiceByName(self: *const ClientConfig, name: []const u8) ?*const Service {
        return self.services.getPtr(name);
    }

    // Parse server address:port
    pub fn getServerHost(self: *const ClientConfig) ![]const u8 {
        const colon_pos = std.mem.lastIndexOfScalar(u8, self.server, ':');
        if (colon_pos) |pos| {
            return self.server[0..pos];
        }
        return self.server;
    }

    pub fn getServerPort(self: *const ClientConfig) !u16 {
        const colon_pos = std.mem.lastIndexOfScalar(u8, self.server, ':');
        if (colon_pos) |pos| {
            const port_str = self.server[pos + 1 ..];
            return std.fmt.parseInt(u16, port_str, 10) catch DEFAULT_PORT;
        }
        return DEFAULT_PORT;
    }
};

// Helper functions

fn dupString(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return allocator.dupe(u8, value);
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
    if (std.ascii.eqlIgnoreCase(value, "aegis256")) {
        return "aegis256";
    }
    return null;
}

pub fn canonicalCipher(config: anytype) []const u8 {
    return canonicalizeCipher(config.cipher) orelse config.cipher;
}

// Generate service ID from name using cryptographic hash to prevent collisions
fn generateServiceId(name: []const u8) tunnel.ServiceId {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(name);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    // Use first 2 bytes of hash, ensure non-zero
    const id = std.mem.readInt(u16, hash[0..2], .little);
    return if (id == 0) 1 else id;
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

    // Check for transport suffix
    if (std.mem.lastIndexOfScalar(u8, value, '/')) |slash_pos| {
        const transport_str = value[slash_pos + 1 ..];
        transport = Transport.fromString(transport_str) orelse .tcp;
        addr_port = value[0..slash_pos];
    }

    // Parse address:port
    const colon_pos = std.mem.lastIndexOfScalar(u8, addr_port, ':') orelse {
        return error.InvalidServiceDefinition;
    };

    const address = addr_port[0..colon_pos];
    const port_str = addr_port[colon_pos + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch |err| {
        std.debug.print("[DEBUG] Failed to parse port '{s}' from service '{s}': {}\n", .{ port_str, name, err });
        return error.InvalidPort;
    };

    return Service{
        .name = try dupString(allocator, name),
        .id = 0, // Will be set later
        .address = try dupString(allocator, address),
        .port = port,
        .transport = transport,
        .token = try dupString(allocator, ""),
    };
}

// Parse client service definition: port number or "address:port[/transport]"
fn parseClientServiceDefinition(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !Service {
    // Simple case: just a port number
    if (std.fmt.parseInt(u16, value, 10)) |port| {
        return Service{
            .name = try dupString(allocator, name),
            .id = 0, // Will be set later
            .address = try dupString(allocator, "127.0.0.1"),
            .port = port,
            .transport = .tcp,
            .token = try dupString(allocator, ""),
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
        allocator.free(service.token);
        service.token = try dupString(allocator, value);
        return true;
    }

    std.debug.print("[CONFIG] Warning: unknown property '{s}' for service '{s}'\n", .{ field, service_name });
    return true;
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

    if (encryption_enabled and config.psk.len == 0) {
        return error.MissingPsk;
    }
    if (encryption_enabled and config.psk.len < 16) {
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

    if (needs_token and config.token.len == 0) {
        return error.MissingToken;
    }
}

// Compatibility layer for existing code
// These structures map old config to new simplified format

pub const ServerCore = struct {
    host: []const u8,
    port: u16,
    transport: Transport,
};

pub const TunnelSettings = struct {
    cipher: []const u8,
    psk: []const u8,
    default_token: []const u8,
};

pub const TcpSettings = struct {
    nodelay: bool,
    keepalive: bool,
    keepalive_idle: u32,
    keepalive_interval: u32,
    keepalive_count: u32,
};

pub const ServerTuning = struct {
    udp_timeout_seconds: u64,
    socket_buffer_size: u32,
    tcp: TcpSettings,
    heartbeat_interval_seconds: u32,
};

pub const ClientCore = struct {
    local_host: []const u8,
    local_port: u16,
    remote_host: []const u8,
    remote_port: u16,
    service_id: tunnel.ServiceId,
    transport: Transport,
};

pub const ClientTuning = struct {
    udp_timeout_seconds: u64,
    num_tunnels: usize,
    socket_buffer_size: u32,
    tcp: TcpSettings,
    heartbeat_timeout_seconds: u32,
};

pub const ClientReconnect = struct {
    enabled: bool,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    backoff_multiplier: u64,
};

// Compatibility wrappers for old-style configs
pub const ServerServiceConfig = struct {
    name: []const u8,
    service_id: tunnel.ServiceId,
    transport: Transport,
    mode: ServiceMode,
    target_host: []const u8,
    target_port: u16,
    local_port: u16,
    token: []const u8,

    fn deinit(self: *ServerServiceConfig, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

pub const ClientServiceConfig = struct {
    name: []const u8,
    service_id: tunnel.ServiceId,
    transport: Transport,
    mode: ServiceMode,
    local_host: []const u8,
    local_port: u16,
    token: []const u8,

    fn deinit(self: *ClientServiceConfig, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

pub const ServiceMode = enum {
    forward,
    reverse,

    pub fn fromString(value: []const u8) ?ServiceMode {
        if (std.mem.eql(u8, value, "forward")) return .forward;
        if (std.mem.eql(u8, value, "reverse")) return .reverse;
        return null;
    }
};

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
    const id1 = generateServiceId("web");
    const id2 = generateServiceId("web");
    const id3 = generateServiceId("database");

    try std.testing.expectEqual(id1, id2);
    try std.testing.expect(id1 != id3);
    try std.testing.expect(id1 > 0);
    try std.testing.expect(id3 > 0);
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
