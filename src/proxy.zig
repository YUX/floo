const std = @import("std");
const Io = std.Io;
const common = @import("common.zig");

/// Proxy type for client connections
pub const ProxyType = enum {
    none,
    socks5,
    http,

    pub fn fromUrl(url: []const u8) !ProxyType {
        if (std.mem.startsWith(u8, url, "socks5://")) return .socks5;
        if (std.mem.startsWith(u8, url, "http://")) return .http;
        if (std.mem.startsWith(u8, url, "https://")) return error.HttpsProxyUnsupported;
        return error.InvalidProxyUrl;
    }
};

/// Parsed proxy configuration
pub const ProxyConfig = struct {
    proxy_type: ProxyType,
    host: []const u8,
    port: u16,
    username: []const u8, // Empty if no auth
    password: []const u8, // Empty if no auth

    pub fn parseUrl(allocator: std.mem.Allocator, url: []const u8) !ProxyConfig {
        if (url.len == 0) {
            return ProxyConfig{
                .proxy_type = .none,
                .host = "",
                .port = 0,
                .username = "",
                .password = "",
            };
        }

        const proxy_type = try ProxyType.fromUrl(url);

        // Strip protocol prefix
        var remainder = url;
        if (std.mem.startsWith(u8, url, "socks5://")) {
            remainder = url["socks5://".len..];
        } else if (std.mem.startsWith(u8, url, "http://")) {
            remainder = url["http://".len..];
        }

        // Parse username:password@host:port or just host:port
        var username: []const u8 = "";
        var password: []const u8 = "";
        var host_port = remainder;
        var username_buf: ?[]const u8 = null;
        var password_buf: ?[]const u8 = null;
        var host_buf: ?[]const u8 = null;
        errdefer {
            if (username_buf) |buf| allocator.free(buf);
            if (password_buf) |buf| allocator.free(buf);
            if (host_buf) |buf| allocator.free(buf);
        }

        if (std.mem.indexOfScalar(u8, remainder, '@')) |at_idx| {
            const auth_part = remainder[0..at_idx];
            host_port = remainder[at_idx + 1 ..];

            if (std.mem.indexOfScalar(u8, auth_part, ':')) |colon_idx| {
                username_buf = try allocator.dupe(u8, auth_part[0..colon_idx]);
                password_buf = try allocator.dupe(u8, auth_part[colon_idx + 1 ..]);
            } else {
                username_buf = try allocator.dupe(u8, auth_part);
            }
            if (username_buf) |buf| username = buf;
            if (password_buf) |buf| password = buf;
        }

        // Parse host:port. Bracketed IPv6 form (`[::1]:8080`) is supported:
        // the closing `]` separates host from `:port`. Without bracket
        // handling, lastIndexOfScalar(':') would land inside the IPv6
        // address itself for unbracketed forms — which we reject by
        // requiring brackets when the host contains multiple colons.
        const parsed = common.parseHostPort(host_port) catch return error.InvalidProxyUrl;
        host_buf = try allocator.dupe(u8, parsed.host);
        const port = parsed.port;
        const host = host_buf.?;

        return ProxyConfig{
            .proxy_type = proxy_type,
            .host = host,
            .port = port,
            .username = username,
            .password = password,
        };
    }

    pub fn deinit(self: *ProxyConfig, allocator: std.mem.Allocator) void {
        if (self.host.len > 0) allocator.free(self.host);
        if (self.username.len > 0) allocator.free(self.username);
        if (self.password.len > 0) allocator.free(self.password);
    }
};

/// SOCKS5 authentication methods
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERNAME_PASSWORD: u8 = 0x02;
const SOCKS5_NO_ACCEPTABLE_METHODS: u8 = 0xFF;

/// SOCKS5 command types
const SOCKS5_CMD_CONNECT: u8 = 0x01;

/// SOCKS5 address types
const SOCKS5_ADDR_IPV4: u8 = 0x01;
const SOCKS5_ADDR_DOMAIN: u8 = 0x03;
const SOCKS5_ADDR_IPV6: u8 = 0x04;

/// Per-syscall timeout applied during proxy negotiation. A misbehaving
/// proxy that accepts the TCP connect but never replies would otherwise
/// block the calling tunnel thread until the kernel TCP timeout (minutes).
const PROXY_NEGOTIATION_TIMEOUT_SEC: u32 = 30;

fn validateSocks5Auth(username: []const u8, password: []const u8) !void {
    if (username.len > 255 or password.len > 255) return error.Socks5AuthTooLong;
}

/// Connect to target through SOCKS5 proxy. Returns a connected Stream
/// that has finished its negotiation; caller wraps it in their own
/// Reader/Writer for subsequent traffic.
pub fn connectViaSocks5(
    io: Io,
    _: std.mem.Allocator,
    proxy_host: []const u8,
    proxy_port: u16,
    proxy_username: []const u8,
    proxy_password: []const u8,
    target_host: []const u8,
    target_port: u16,
) !Io.net.Stream {
    const proxy_addr = try common.resolveHostPort(io, proxy_host, proxy_port);
    var stream = try proxy_addr.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);

    // Bound every read/write during negotiation; cleared before return so
    // the data plane runs without per-syscall timeouts (audit B-7).
    common.applySocketTimeout(stream.socket.handle, PROXY_NEGOTIATION_TIMEOUT_SEC);
    defer common.clearSocketTimeout(stream.socket.handle);

    // Build temporary buffered reader/writer for the negotiation. Sized for the
    // maximum negotiation message (SOCKS5 auth = 515 bytes).
    var rbuf: [1024]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var rdr = stream.reader(io, &rbuf);
    var wtr = stream.writer(io, &wbuf);
    const reader = &rdr.interface;
    const writer = &wtr.interface;

    // SOCKS5 greeting - negotiate authentication method
    const has_auth = proxy_username.len > 0;
    var greeting_buf: [4]u8 = undefined;
    const greeting = if (has_auth) blk: {
        greeting_buf[0] = 0x05; // Version
        greeting_buf[1] = 0x02; // 2 methods
        greeting_buf[2] = SOCKS5_NO_AUTH;
        greeting_buf[3] = SOCKS5_USERNAME_PASSWORD;
        break :blk greeting_buf[0..4];
    } else blk: {
        greeting_buf[0] = 0x05; // Version
        greeting_buf[1] = 0x01; // 1 method
        greeting_buf[2] = SOCKS5_NO_AUTH;
        break :blk greeting_buf[0..3];
    };

    try writer.writeAll(greeting);
    try writer.flush();

    // Read authentication method choice
    var method_response: [2]u8 = undefined;
    try reader.readSliceAll(&method_response);

    if (method_response[0] != 0x05) return error.InvalidSocks5Response;
    const chosen_method = method_response[1];

    if (chosen_method == SOCKS5_NO_ACCEPTABLE_METHODS) return error.Socks5NoAcceptableAuth;

    // Perform authentication if required
    if (chosen_method == SOCKS5_USERNAME_PASSWORD) {
        if (!has_auth) return error.Socks5AuthRequired;
        try validateSocks5Auth(proxy_username, proxy_password);

        // Send username/password
        var auth_buf: [515]u8 = undefined; // Max: 1 + 1 + 255 + 1 + 255
        var offset: usize = 0;

        auth_buf[offset] = 0x01; // Auth version
        offset += 1;

        auth_buf[offset] = @intCast(proxy_username.len);
        offset += 1;
        @memcpy(auth_buf[offset .. offset + proxy_username.len], proxy_username);
        offset += proxy_username.len;

        auth_buf[offset] = @intCast(proxy_password.len);
        offset += 1;
        @memcpy(auth_buf[offset .. offset + proxy_password.len], proxy_password);
        offset += proxy_password.len;

        try writer.writeAll(auth_buf[0..offset]);
        try writer.flush();

        // Read auth response
        var auth_response: [2]u8 = undefined;
        try reader.readSliceAll(&auth_response);

        if (auth_response[0] != 0x01 or auth_response[1] != 0x00) {
            return error.Socks5AuthFailed;
        }
    } else if (chosen_method != SOCKS5_NO_AUTH) {
        return error.Socks5UnsupportedAuth;
    }

    // Send CONNECT request
    var request_buf: [262]u8 = undefined; // Max size for domain name
    var req_offset: usize = 0;

    // SOCKS5 request header
    request_buf[req_offset] = 0x05; // Version
    req_offset += 1;
    request_buf[req_offset] = SOCKS5_CMD_CONNECT; // Command
    req_offset += 1;
    request_buf[req_offset] = 0x00; // Reserved
    req_offset += 1;

    // Address type and address
    // Try to parse as IP first, otherwise use domain name
    if (Io.net.Ip4Address.parse(target_host, 0)) |addr| {
        request_buf[req_offset] = SOCKS5_ADDR_IPV4;
        req_offset += 1;
        const bytes = std.mem.asBytes(&addr.bytes);
        @memcpy(request_buf[req_offset .. req_offset + 4], bytes[0..4]);
        req_offset += 4;
    } else |_| {
        if (Io.net.Ip6Address.parse(target_host, 0)) |addr| {
            request_buf[req_offset] = SOCKS5_ADDR_IPV6;
            req_offset += 1;
            @memcpy(request_buf[req_offset .. req_offset + 16], &addr.bytes);
            req_offset += 16;
        } else |_| {
            // Use domain name
            if (target_host.len > 255) return error.HostnameTooLong;
            request_buf[req_offset] = SOCKS5_ADDR_DOMAIN;
            req_offset += 1;
            request_buf[req_offset] = @intCast(target_host.len);
            req_offset += 1;
            @memcpy(request_buf[req_offset .. req_offset + target_host.len], target_host);
            req_offset += target_host.len;
        }
    }

    // Port (big-endian)
    std.mem.writeInt(u16, request_buf[req_offset..][0..2], target_port, .big);
    req_offset += 2;

    try writer.writeAll(request_buf[0..req_offset]);
    try writer.flush();

    // Read CONNECT response
    var response_header: [4]u8 = undefined;
    try reader.readSliceAll(&response_header);

    if (response_header[0] != 0x05) return error.InvalidSocks5Response;
    if (response_header[1] != 0x00) {
        return switch (response_header[1]) {
            0x01 => error.Socks5GeneralFailure,
            0x02 => error.Socks5ConnectionNotAllowed,
            0x03 => error.Socks5NetworkUnreachable,
            0x04 => error.Socks5HostUnreachable,
            0x05 => error.Socks5ConnectionRefused,
            0x06 => error.Socks5TtlExpired,
            0x07 => error.Socks5CommandNotSupported,
            0x08 => error.Socks5AddressTypeNotSupported,
            else => error.Socks5UnknownError,
        };
    }

    // Read bind address (we don't need it, but must consume it)
    const addr_type = response_header[3];
    var discard_buf: [256]u8 = undefined;
    const addr_len: usize = switch (addr_type) {
        SOCKS5_ADDR_IPV4 => 4,
        SOCKS5_ADDR_IPV6 => 16,
        SOCKS5_ADDR_DOMAIN => blk: {
            var len_buf: [1]u8 = undefined;
            try reader.readSliceAll(&len_buf);
            break :blk len_buf[0];
        },
        else => return error.InvalidSocks5Response,
    };

    try reader.readSliceAll(discard_buf[0..addr_len]);
    try reader.readSliceAll(discard_buf[0..2]); // Port

    // Connection established through proxy
    return stream;
}

/// Connect to target through HTTP CONNECT proxy. Returns a connected Stream.
pub fn connectViaHttpConnect(
    io: Io,
    _: std.mem.Allocator,
    proxy_host: []const u8,
    proxy_port: u16,
    proxy_username: []const u8,
    proxy_password: []const u8,
    target_host: []const u8,
    target_port: u16,
) !Io.net.Stream {
    const proxy_addr = try common.resolveHostPort(io, proxy_host, proxy_port);
    var stream = try proxy_addr.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);

    // Bound every read/write during negotiation; cleared before return so
    // the data plane runs without per-syscall timeouts (audit B-7).
    common.applySocketTimeout(stream.socket.handle, PROXY_NEGOTIATION_TIMEOUT_SEC);
    defer common.clearSocketTimeout(stream.socket.handle);

    // Note: we do NOT use a buffered reader for the response. A buffered
    // reader can over-read past `\r\n\r\n` into bytes that belong to the
    // next protocol layer (the Noise handshake immediately following);
    // when this function returns, those over-read bytes vanish with the
    // local stack buffer and the next reader desyncs. Instead we read
    // byte-by-byte directly via std.c.read on the raw fd, leaving any
    // post-header bytes in the kernel TCP buffer for the channel layer.
    var wbuf: [2048]u8 = undefined;
    var wtr = stream.writer(io, &wbuf);
    const writer = &wtr.interface;

    // Build CONNECT request
    var request_buf: [2048]u8 = undefined;
    var offset: usize = 0;

    // Request line
    const request_line = try std.fmt.bufPrint(
        request_buf[offset..],
        "CONNECT {s}:{d} HTTP/1.1\r\n",
        .{ target_host, target_port },
    );
    offset += request_line.len;

    // Host header
    const host_header = try std.fmt.bufPrint(
        request_buf[offset..],
        "Host: {s}:{d}\r\n",
        .{ target_host, target_port },
    );
    offset += host_header.len;

    // Proxy-Authorization header (if credentials provided)
    if (proxy_username.len > 0) {
        // Basic auth: base64(username:password). The local auth_str buffer
        // is 512 bytes; pre-check so a long username/password yields a
        // helpful error rather than the bare NoSpaceLeft from bufPrint.
        //
        // Header-injection safety: a malicious credential containing CR/LF
        // could in principle write extra HTTP header lines into the request.
        // It can't here because the credential is base64-encoded BEFORE it
        // is interpolated into the header line — the standard base64 alphabet
        // is `[A-Za-z0-9+/=]` (no CR, no LF), so any \r or \n in the input
        // becomes regular base64 characters in the output. The bufPrint at
        // line 386 only ever sees clean alphanumerics, regardless of the
        // bytes the user typed in proxy_url. Don't change this ordering.
        if (proxy_username.len + 1 + proxy_password.len + 1 > 512) {
            return error.ProxyCredentialsTooLong;
        }
        var auth_str: [512]u8 = undefined;
        const auth_len = try std.fmt.bufPrint(&auth_str, "{s}:{s}", .{ proxy_username, proxy_password });

        const encoder = std.base64.standard.Encoder;
        var encoded: [1024]u8 = undefined;
        const encoded_len = encoder.calcSize(auth_len.len);
        _ = encoder.encode(&encoded, auth_str[0..auth_len.len]);

        const auth_header = try std.fmt.bufPrint(
            request_buf[offset..],
            "Proxy-Authorization: Basic {s}\r\n",
            .{encoded[0..encoded_len]},
        );
        offset += auth_header.len;
    }

    // User-Agent header
    const user_agent = "User-Agent: Floo/0.0.0\r\n";
    @memcpy(request_buf[offset .. offset + user_agent.len], user_agent);
    offset += user_agent.len;

    // End of headers
    @memcpy(request_buf[offset .. offset + 2], "\r\n");
    offset += 2;

    // Send CONNECT request
    try writer.writeAll(request_buf[0..offset]);
    try writer.flush();

    // Read response byte-by-byte until \r\n\r\n. Slow but only at handshake
    // time, and ensures any data the proxy pipelined after the headers
    // remains in the kernel TCP buffer for the next layer to consume.
    var response_buf: [4096]u8 = undefined;
    var response_len: usize = 0;
    const fd = stream.socket.handle;
    while (response_len < response_buf.len) {
        const n = std.c.read(fd, response_buf[response_len..].ptr, 1);
        if (n < 0) {
            const errno = std.posix.errno(n);
            switch (errno) {
                .INTR, .AGAIN => continue,
                else => return error.ProxyReadFailed,
            }
        }
        if (n == 0) return error.ProxyConnectionClosed;
        response_len += @intCast(n);
        if (response_len >= 4 and
            std.mem.endsWith(u8, response_buf[0..response_len], "\r\n\r\n"))
        {
            break;
        }
    }

    // Parse HTTP response status line
    const response = response_buf[0..response_len];
    const first_line_end = std.mem.indexOfScalar(u8, response, '\r') orelse return error.InvalidHttpResponse;
    const status_line = response[0..first_line_end];

    // Should be "HTTP/1.1 200 Connection established" or similar
    if (status_line.len < 12) return error.InvalidHttpResponse;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.InvalidHttpResponse;

    // Extract status code
    const status_code_start = std.mem.indexOfScalar(u8, status_line, ' ') orelse return error.InvalidHttpResponse;
    if (status_code_start + 4 > status_line.len) return error.InvalidHttpResponse;

    const status_code_str = status_line[status_code_start + 1 .. status_code_start + 4];
    const status_code = std.fmt.parseInt(u16, status_code_str, 10) catch return error.InvalidHttpResponse;

    if (status_code != 200) {
        return switch (status_code) {
            407 => error.HttpProxyAuthRequired,
            403 => error.HttpProxyForbidden,
            502, 503 => error.HttpProxyUnavailable,
            else => error.HttpProxyError,
        };
    }

    return stream;
}

/// Connect to target, optionally through a proxy. Returns a Stream.
pub fn connectWithProxy(
    io: Io,
    allocator: std.mem.Allocator,
    proxy_config: ?ProxyConfig,
    target_host: []const u8,
    target_port: u16,
) !Io.net.Stream {
    if (proxy_config) |proxy| {
        if (proxy.proxy_type == .none) {
            const addr = try common.resolveHostPort(io, target_host, target_port);
            return try addr.connect(io, .{ .mode = .stream });
        }

        return switch (proxy.proxy_type) {
            .socks5 => try connectViaSocks5(
                io,
                allocator,
                proxy.host,
                proxy.port,
                proxy.username,
                proxy.password,
                target_host,
                target_port,
            ),
            .http => try connectViaHttpConnect(
                io,
                allocator,
                proxy.host,
                proxy.port,
                proxy.username,
                proxy.password,
                target_host,
                target_port,
            ),
            .none => unreachable,
        };
    }

    // No proxy config provided, direct connection
    const addr = try common.resolveHostPort(io, target_host, target_port);
    return try addr.connect(io, .{ .mode = .stream });
}

// Tests
test "parse socks5 proxy url without auth" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "socks5://127.0.0.1:1080");
    defer config.deinit(allocator);

    try std.testing.expectEqual(ProxyType.socks5, config.proxy_type);
    try std.testing.expectEqualStrings("127.0.0.1", config.host);
    try std.testing.expectEqual(@as(u16, 1080), config.port);
    try std.testing.expectEqual(@as(usize, 0), config.username.len);
}

test "parse socks5 proxy url with auth" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "socks5://user:pass@proxy.example.com:1080");
    defer config.deinit(allocator);

    try std.testing.expectEqual(ProxyType.socks5, config.proxy_type);
    try std.testing.expectEqualStrings("proxy.example.com", config.host);
    try std.testing.expectEqual(@as(u16, 1080), config.port);
    try std.testing.expectEqualStrings("user", config.username);
    try std.testing.expectEqualStrings("pass", config.password);
}

test "parse http proxy url" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "http://proxy.corp.com:8080");
    defer config.deinit(allocator);

    try std.testing.expectEqual(ProxyType.http, config.proxy_type);
    try std.testing.expectEqualStrings("proxy.corp.com", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
}

test "parse empty proxy url" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "");
    defer config.deinit(allocator);

    try std.testing.expectEqual(ProxyType.none, config.proxy_type);
}

test "parse bracketed IPv6 proxy url" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "socks5://[::1]:1080");
    defer config.deinit(allocator);
    try std.testing.expectEqual(ProxyType.socks5, config.proxy_type);
    try std.testing.expectEqualStrings("::1", config.host);
    try std.testing.expectEqual(@as(u16, 1080), config.port);
}

test "parse bracketed IPv6 proxy url with auth" {
    const allocator = std.testing.allocator;

    var config = try ProxyConfig.parseUrl(allocator, "http://user:pw@[2001:db8::1]:8080");
    defer config.deinit(allocator);
    try std.testing.expectEqual(ProxyType.http, config.proxy_type);
    try std.testing.expectEqualStrings("2001:db8::1", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
    try std.testing.expectEqualStrings("user", config.username);
    try std.testing.expectEqualStrings("pw", config.password);
}

test "reject unbracketed IPv6 proxy url (ambiguous)" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidProxyUrl,
        ProxyConfig.parseUrl(allocator, "socks5://::1:1080"),
    );
}

test "reject malformed bracketed proxy url" {
    const allocator = std.testing.allocator;
    // Missing closing bracket
    try std.testing.expectError(
        error.InvalidProxyUrl,
        ProxyConfig.parseUrl(allocator, "socks5://[::1:1080"),
    );
    // Missing port after bracket
    try std.testing.expectError(
        error.InvalidProxyUrl,
        ProxyConfig.parseUrl(allocator, "socks5://[::1]"),
    );
}

test "reject https proxy urls" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.HttpsProxyUnsupported,
        ProxyConfig.parseUrl(allocator, "https://proxy.example.com:443"),
    );
    try std.testing.expectError(
        error.HttpsProxyUnsupported,
        ProxyType.fromUrl("https://127.0.0.1:8080"),
    );
}

test "reject SOCKS5 username or password longer than 255" {
    var long: [256]u8 = undefined;
    @memset(&long, 'u');
    try std.testing.expectError(error.Socks5AuthTooLong, validateSocks5Auth(&long, "pass"));
    @memset(&long, 'p');
    try std.testing.expectError(error.Socks5AuthTooLong, validateSocks5Auth("user", &long));
    try validateSocks5Auth("user", "pass");
}
