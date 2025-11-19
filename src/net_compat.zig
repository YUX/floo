const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const native_endian = builtin.cpu.arch.endian();

pub const Address = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    pub fn initIp4(address: [4]u8, port: u16) Address {
        return .{
            .in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, port),
                .addr = std.mem.readInt(u32, &address, native_endian),
                .zero = std.mem.zeroes([8]u8),
            },
        };
    }

    pub fn initPosix(addr: *const posix.sockaddr) Address {
        switch (addr.family) {
            posix.AF.INET => return .{ .in = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(addr))).* },
            posix.AF.INET6 => return .{ .in6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(addr))).* },
            else => return .{ .any = addr.* },
        }
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => std.mem.bigToNative(u16, self.in.port),
            posix.AF.INET6 => std.mem.bigToNative(u16, self.in6.port),
            else => 0,
        };
    }

    pub fn parseIp4(host: []const u8, port: u16) !Address {
        var addr: u32 = 0;
        var octets: u32 = 0;
        var seen_octets: u3 = 0;

        for (host) |char| {
            if (char == '.') {
                if (octets > 255) return error.InvalidIp;
                addr = (addr << 8) | octets;
                octets = 0;
                seen_octets += 1;
                if (seen_octets > 3) return error.InvalidIp;
            } else if (std.ascii.isDigit(char)) {
                octets = octets * 10 + (char - '0');
                if (octets > 255 and seen_octets < 3) return error.InvalidIp; // optimization
            } else {
                return error.InvalidIp;
            }
        }
        if (octets > 255) return error.InvalidIp;
        if (seen_octets != 3) return error.InvalidIp;
        addr = (addr << 8) | octets;

        // In sockaddr.in.addr, it expects network byte order (Big Endian)
        // Our manual parse produced host byte order (if we treat it as a u32)
        // Wait, actually: 1.2.3.4 -> 0x01020304.
        // std.mem.readInt reads bytes.
        // Let's just use the byte array logic which is safer.

        // Simpler way:
        var it = std.mem.splitScalar(u8, host, '.');
        var bytes: [4]u8 = undefined;
        var index: usize = 0;
        while (it.next()) |part| {
            if (index >= 4) return error.InvalidIp;
            bytes[index] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIp;
            index += 1;
        }
        if (index != 4) return error.InvalidIp;

        return initIp4(bytes, port);
    }

    pub fn parseIp6(host: []const u8, port: u16) !Address {
        _ = host;
        _ = port;
        // TODO: Implement IPv6 parsing if needed. For now return error to fallback to resolveIp
        return error.InvalidIp;
    }

    pub fn resolveIp(host: []const u8, port: u16) !Address {
        const c = std.c;
        var hints: c.addrinfo = undefined;
        // hints must be zeroed?
        @memset(@as([*]u8, @ptrCast(&hints))[0..@sizeOf(c.addrinfo)], 0);

        hints.flags = std.mem.zeroes(@TypeOf(hints.flags));
        hints.family = posix.AF.UNSPEC;
        hints.socktype = posix.SOCK.STREAM;
        hints.protocol = posix.IPPROTO.TCP;

        // Host string needs to be null-terminated for C
        var host_z_buf: [256]u8 = undefined;
        if (host.len >= host_z_buf.len) return error.NameTooLong;
        @memcpy(host_z_buf[0..host.len], host);
        host_z_buf[host.len] = 0;
        const host_z = host_z_buf[0..host.len :0];

        var port_buf: [16]u8 = undefined;
        const port_str = std.fmt.bufPrintZ(&port_buf, "{}", .{port}) catch return error.Unexpected;

        var res: ?*c.addrinfo = null;
        const rc = c.getaddrinfo(host_z, port_str, &hints, &res);
        if (@intFromEnum(rc) != 0) {
            return error.UnknownHost;
        }
        defer if (res) |r| c.freeaddrinfo(r);

        if (res) |r| {
            if (r.addr) |addr_ptr| {
                if (r.family == posix.AF.INET) {
                    const addr_in = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(addr_ptr)));
                    return .{ .in = addr_in.* };
                } else if (r.family == posix.AF.INET6) {
                    const addr_in6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(addr_ptr)));
                    return .{ .in6 = addr_in6.* };
                }
            }
        }
        return error.UnknownHost;
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            else => @sizeOf(posix.sockaddr),
        };
    }

    pub fn format(self: Address, writer: anytype) !void {
        switch (self.any.family) {
            posix.AF.INET => {
                const addr = self.in.addr; // u32 big endian (network order)
                // We need to read it as bytes.
                // addr is u32. In net compat, we initialized it via initIp4 which put bytes in memory.
                // But posix.sockaddr.in.addr is u32.
                // Let's just cast pointer to *[4]u8.
                const bytes = @as(*const [4]u8, @ptrCast(&addr));
                try writer.print("{}.{}.{}.{}:{}", .{ bytes[0], bytes[1], bytes[2], bytes[3], std.mem.bigToNative(u16, self.in.port) });
            },
            posix.AF.INET6 => {
                try writer.print("[IPv6]:{}", .{std.mem.bigToNative(u16, self.in6.port)});
            },
            else => try writer.writeAll("unknown-address"),
        }
    }
};

pub fn getAddressList(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    // Mock implementation that returns a single address using resolveIp
    const addr = try Address.resolveIp(host, port);
    const list = try allocator.alloc(Address, 1);
    list[0] = addr;
    return AddressList{ .allocator = allocator, .addrs = list };
}

pub const AddressList = struct {
    allocator: std.mem.Allocator,
    addrs: []Address,

    pub fn deinit(self: AddressList) void {
        self.allocator.free(self.addrs);
    }
};
