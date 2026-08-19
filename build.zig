const std = @import("std");
const builtin = @import("builtin");

fn configureCpuModel(target_label: []const u8, query: *std.Target.Query, cpu_name_raw: []const u8) void {
    const cpu_name = std.mem.trim(u8, cpu_name_raw, " \t\r\n");
    if (cpu_name.len == 0) return;

    if (std.mem.eql(u8, cpu_name, "native")) {
        query.cpu_model = .native;
        return;
    }
    if (std.mem.eql(u8, cpu_name, "baseline")) {
        query.cpu_model = .baseline;
        return;
    }

    const arch = query.cpu_arch orelse builtin.target.cpu.arch;
    const parsed = std.Target.Cpu.Arch.parseCpuModel(arch, cpu_name) catch |err| switch (err) {
        error.UnknownCpuModel => null,
    };

    if (parsed) |model| {
        query.cpu_model = .{ .explicit = model };
    } else {
        std.debug.print(
            "Warning: CPU model '{s}' not valid for target {s}; using baseline\n",
            .{ cpu_name, target_label },
        );
        query.cpu_model = .baseline;
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Read version from build.zig.zon by default, can be overridden with -Dversion
    const build_zon_contents = @embedFile("build.zig.zon");
    const version_start = std.mem.indexOf(u8, build_zon_contents, ".version = \"") orelse {
        @panic("Could not find .version in build.zig.zon");
    };
    const version_value_start = version_start + ".version = \"".len;
    const version_end = std.mem.indexOfPos(u8, build_zon_contents, version_value_start, "\"") orelse {
        @panic("Could not parse .version in build.zig.zon");
    };
    const default_version_string = build_zon_contents[version_value_start..version_end];
    const version_option = b.option([]const u8, "version", "Version string reported by --version") orelse default_version_string;
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version_option);

    // Server executable: floos
    const server = b.addExecutable(.{
        .name = "floos",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    server.root_module.addOptions("build_options", build_options);
    server.root_module.strip = true;
    b.installArtifact(server);

    // Client executable: flooc
    const client = b.addExecutable(.{
        .name = "flooc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/client.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    client.root_module.addOptions("build_options", build_options);
    client.root_module.strip = true;
    b.installArtifact(client);

    // Run server
    const run_server = b.step("server", "Run the tunnel server (floos)");
    const server_cmd = b.addRunArtifact(server);
    server_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        server_cmd.addArgs(args);
    }
    run_server.dependOn(&server_cmd.step);

    // Run client
    const run_client = b.step("client", "Run the tunnel client (flooc)");
    const client_cmd = b.addRunArtifact(client);
    client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        client_cmd.addArgs(args);
    }
    run_client.dependOn(&client_cmd.step);

    // Tests
    const protocol_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    protocol_tests.root_module.addOptions("build_options", build_options);

    const config_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    config_tests.root_module.addOptions("build_options", build_options);

    const noise_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/noise.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    noise_tests.root_module.addOptions("build_options", build_options);

    const proxy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/proxy.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    proxy_tests.root_module.addOptions("build_options", build_options);

    const udp_session_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/udp_session.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    udp_session_tests.root_module.addOptions("build_options", build_options);

    const common_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/common.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    common_tests.root_module.addOptions("build_options", build_options);

    const tunnel_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tunnel.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    tunnel_tests.root_module.addOptions("build_options", build_options);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(protocol_tests).step);
    test_step.dependOn(&b.addRunArtifact(config_tests).step);
    test_step.dependOn(&b.addRunArtifact(noise_tests).step);
    test_step.dependOn(&b.addRunArtifact(proxy_tests).step);
    test_step.dependOn(&b.addRunArtifact(udp_session_tests).step);
    test_step.dependOn(&b.addRunArtifact(common_tests).step);
    test_step.dependOn(&b.addRunArtifact(tunnel_tests).step);

    // Cross-platform release matrix
    const ReleaseTarget = struct {
        name: []const u8,
        query: std.Target.Query,
        cpu: ?[]const u8 = null,
    };

    const release_cpu_option = b.option([]const u8, "release_cpu", "Override CPU model for release-all targets (e.g. haswell, znver3, baseline, native)");

    const release_targets = [_]ReleaseTarget{
        .{ .name = "x86_64-linux-gnu", .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .gnu,
        } },
        .{ .name = "x86_64-linux-gnu-haswell", .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .gnu,
        }, .cpu = "haswell" },
        .{ .name = "x86_64-linux-musl", .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .musl,
        } },
        .{ .name = "aarch64-linux-gnu", .query = .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .gnu,
        } },
        .{ .name = "aarch64-linux-gnu-neoverse-n1", .query = .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .gnu,
        }, .cpu = "neoverse_n1" },
        .{ .name = "aarch64-linux-gnu-rpi4", .query = .{
            .cpu_arch = .aarch64,
            .os_tag = .linux,
            .abi = .gnu,
        }, .cpu = "cortex_a72" },
        .{ .name = "x86_64-macos", .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .macos,
        } },
        .{ .name = "x86_64-macos-haswell", .query = .{
            .cpu_arch = .x86_64,
            .os_tag = .macos,
        }, .cpu = "haswell" },
        .{ .name = "aarch64-macos-m1", .query = .{
            .cpu_arch = .aarch64,
            .os_tag = .macos,
        }, .cpu = "apple_m1" },
    };

    const release_step = b.step("release-all", "Build release binaries for common platforms");

    inline for (release_targets) |cfg| {
        var target_query = cfg.query;

        if (release_cpu_option) |cpu_name_raw| {
            configureCpuModel(cfg.name, &target_query, cpu_name_raw);
        } else if (cfg.cpu) |cpu_name| {
            configureCpuModel(cfg.name, &target_query, cpu_name);
        }

        const resolved_target = b.resolveTargetQuery(target_query);
        const server_name = "floos";
        const client_name = "flooc";
        const dest_dir = b.pathJoin(&.{ "release", cfg.name });

        const server_release = b.addExecutable(.{
            .name = server_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/server.zig"),
                .target = resolved_target,
                .optimize = .ReleaseFast,
                .link_libc = true,
            }),
        });
        server_release.root_module.addOptions("build_options", build_options);
        const client_release = b.addExecutable(.{
            .name = client_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/client.zig"),
                .target = resolved_target,
                .optimize = .ReleaseFast,
                .link_libc = true,
            }),
        });
        client_release.root_module.addOptions("build_options", build_options);
        server_release.root_module.strip = true;
        client_release.root_module.strip = true;

        release_step.dependOn(&b.addInstallArtifact(server_release, .{
            .dest_dir = .{ .override = .{ .custom = dest_dir } },
        }).step);
        release_step.dependOn(&b.addInstallArtifact(client_release, .{
            .dest_dir = .{ .override = .{ .custom = dest_dir } },
        }).step);
    }
}
