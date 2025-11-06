```
███████╗██╗      ██████╗  ██████╗
██╔════╝██║     ██╔═══██╗██╔═══██╗
█████╗  ██║     ██║   ██║██║   ██║
██╔══╝  ██║     ██║   ██║██║   ██║
██║     ███████╗╚██████╔╝╚██████╔╝
╚═╝     ╚══════╝ ╚═════╝  ╚═════╝

   29 Gbit/s • Zero Dependencies • 671 KB
```

**Secure, high-performance tunneling in Zig. Expose your home services or access remote ones.**

[![Language: Zig](https://img.shields.io/badge/language-Zig-orange.svg)](https://ziglang.org/)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-green.svg)](build.zig.zon)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## 🚀 Quick Start

### 1. Choose Your Use Case

| I want to... | Example | Mode |
|--------------|---------|------|
| **Expose my home media server (Emby/Plex)** | [`expose-home-server/`](examples/expose-home-server/) | Reverse |
| **Access my cloud database securely** | [`access-cloud-database/`](examples/access-cloud-database/) | Forward |
| **Expose multiple services (Emby + SSH)** | [`expose-multiple-services/`](examples/expose-multiple-services/) | Reverse |
| **Connect through corporate proxy** | [`through-corporate-proxy/`](examples/through-corporate-proxy/) | Forward |

### 2. Get Floo

**Download pre-built binaries:**
- **Latest (nightly):** https://github.com/YUX/floo/releases/tag/nightly
- Pick your platform: `floo-aarch64-macos-m1.tar.gz`, `floo-aarch64-linux-rpi.tar.gz`, etc.

**Or build from source:**
```bash
git clone https://github.com/YUX/floo
cd floo
zig build -Doptimize=ReleaseFast
# Binaries in zig-out/bin/
```

### 3. Follow the Example

Each example folder contains:
- `README.md` - Complete setup guide with troubleshooting
- `floos.toml` - Server config (copy and edit)
- `flooc.toml` - Client config (copy and edit)

**Most users get running in under 5 minutes!**

---

## What is Floo?

**Reverse Tunneling (most common):**
Expose local services through a public server
```
Home (Emby) → flooc → Tunnel → floos (Public IP) ← Users access here
```

**Forward Tunneling (traditional):**
Access remote services through encrypted tunnel
```
Your laptop → flooc → Tunnel → floos → Cloud database
```

Both modes support:
- ✅ End-to-end encryption (29 Gbps on M1)
- ✅ Multi-service multiplexing
- ✅ Automatic reconnection
- ✅ Zero dependencies

---

## Key Features

- **🔐 Secure:** Noise XX + PSK with AEGIS/AES-GCM ciphers
- **⚡ Fast:** 29.4 Gbps encrypted (62% faster than Rathole, 194% faster than FRP)
- **📦 Tiny:** 671 KB total binaries (vs 2-24 MB alternatives)
- **🎯 Flexible:** Forward and reverse tunneling modes
- **🔄 Reliable:** Hot config reload, auto-reconnect, heartbeat supervision
- **🌐 Corporate-friendly:** SOCKS5 and HTTP CONNECT proxy support
- **🔧 Developer-friendly:** Built-in `--doctor` and `--ping` diagnostics

---

## Performance

**Benchmarks** (Apple M1 MacBook Air, iperf3):

| Tool | Throughput | vs Floo |
|------|-----------|---------|
| **Floo (AEGIS-128L)** | **29.4 Gbps** | baseline |
| Rathole | 18.1 Gbps | -38% |
| FRP | 10.0 Gbps | -66% |

```
Floo (AEGIS-128L)   ██████████████▊ ⭐                                   29.4 Gbps
Rathole             █████████▏                                           18.1 Gbps
FRP                 █████                                                10.0 Gbps
                    └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴────►
                    0     5    10    15    20    25    30 Gbps
```

---

## Installation

### Pre-built Binaries

**Nightly builds:** https://github.com/YUX/floo/releases/tag/nightly

| Platform | File |
|----------|------|
| Apple Silicon (M1/M2/M3) | `floo-aarch64-macos-m1.tar.gz` |
| Intel Mac | `floo-x86_64-macos.tar.gz` |
| Raspberry Pi / ARM64 Linux | `floo-aarch64-linux-rpi.tar.gz` |
| Modern x86_64 Linux | `floo-x86_64-linux-haswell.tar.gz` |
| Generic x86_64 Linux | `floo-x86_64-linux.tar.gz` |

```bash
tar xzf floo-*.tar.gz
cd floo-*/
./floos --version
./flooc --version
```

### Build from Source

**Requirements:** [Zig 0.15.x](https://ziglang.org/download/)

```bash
git clone https://github.com/YUX/floo
cd floo
zig build -Doptimize=ReleaseFast
./zig-out/bin/floos --version
```

---

## Configuration

See [`examples/`](examples/) for complete examples.

**Minimal reverse tunnel (expose Emby):**

Server (public):
```toml
port = 8443
psk = "YOUR-SECRET-PSK"
default_token = "YOUR-TOKEN"

[server.services.emby]
id = 1
mode = "reverse"
local_port = 8096
target_port = 8096
```

Client (home):
```toml
remote_host = "YOUR_SERVER_IP"
remote_port = 8443
psk = "YOUR-SECRET-PSK"
default_token = "YOUR-TOKEN"
```

**Generate secrets:**
```bash
openssl rand -base64 32  # Use for PSK and token
```

---

## Diagnostics

Validate your setup before starting:

```bash
./floos --doctor floos.toml  # Check server config
./flooc --doctor flooc.toml  # Check client config and connectivity
./flooc --ping flooc.toml    # Measure tunnel latency
```

---

## Why Floo?

**vs Rathole:**
- ✅ 62% faster (29.4 vs 18.1 Gbps)
- ✅ Smaller binaries (671 KB vs 2-4 MB)
- ✅ Zero dependencies (vs 27+ crates)
- ✅ CLI diagnostics (vs logging only)

**vs FRP:**
- ✅ 194% faster (29.4 vs 10.0 Gbps)  
- ✅ 36x smaller binaries (671 KB vs 24 MB)
- ✅ Zero dependencies (vs 34+ packages)
- ✅ Simpler (CLI vs web dashboard)

**When to use alternatives:**
- **Rathole:** Need Windows support or WebSocket transport
- **FRP:** Need HTTP virtual hosting, compression, P2P mode

---

## Documentation

- **Examples:** [`examples/`](examples/) - Real-world use cases
- **CLI Reference:** Run `--help` or see [Command-Line Interface](#command-line-interface)
- **Troubleshooting:** See example READMEs
- **Advanced:** See `flooc.toml.example` and `floos.toml.example`

---

## Development

```bash
zig build test          # Run tests
zig fmt src/*.zig       # Format code
zig build release-all   # Cross-compile all platforms
```

---

## Roadmap

- [ ] io_uring backend (Linux performance)
- [ ] Compression support
- [ ] Windows support
- [ ] QUIC/DTLS for UDP
- [ ] Observability (Prometheus)

---

## Contributing

Pull requests welcome! Please:
1. Run `zig fmt` before committing
2. Add tests for new features
3. Update documentation
4. Ensure benchmarks don't regress

---

## License

MIT License - See LICENSE file

---

## Support

- **Issues:** https://github.com/YUX/floo/issues
- **Examples:** [`examples/`](examples/)
- **Discussions:** https://github.com/YUX/floo/discussions

---

**Built with ❤️ in Zig**
