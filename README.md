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

| I want to... | Example | Time |
|--------------|---------|------|
| **Expose my home Emby/Plex** | [`expose-home-server/`](examples/expose-home-server/) | 5 min |
| **Access cloud database** | [`access-cloud-database/`](examples/access-cloud-database/) | 5 min |
| **Expose Emby + SSH** | [`expose-multiple-services/`](examples/expose-multiple-services/) | 10 min |
| **Through corporate proxy** | [`through-corporate-proxy/`](examples/through-corporate-proxy/) | 5 min |

### 2. Download Binaries

[**Nightly builds**](https://github.com/YUX/floo/releases/tag/nightly) (updated automatically):
- `floo-aarch64-macos-m1.tar.gz` - Apple Silicon
- `floo-aarch64-linux-rpi.tar.gz` - Raspberry Pi
- `floo-x86_64-linux-haswell.tar.gz` - Modern Linux

Or build: `zig build -Doptimize=ReleaseFast`

### 3. Follow the Example

Each example has complete setup guide + configs. Just copy, edit, run!

---

## Feature Comparison

| Feature | Floo | Rathole | FRP |
|---------|------|---------|-----|
| **Language** | Zig | Rust | Go |
| **Dependencies** | **0** ⭐ | 27+ crates | 34+ packages |
| **Max Throughput (M1)** | **29.4 Gbps** ⭐ | 18.1 Gbps | 10.0 Gbps |
| **vs Rathole** | **+62%** faster | baseline | -45% slower |
| **vs FRP** | **+194%** faster | +81% faster | baseline |
| **Reverse Tunneling** | ✅ | ✅ | ✅ |
| **Forward Tunneling** | ✅ | ✅ | ✅ |
| **Proxy Client** | ✅ SOCKS5, HTTP | ✅ SOCKS5, HTTP | ✅ HTTP, SOCKS5 |
| **Multi-Service** | ✅ | ✅ | ✅ |
| **Parallel Tunnels** | ✅ Explicit (1-16) | 🔶 | ✅ Connection pool |
| **Built-in Diagnostics** | ✅ `--doctor`, `--ping` | 🔶 Logging | ✅ Dashboard |
| **Binary Size** | **394 KB + 277 KB** ⭐ | ~1-2 MB each | ~12-13 MB |
| **Hot Reload** | ✅ SIGHUP | ✅ | ✅ Admin API |

**Visual Comparison:**

```
Dependencies:  Floo      ∅ (zero)          ⭐
               Rathole   ████████████████████████████ (27+ crates)
               FRP       █████████████████████████████████ (34+ packages)

Binary Size:   Floo      ▌ 671 KB          ⭐
               Rathole   ████ ~2-4 MB
               FRP       ████████████████████████████████ ~24+ MB

Throughput:    Floo      ██████████████████████████████ 29.4 Gbps ⭐
               Rathole   ██████████████████ 18.1 Gbps
               FRP       ██████████ 10.0 Gbps
```

**When to use alternatives:**
- **Rathole:** Windows support, WebSocket transport
- **FRP:** HTTP virtual hosting, compression, P2P mode

---

## Performance

**Benchmark** (Apple M1 MacBook Air):

| Configuration | Throughput |
|--------------|-----------|
| Floo (AEGIS-128L) | **29.4 Gbps** ⭐ |
| Floo (AEGIS-256) | 24.5 Gbps |
| Rathole | 18.1 Gbps |
| Floo (AES-128-GCM) | 17.9 Gbps |
| Floo (AES-256-GCM) | 15.8 Gbps |
| FRP | 10.0 Gbps |
| Floo (ChaCha20) | 3.53 Gbps |

**Visual:**
```
Floo (AEGIS-128L)   ██████████████▊ ⭐                                   29.4 Gbps
Floo (AEGIS-256)    ████████████▎                                        24.5 Gbps
Rathole             █████████▏                                           18.1 Gbps
Floo (AES-128-GCM)  █████████                                            17.9 Gbps
Floo (AES-256-GCM)  ████████                                             15.8 Gbps
FRP                 █████                                                10.0 Gbps
Floo (ChaCha20)     █▊                                                    3.53 Gbps
                    └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴────►
                    0     5    10    15    20    25    30 Gbps
```

---

## Installation

### Option 1: Pre-built Binaries (Recommended)

[**Download from releases**](https://github.com/YUX/floo/releases/tag/nightly):

```bash
wget https://github.com/YUX/floo/releases/download/nightly/floo-aarch64-macos-m1.tar.gz
tar xzf floo-*.tar.gz
cd floo-*/
./flooc --version
./floos --version
```

### Option 2: Build from Source

**Requirements:** Zig 0.15.x

```bash
git clone https://github.com/YUX/floo
cd floo
zig build -Doptimize=ReleaseFast
./zig-out/bin/floos --version
```

---

## Key Features

- **🔐 Noise XX + PSK** - Mutual authentication with 5 AEAD ciphers
- **🔄 Reverse tunneling** - Expose local services through public server (like ngrok)
- **⚡ Forward tunneling** - Access remote services securely (like SSH -L)
- **🌐 Proxy support** - SOCKS5 and HTTP CONNECT for corporate networks
- **📊 Built-in diagnostics** - `--doctor` and `--ping` commands
- **🔧 Hot config reload** - Update settings without restart (SIGHUP)
- **💓 Auto-reconnect** - Exponential backoff, heartbeat supervision

---

## CLI Reference

### Server (`floos`)

```bash
floos floos.toml                    # Start server
floos --doctor floos.toml          # Validate config
floos --ping floos.toml            # Test service reachability
floos -p 9000 floos.toml           # Override port
```

### Client (`flooc`)

```bash
flooc flooc.toml                   # Start client
flooc --doctor flooc.toml          # Validate config and connectivity
flooc --ping flooc.toml            # Measure tunnel latency
flooc -r server.com:8443 --ping    # Quick test
flooc -x socks5://proxy:1080       # Through proxy
```

**See [`examples/`](examples/) for complete usage guides.**

---

## Common Issues

### Connection Refused
```bash
./flooc --ping flooc.toml  # Test connectivity
# Check: firewall, correct IP, server running
```

### Authentication Failed  
```bash
# Verify PSK and cipher match EXACTLY in both configs
grep "psk\|cipher" floos.toml flooc.toml
```

### Heartbeat Timeout
```bash
# Server heartbeat_interval (30s) < Client timeout (40s)
grep "heartbeat" floos.toml flooc.toml
```

**Full troubleshooting:** See example READMEs

---

## Configuration

**Reverse mode** (expose home service):
```toml
# Server (public)
[server.services.emby]
mode = "reverse"
local_port = 8096  # Users connect here

# Client (home)
remote_host = "server.ip"
```

**Forward mode** (access remote service):
```toml
# Server (remote)
[server.services.db]
target_port = 5432  # Server connects here

# Client (local)
local_port = 5432  # You connect here
```

**See [`examples/`](examples/) for complete configurations.**

---

## Development

```bash
zig build test                      # Run tests
zig fmt src/*.zig                   # Format code
zig build release-all               # Cross-compile
./run_benchmarks.sh                 # Benchmark suite
```

---

## Roadmap

- [ ] Windows support
- [ ] Compression
- [ ] io_uring backend (Linux)
- [ ] QUIC/DTLS for UDP
- [ ] Prometheus metrics

---

## Contributing

Pull requests welcome!

1. Format: `zig fmt src/*.zig`
2. Test: `zig build test`
3. Document changes
4. Ensure benchmarks don't regress

---

## License

MIT - See LICENSE file

---

## Links

- **Examples:** [`examples/`](examples/)
- **Issues:** https://github.com/YUX/floo/issues
- **Releases:** https://github.com/YUX/floo/releases

---

**Built with ❤️ in Zig**
