```
███████╗██╗      ██████╗  ██████╗
██╔════╝██║     ██╔═══██╗██╔═══██╗
█████╗  ██║     ██║   ██║██║   ██║
██╔══╝  ██║     ██║   ██║██║   ██║
██║     ███████╗╚██████╔╝╚██████╔╝
╚═╝     ╚══════╝ ╚═════╝  ╚═════╝

Dependencies:  Floo      ∅ (zero)          ⭐
               Rathole   ████████████████████████████ (27+ crates)
               FRP       █████████████████████████████████ (34+ packages)

Binary Size:   Floo      ▌ 671 KB total (394 KB + 277 KB)  ⭐
               Rathole   ████ ~2-4 MB total
               FRP       ████████████████████████████████ ~24+ MB total

Throughput:    Floo      ██████████████████████████████ 29.4 Gbps ⭐
               Rathole   ██████████████████ 18.1 Gbps
               FRP       ██████████ 10.0 Gbps
```

**Secure, high-performance tunneling in Zig. Expose your home services or access remote ones.**

[![Language: Zig](https://img.shields.io/badge/language-Zig-orange.svg)](https://ziglang.org/)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-green.svg)](build.zig.zon)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)


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


## Feature Comparison

| Feature | Floo | Rathole | FRP |
|---------|------|---------|-----|
| **Language** | Zig | Rust | Go |
| **Dependencies** | **0** ⭐ | 27+ crates | 34+ packages |
| **Max Throughput (M1)** | **29.4 Gbps** ⭐ | 18.1 Gbps | 10.0 Gbps |
| **vs Rathole** | **+62%** faster | baseline | -45% slower |
| **vs FRP** | **+194%** faster | +81% faster | baseline |
| **Encryption** | Noise XX + PSK | Noise NK, TLS, WS | TLS |
| **Ciphers** | 5 AEAD (AEGIS, AES-GCM, ChaCha20) | ChaCha20-Poly1305 | TLS standard |
| **TCP Forwarding** | ✅ | ✅ | ✅ |
| **UDP Forwarding** | ✅ | ✅ | ✅ |
| **Multi-Service** | ✅ Per tunnel | ✅ Per tunnel | ✅ Per process |
| **Parallel Tunnels** | ✅ Round-robin (1-16) | 🔶 Not documented | ✅ Connection pool |
| **Token Auth** | ✅ Per-service + default | ✅ Per-service + default | ✅ Global + OIDC |
| **Hot Config Reload** | ✅ SIGHUP (both) | ✅ Dynamic services | ✅ Admin API |
| **Heartbeat** | ✅ Configurable | ✅ Configurable | ✅ Configurable |
| **Auto-Reconnect** | ✅ Exponential backoff | ✅ Exponential backoff | ✅ Reconnection |
| **Built-in Diagnostics** | ✅ `--doctor`, `--ping` | 🔶 Logging only | ✅ Dashboard, Prometheus |
| **Config Format** | TOML | TOML | TOML, INI, YAML |
| **CLI Overrides** | ✅ Port, host, target, proxy | 🔶 Limited | ✅ Via flags |
| **IPv6 Support** | ✅ | ✅ | ✅ |
| **Proxy Client** | ✅ SOCKS5, HTTP CONNECT | ✅ SOCKS5, HTTP | ✅ HTTP, SOCKS5 |
| **Compression** | ❌ Planned | ❌ | ✅ |
| **HTTP Features** | ❌ | ❌ | ✅ Virtual hosts, auth |
| **P2P Mode** | ❌ | ❌ | ✅ XTCP, STCP |
| **Load Balancing** | ✅ Round-robin tunnels | 🔶 Not documented | ✅ Multiple backends |
| **Binary Size** | **394 KB + 277 KB** ⭐ | ~1-2 MB each | ~12-13 MB compressed |
| **Platform** | macOS, Linux (Windows planned) | Linux, macOS, Windows | All platforms |

- **🔐 Noise XX + PSK** - Mutual authentication with 5 AEAD ciphers
- **🔄 Reverse tunneling** - Expose local services through public server 
- **⚡ Forward tunneling** - Access remote services securely (like SSH -L)
- **🌐 Proxy support** - SOCKS5 and HTTP CONNECT for corporate networks
- **📊 Built-in diagnostics** - `--doctor` and `--ping` commands
- **🔧 Hot config reload** - Update settings without restart (SIGHUP)
- **💓 Auto-reconnect** - Exponential backoff, heartbeat supervision

> **Note:** All features verified against source repositories (Rathole v0.5.0, FRP v0.65.0). Benchmarks measured on identical hardware (Apple M1 MacBook Air) using `iperf3` with single stream. Dependencies counted from Cargo.toml/go.mod. Binary sizes measured from compiled/released artifacts.





## Performance

**Benchmark** (Apple M1 MacBook Air):

```
Raw loopback        ████████████████████████████████████████████████████ 99.8 Gbps
Floo (plaintext)    █████████████████▌                                   34.8 Gbps
Floo (AEGIS-128L)   ██████████████▊ ⭐                                   29.4 Gbps
Floo (AEGIS-256)    ████████████▎                                        24.5 Gbps
Rathole             █████████▏                                           18.1 Gbps
Floo (AES-128-GCM)  █████████                                            17.9 Gbps
Floo (AES-256-GCM)  ████████                                             15.8 Gbps
FRP                 █████                                                10.0 Gbps
Floo (ChaCha20)     █▊                                                   3.53 Gbps
                    └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴────►
                    0    10    20    30    40    50    60    70    80    90   100 Gbps
```

- **AEGIS ciphers** deliver the best encrypted performance (29.4 Gbps)
- **Floo outperforms alternatives** by 62% (vs Rathole) with AEGIS-128L
- Hardware acceleration (ARM crypto extensions) makes encryption nearly free
- Even AES-GCM maintains competitive throughput vs. plaintext alternatives


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


## Development

```bash
zig build test                      # Run tests
zig fmt src/*.zig                   # Format code
zig build release-all               # Cross-compile
./run_benchmarks.sh                 # Benchmark suite
```



## Roadmap

- [ ] Windows support
- [ ] Compression
- [ ] io_uring backend (Linux)
- [ ] QUIC/DTLS for UDP
- [ ] Prometheus metrics



## Contributing

Pull requests welcome!

1. Format: `zig fmt src/*.zig`
2. Test: `zig build test`
3. Document changes
4. Ensure benchmarks don't regress


## License

MIT - See LICENSE file



## Links

- **Examples:** [`examples/`](examples/)
- **Issues:** https://github.com/YUX/floo/issues
- **Releases:** https://github.com/YUX/floo/releases

---

**Built with ❤️ in Zig**
