# Floo

```
  _____.__
_/ ____\  |   ____   ____
\   __\|  |  /  _ \ /  _ \
 |  |  |  |_(  <_> |  <_> )
 |__|  |____/\____/ \____/
```

[![Language: Zig](https://img.shields.io/badge/language-Zig-orange.svg)](https://ziglang.org/)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](build.zig.zon)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Floo** is a lightweight, secure tunneling toolkit that lets you:
- 🔒 Access private services through encrypted tunnels
- 🌐 Expose local services to the internet securely
- ⚡ Achieve multi-gigabit throughput (18-22+ Gbps)
- 🧠 Auto-scale tunnels to your CPU cores and pin them to dedicated threads
- 📦 Deploy a single static binary with zero dependencies

Written in Zig with modern cryptography (Noise XX protocol), Floo provides both **forward tunneling** (reach into private networks) and **reverse tunneling** (expose local services) with strong authentication.

---

## 🎯 Common Use Cases

<details>
<summary><b>Access your home database from anywhere</b></summary>

Run `floos` on a public VPS and `flooc` on your home server. Connect to localhost:5432 on your laptop to reach your home PostgreSQL instance.

```bash
# On VPS (floos.toml):
[services]
postgres = "10.0.0.5:5432"

# On laptop (flooc.toml):
[services]
postgres = "127.0.0.1:5432"
```
</details>

<details>
<summary><b>Share your home media server (Jellyfin/Plex)</b></summary>

Expose your local Jellyfin server to friends without opening router ports or using dynamic DNS.

```bash
# On VPS (floos.toml):
[reverse_services]
media = "0.0.0.0:8096"

# On home server (flooc.toml):
[reverse_services]
media = "127.0.0.1:8096"
```

Friends access `http://your-vps:8096` → your home Jellyfin.
</details>

<details>
<summary><b>Work through a corporate firewall</b></summary>

Your company blocks everything except HTTP/HTTPS proxies. Floo can tunnel through SOCKS5 or HTTP CONNECT proxies.

```bash
# flooc.toml:
[advanced]
proxy_url = "socks5://corporate-proxy:1080"
```
</details>

---

## 🚀 Quick Start (5 minutes)

### Step 1: Get Floo

**Download prebuilt binaries:**
- [Latest release](https://github.com/YUX/floo/releases/latest)
- [Nightly builds](https://github.com/YUX/floo/releases/tag/nightly)

Or **build from source**:
```bash
git clone https://github.com/YUX/floo.git
cd floo
zig build -Doptimize=ReleaseFast
# Binaries in: zig-out/bin/
```

### Step 2: Generate Strong Credentials

⚠️ **Security First**: Never use default or weak credentials!

```bash
# Generate a strong PSK (Pre-Shared Key)
openssl rand -base64 32

# Generate a strong token
openssl rand -base64 24
```

Save these somewhere secure - you'll need them for both server and client.

### Step 3: Configure the Server (VPS/Public Machine)

Copy the example config:
```bash
cp configs/floos.example.toml floos.toml
```

Edit `floos.toml` and set your **real credentials**:
```toml
bind = "0.0.0.0"
port = 8443
cipher = "aes256gcm"
psk = "YOUR_GENERATED_PSK_HERE"        # ← Paste your openssl output
token = "YOUR_GENERATED_TOKEN_HERE"    # ← Paste your openssl output

[services]
# Example: allow clients to reach an internal database
database = "10.0.0.5:5432"

[reverse_services]
# Example: accept connections from clients and expose on port 8096
media = "0.0.0.0:8096"
```

### Step 4: Configure the Client (Home/Local Machine)

Copy the example config:
```bash
cp configs/flooc.example.toml flooc.toml
```

Edit `flooc.toml` with the **same credentials**:
```toml
server = "your-vps-ip:8443"            # ← Your VPS address
cipher = "aes256gcm"
psk = "YOUR_GENERATED_PSK_HERE"        # ← Must match server!
token = "YOUR_GENERATED_TOKEN_HERE"    # ← Must match server!

[services]
# Listen locally and connect through tunnel to server's "database" service
database = "127.0.0.1:5432"

[reverse_services]
# Expose your local media server through the tunnel
media = "127.0.0.1:8096"
```

### Step 5: Start the Tunnel

**On the server (VPS):**
```bash
./floos floos.toml
# [SERVER] Port: 8443
# [SERVER] Mode: Blocking I/O + Threads
```

**On the client (home machine):**
```bash
./flooc flooc.toml
# [CLIENT] Connected to tunnel server
# [CLIENT] All services started
```

### Step 6: Test It

If you configured the database example:
```bash
# On your laptop (where flooc is running):
psql -h 127.0.0.1 -p 5432
# You're now connected to your home database through the encrypted tunnel!
```

If you configured reverse media sharing:
```bash
# From anywhere on the internet:
curl http://your-vps-ip:8096
# You're accessing your home media server!
```

---

## 📖 Understanding Forward vs Reverse Modes

### Forward Mode: Reach Into Private Networks

**Scenario**: You have a database at home, want to access it from your laptop.

```
┌─────────┐    encrypted    ┌─────────┐              ┌──────────┐
│ Laptop  │───────tunnel────│   VPS   │──────────────│ Home DB  │
│ (you)   │                 │ (floos) │    local     │ 10.0.0.5 │
└─────────┘                 └─────────┘              └──────────┘
 flooc
 connects to                 defines [services]
 127.0.0.1:5432             database = "10.0.0.5:5432"
```

**Client config** (`flooc.toml`): Local listener
```toml
[services]
database = "127.0.0.1:5432"
```

**Server config** (`floos.toml`): Target location
```toml
[services]
database = "10.0.0.5:5432"
```

### Reverse Mode: Expose Local Services

**Scenario**: Share your home media server with friends.

```
┌─────────┐              ┌─────────┐     encrypted   ┌──────────┐
│ Friend  │──────────────│   VPS   │───────tunnel────│ Home     │
│ Browser │   internet   │ (floos) │                 │ Jellyfin │
└─────────┘              └─────────┘                 └──────────┘
                         binds on                     flooc
connects to              0.0.0.0:8096                 exposes
your-vps:8096            [reverse_services]          127.0.0.1:8096
```

**Server config** (`floos.toml`): Public listener
```toml
[reverse_services]
media = "0.0.0.0:8096"
```

**Client config** (`flooc.toml`): Local service
```toml
[reverse_services]
media = "127.0.0.1:8096"
```

---

## 🛠️ Configuration Reference

### Minimal Config

The simplest possible setup:

**floos.toml** (server):
```toml
port = 8443
psk = "your-strong-psk-here"
token = "your-strong-token-here"

[services]
web = "10.0.0.10:80"
```

**flooc.toml** (client):
```toml
server = "vps.example.com:8443"
psk = "your-strong-psk-here"
token = "your-strong-token-here"

[services]
web = "127.0.0.1:8080"
```

### Cipher Options

Choose based on your hardware:

| Cipher | Speed | Hardware Acceleration | Use When |
|--------|-------|----------------------|----------|
| `aegis128l` | 22+ Gbps | ARMv8, x86 AES-NI | Modern CPU, max speed |
| `aes256gcm` | 18 Gbps | ARMv8, x86 AES-NI | Modern CPU, standard choice |
| `chacha20poly1305` | 8-12 Gbps | Software-only | Older CPU, mobile devices |
| `aes128gcm` | 20 Gbps | ARMv8, x86 AES-NI | Modern CPU, compatibility |

### Per-Service Tokens

Add extra security by requiring different tokens per service:

```toml
token = "default-token"

[services]
web = "10.0.0.10:80"
web.token = "public-web-token"

database = "10.0.0.20:5432"
database.token = "sensitive-db-token"
```

Clients must use the matching token to access each service.

### UDP Support

Tunnel UDP traffic (DNS, VoIP, games):

```toml
[services]
dns = "8.8.8.8:53/udp"
voip = "10.0.0.30:5060/udp"
```

### Advanced Performance Tuning

```toml
[advanced]
socket_buffer_size = 4194304      # 4MB buffers for high throughput
num_tunnels = 0                   # 0 = auto based on CPU cores
pin_threads = true                # Pin tunnel handlers to CPU cores
io_batch_bytes = 131072           # Per-stream I/O buffer size
tcp_nodelay = true                # Disable Nagle for lower latency
heartbeat_interval_seconds = 30   # Keepalive frequency
```

> ℹ️ **num_tunnels**: leave at `0` to match your CPU core count automatically. Set an explicit number only when you need to cap or boost tunnel fan-out.
>
> ℹ️ **pin_threads**: keeps each tunnel on a dedicated core (Linux/Unix). Disable only if your scheduler forbids manual affinity.
>
> ℹ️ **io_batch_bytes**: per-stream read/write buffer size. Increase for jumbo frames or high-latency satellite links; decrease for memory-constrained devices.

---

## 🔍 Built-in Diagnostics

Validate your configuration before running:

```bash
# Test server config
./floos --doctor floos.toml
# ✓ Configuration valid
# ✓ Can bind on 0.0.0.0:8443
# ✓ All forward targets reachable

# Test client config
./flooc --doctor flooc.toml
# ✓ Configuration valid
# ✓ Server reachable at vps.example.com:8443
# ⚠ Warning: proxy_url not set
```

Measure tunnel latency:

```bash
./flooc --ping flooc.toml
# Noise handshake latency: 8.2ms
```

Test target connectivity:

```bash
./floos --ping floos.toml
# [PING] database (10.0.0.5:5432): 1.2ms ✓
# [PING] api (10.0.0.10:443): 3.5ms ✓
```

---

## 📦 Prebuilt Binaries

Every release publishes optimized binaries for:

| Platform | File | Best For |
|----------|------|----------|
| **Linux x86_64** | `floo-x86_64-linux-gnu.tar.gz` | Ubuntu, Debian, RHEL, Fedora |
| **Linux x86_64 (Haswell+)** | `floo-x86_64-linux-gnu-haswell.tar.gz` | Modern servers (2013+), 3-5× crypto speed |
| **Linux x86_64 (static)** | `floo-x86_64-linux-musl.tar.gz` | Alpine, containers, no glibc |
| **Linux ARM64** | `floo-aarch64-linux-gnu.tar.gz` | Raspberry Pi, AWS Graviton, cloud ARM |
| **Linux ARM64 (optimized)** | `floo-aarch64-linux-gnu-neoverse-n1.tar.gz` | AWS Graviton, Ampere Altra |
| **macOS Apple Silicon** | `floo-aarch64-macos-m1.tar.gz` | M1/M2/M3/M4 Macs |
| **macOS Intel** | `floo-x86_64-macos.tar.gz` | Intel Macs |

Download from [releases page](https://github.com/YUX/floo/releases).

---

## 🏗️ Building from Source

Requires [Zig 0.15.1+](https://ziglang.org/download/)

```bash
# Debug build (fast compilation)
zig build

# Optimized release build
zig build -Doptimize=ReleaseFast

# Cross-compile for Raspberry Pi
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu -Dcpu=cortex_a72

# Build all release artifacts
zig build release-all
```

Run tests:
```bash
zig build test
```

---

## 🔐 Security Features

- ✅ **Noise XX protocol** - Modern cryptographic handshake with perfect forward secrecy
- ✅ **AEAD ciphers** - Authenticated encryption prevents tampering
- ✅ **PSK authentication** - Mutual verification of server and client
- ✅ **Per-service tokens** - Fine-grained access control
- ✅ **Constant-time comparisons** - Prevents timing attacks
- ✅ **Rate limiting** - Protects against connection floods (100/sec default)
- ✅ **No default credentials** - Refuses to start with example passwords

⚠️ **Important Security Notes**:
1. Always use strong, randomly-generated PSKs and tokens
2. Never commit credentials to version control
3. Rotate credentials if you suspect compromise
4. Use `cipher = "none"` only for debugging on trusted networks

---

## 📚 Examples

The `examples/` directory contains complete working setups:

- **[access-cloud-database](examples/access-cloud-database/)** - Securely connect to RDS/cloud databases
- **[expose-home-server](examples/expose-home-server/)** - Share Jellyfin/Plex media servers
- **[expose-multiple-services](examples/expose-multiple-services/)** - Multi-service with per-service tokens
- **[multi-client-loadbalancing](examples/multi-client-loadbalancing/)** - Run multiple clients for redundancy
- **[reverse-forwarding-emby](examples/reverse-forwarding-emby/)** - Complete Emby streaming setup
- **[through-corporate-proxy](examples/through-corporate-proxy/)** - Tunnel through corporate SOCKS5/HTTP proxies

Each example includes ready-to-use config files and setup instructions.

---

## 🗺️ Roadmap

- [ ] Compression for high-latency links
- [ ] io_uring backend (Linux performance boost)
- [ ] QUIC/DTLS transport for UDP
- [ ] Prometheus metrics endpoint
- [ ] Web dashboard for monitoring

---

## 🤝 Contributing

Pull requests welcome! Please:
- Include tests for protocol changes
- Run `zig fmt src/*.zig` before committing
- Use `--doctor` mode to validate config changes
- Document new features in README and examples

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## ⚡ Performance

Benchmarked on AWS c7g.xlarge (Graviton 3, 4 vCPU):

| Cipher | Single Stream | Notes |
|--------|--------------|-------|
| AEGIS-128L | 22.6 Gbps | Hardware crypto, ARM v8.4+ |
| AES-256-GCM | 18.0 Gbps | Hardware AES-NI |
| ChaCha20-Poly1305 | 11.2 Gbps | Software fallback |
| Plaintext (debug) | 28+ Gbps | Baseline |

For max throughput, let `num_tunnels = 0` (auto) so Floo matches your CPU core count, and pair it with AEGIS/AES ciphers on modern hardware.

---

**Questions?** Check the [examples/](examples/) directory or open an issue.
# 🔍 Built-in Runtime Metrics

Every `floos`/`flooc` process keeps live counters for:

- **Encryption time** – total nanoseconds spent encrypting/decrypting plus average cost per frame.
- **Throughput** – cumulative plaintext bytes transmitted (tx) and received (rx) per tunnel.

Dump a snapshot at any time with `SIGUSR1`, or just stop the process cleanly:

```bash
kill -USR1 $(pgrep floos)   # server side
kill -USR1 $(pgrep flooc)   # client side
```

Sample output:

```
[PROFILE] server encryption total=12000 ns calls=14 avg=857 ns
[PROFILE] server throughput tx=865 bytes (0.00 MB) rx=9649744503 bytes (9202.71 MB)
```

### When it’s useful

- **Capacity planning / billing** – snapshot tx/rx periodically to see true payload volume.
- **Benchmark verification** – correlate iperf results with tunnel counters when tuning ciphers or kernels.
- **Health monitoring** – alert when payload volume drops unexpectedly or encryption costs spike (CPU pressure).

Because the counters are always on in the data path, there’s no extra agent to run—just signal the process and parse the two log lines.

---
