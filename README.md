# Floo

[![Language: Zig](https://img.shields.io/badge/language-Zig-orange.svg)](https://ziglang.org/)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](build.zig.zon)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Floo is a small, fast tunneling toolkit for private services.

- `floos` runs on a public server.
- `flooc` runs near the private service or on your laptop.
- Traffic is authenticated with a PSK and token, and encrypted with Noise XX plus AEAD ciphers by default.

Use it to reach a private database, expose a home service through a VPS, or tunnel through a SOCKS5/HTTP CONNECT proxy.

## Quick Start

### 1. Get Floo

Download a binary from the [latest release](https://github.com/YUX/floo/releases/latest), or build from source:

```bash
git clone https://github.com/YUX/floo.git
cd floo
zig build -Doptimize=ReleaseFast
```

Binaries are written to `zig-out/bin/`.

The commands below assume a source build. If you downloaded a release archive, run `./floos` and `./flooc` from the extracted directory instead.

### 2. Generate Credentials

Use strong shared secrets. Floo refuses placeholder, default, short, and low-entropy credentials.

```bash
openssl rand -base64 32 # psk
openssl rand -base64 24 # token
```

Use the same `psk` and `token` on both sides.

### 3. Configure the Server

Create `floos.toml` on the public machine:

```toml
bind = "0.0.0.0"
port = 8443
cipher = "aegis128l"
psk = "REPLACE_WITH_OPENSSL_RAND_BASE64_32_OUTPUT"
token = "REPLACE_WITH_OPENSSL_RAND_BASE64_24_OUTPUT"

[services]
# Forward mode: clients reach this private target through the tunnel.
database = "10.0.0.5:5432"

[reverse_services]
# Reverse mode: the server exposes this public listener for a client-side service.
media = "0.0.0.0:8096"
```

### 4. Configure the Client

Create `flooc.toml` on the machine that will connect to `floos`:

```toml
server = "your-vps.example.com:8443"
cipher = "aegis128l"
psk = "REPLACE_WITH_OPENSSL_RAND_BASE64_32_OUTPUT"
token = "REPLACE_WITH_OPENSSL_RAND_BASE64_24_OUTPUT"

[services]
# Forward mode: listen locally and route to server-side `database`.
database = "127.0.0.1:5432"

[reverse_services]
# Reverse mode: serve traffic accepted by server-side `media`.
media = "127.0.0.1:8096"
```

Use either `[services]`, `[reverse_services]`, or both.

### 5. Validate and Run

```bash
./zig-out/bin/floos --doctor floos.toml
./zig-out/bin/flooc --doctor flooc.toml

./zig-out/bin/floos floos.toml
./zig-out/bin/flooc flooc.toml
```

Test forward mode from the client side:

```bash
psql -h 127.0.0.1 -p 5432
```

Test reverse mode from the internet:

```bash
curl http://your-vps.example.com:8096
```

## Mental Model

| Mode | Server config | Client config | Result |
|---|---|---|---|
| Forward | `[services] database = "10.0.0.5:5432"` | `[services] database = "127.0.0.1:5432"` | Client connects to `127.0.0.1:5432` to reach `10.0.0.5:5432`. |
| Reverse | `[reverse_services] media = "0.0.0.0:8096"` | `[reverse_services] media = "127.0.0.1:8096"` | Public users connect to the server on `:8096` to reach the client-side service. |

## Useful Commands

```bash
zig build                         # debug build
zig build -Doptimize=ReleaseFast  # optimized build
zig build test                    # unit tests
zig build release-all             # cross-platform release binaries

./zig-out/bin/floos --help
./zig-out/bin/flooc --help
./zig-out/bin/flooc --ping flooc.toml
./zig-out/bin/floos --ping floos.toml
```

## Common Options

```toml
cipher = "aegis128l" # default; good on modern x86/ARM

[advanced]
num_tunnels = 0 # 0 = auto scale to CPU count
pin_threads = true
io_batch_bytes = 131072
proxy_url = "socks5://127.0.0.1:1080" # client-side proxy, optional
```

UDP services use `/udp`:

```toml
[services]
dns = "8.8.8.8:53/udp"
```

Per-service tokens are supported:

```toml
token = "REPLACE_WITH_DEFAULT_TOKEN"

[services]
database = "10.0.0.5:5432"
database.token = "REPLACE_WITH_DATABASE_TOKEN"
```

## Examples

Complete examples live in [examples/](examples/):

- [access-cloud-database](examples/access-cloud-database/)
- [expose-home-server](examples/expose-home-server/)
- [expose-multiple-services](examples/expose-multiple-services/)
- [multi-client-loadbalancing](examples/multi-client-loadbalancing/)
- [reverse-forwarding-emby](examples/reverse-forwarding-emby/)
- [through-corporate-proxy](examples/through-corporate-proxy/)

Template configs live in [configs/](configs/).

## Requirements

- Zig 0.16.0 to build from source
- Linux or macOS for current release targets
- MIT License; see [LICENSE](LICENSE)
