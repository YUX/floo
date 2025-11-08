# Reverse Forwarding: Emby/Jellyfin

Expose a home media server by running floos on a VPS and flooc on the machine
that hosts Emby/Jellyfin.

## Flow

```
Home LAN                              Public VPS
┌─────────────┐                       ┌───────────────────────┐
│ Emby :8096  │ ← reverse tunnel ←── │ floos :8443 + :8096   │
│ flooc       │ ─── encrypted ───▶   │ publishes http port   │
└─────────────┘                       └───────────────────────┘
```

## Configuration summary

1. **Server (`floos.toml`)** – bind to `0.0.0.0:8443`, create `[reverse_services]`
   entry such as `emby = "0.0.0.0:8096"`.
2. **Client (`flooc.toml`)** – point `server = "VPS_IP:8443"` and mirror the
   service locally with `emby = "127.0.0.1:8096"`.
3. Use the **same** PSK + token on both sides.

Files in this folder are ready to copy, just replace the secrets and IPs.

## Start the tunnel

```bash
# On the VPS or Raspberry Pi
./floos floos.toml

# On the home server
./flooc flooc.toml
```

Optional: run `./flooc --doctor flooc.toml` to verify reachability without
starting the reverse listener.

## Hardening + tuning

- Leave `num_tunnels = 0` to auto-scale with CPU cores; bump it only if you need
  more dedicated tunnels than the hardware provides.
- Bump `socket_buffer_size` beyond 512 KB when pushing 4K video across
  high-latency links.
- Combine Floo with an HTTPS reverse proxy (Caddy/Traefik/nginx) on the VPS if
  you need browser TLS certificates.

## Troubleshooting checklist

| Issue | Checks |
|-------|--------|
| Handshake fails | Cipher/PSK/token mismatch, firewall blocking 8443 |
| Reverse port closed | Confirm floos is running and listening on the publish port |
| Streaming stutters | Inspect `socket_buffer_size`, internet uplink, or enable multiple tunnels |
| flooc disconnects | Look at `reconnect_*` settings and ISP router logs |
