# Expose Multiple Services with One flooc

Serve Emby (HTTP) and SSH simultaneously through a single Floo client. The
server publishes two public ports; flooc routes each connection back to the
correct local target.

## Config recap

- `floos.toml` defines two `[reverse_services]`: `emby` on `0.0.0.0:8096` and
  `ssh` on `0.0.0.0:2222`. Each has its own token so you can share media without
  exposing SSH credentials.
- `flooc.toml` registers the same service names but points them to local
  addresses (`127.0.0.1:8096` and `127.0.0.1:22`). The SSH service overrides its
  token to match the server-side requirement.

## Launch sequence

```bash
# On the VPS
./floos floos.toml

# On the home lab machine
./flooc flooc.toml
```

Once the tunnel is up:

- Friends visit `http://YOUR_SERVER_IP:8096` for Emby.
- You connect via `ssh -p 2222 user@YOUR_SERVER_IP` for administration.

## Tips

- Leave `num_tunnels = 0` to let Floo match your CPU cores automatically; set an
  explicit value (e.g. `num_tunnels = 4`) only when you want to cap or boost
  tunnel fan-out for specific workloads.
- Add more sections under `[reverse_services]` to expose additional ports using
  the same tunnel.
- Use per-service tokens to gate sensitive ports (SSH, admin dashboards) while
  keeping others broadly accessible.
