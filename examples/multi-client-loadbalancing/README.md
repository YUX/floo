# Multi-Client Load Balancing

Run multiple flooc instances that advertise the **same reverse service name** to
share incoming traffic. floos round-robins new connections across the tunnels.

## Files

- `floos.toml` – publishes `webcluster` on port 8080.
- `flooc-site-a.toml` – forwards traffic to Site A origin (`10.0.1.10:8080`).
- `flooc-site-b.toml` – forwards traffic to Site B origin (`10.0.2.10:8080`).

## How to use

1. Start floos on the public server.
2. Start flooc on Site A and Site B (can be different geographic regions).
3. Each client leaves `num_tunnels = 0`, so Floo opens one tunnel per CPU core
   (set an explicit value if you need to cap fan-out).
4. When users hit `http://YOUR_SERVER_IP:8080`, Floo rotates connections between
   Site A and Site B tunnels.

Add or remove clients at will—just keep the `[reverse_services]` name identical.
