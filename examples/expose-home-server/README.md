# Expose a Home Media Server (Jellyfin/Plex/Emby)

Share your home media server with friends without opening router ports or dealing with dynamic DNS. Floo creates a secure encrypted tunnel from your home to a public VPS, making your media server accessible on the internet.

## 📋 What You Need

- **Home machine** running Jellyfin/Plex/Emby
- **Public VPS** (DigitalOcean, AWS, etc.) with a static IP
- **5 minutes** to set up

## 🏗️ How It Works

```
┌─────────────────┐              ┌─────────────────┐              ┌──────────────┐
│   Friend's      │              │   Your VPS      │              │ Your Home    │
│   Browser       │──────────────│   (floos)       │──────────────│ (flooc +     │
│                 │  Internet    │                 │  Encrypted   │  Jellyfin)   │
│                 │              │ Listens :80     │  Tunnel      │ 127.0.0.1    │
└─────────────────┘              └─────────────────┘              └──────────────┘

Friend visits                    Relay traffic                   Media server
http://vps-ip/                  over secure tunnel              stays private
```

**Key benefit**: No port forwarding or dynamic DNS needed. Your home router stays secure with no exposed ports.

---

## 🚀 Step-by-Step Setup

### Step 1: Generate Strong Credentials

On your VPS or home machine, generate random credentials:

```bash
# Generate PSK (Pre-Shared Key)
openssl rand -base64 32

# Generate authentication token
openssl rand -base64 24
```

**Save both outputs** - you'll need them for both server and client configs.

### Step 2: Configure the Server (VPS)

On your VPS, create `floos.toml`:

```toml
bind = "0.0.0.0"
port = 8443              # Clients connect here
cipher = "aes256gcm"
psk = "PASTE_YOUR_PSK_HERE"       # ← From step 1
token = "PASTE_YOUR_TOKEN_HERE"   # ← From step 1

[reverse_services]
jellyfin = "0.0.0.0:8096"  # Public access on port 8096

[advanced]
tcp_nodelay = true
tcp_keepalive = true
socket_buffer_size = 8388608    # 8MB buffers for streaming
pin_threads = true
io_batch_bytes = 131072
heartbeat_interval_seconds = 30
```

**Start the server**:
```bash
./floos floos.toml
# [SERVER] Port: 8443
# [SERVER] Waiting for tunnel connections...
```

### Step 3: Configure the Client (Home)

On your home machine (where Jellyfin runs), create `flooc.toml`:

```toml
server = "YOUR_VPS_IP:8443"      # ← Your VPS address
cipher = "aes256gcm"
psk = "PASTE_SAME_PSK_HERE"      # ← Must match server!
token = "PASTE_SAME_TOKEN_HERE"  # ← Must match server!

[reverse_services]
jellyfin = "127.0.0.1:8096"      # Your local Jellyfin port

[advanced]
num_tunnels = 0                  # Auto-match CPU cores (set >0 to override)
pin_threads = true
io_batch_bytes = 131072
reconnect_enabled = true         # Auto-reconnect if connection drops
socket_buffer_size = 8388608     # 8MB buffers for streaming
```

**Start the client**:
```bash
./flooc flooc.toml
# [CLIENT] Connected to tunnel server
# [CLIENT] Reverse service 'jellyfin' ready
```

### Step 4: Test It

Open a browser and go to:
```
http://YOUR_VPS_IP:8096
```

You should see your Jellyfin login page! 🎉

The traffic flows:
1. Friend → VPS:8096
2. VPS → (encrypted tunnel) → Your home machine
3. Your home → Jellyfin on localhost:8096
4. Response → back through tunnel → Friend

---

## ✅ Verify Setup

Test your configuration before going live:

```bash
# On home machine
./flooc --doctor flooc.toml
# ✓ Configuration valid
# ✓ Connected to tunnel server
# ✓ Handshake completed
```

---

## 🔒 Security Hardening (Recommended)

### Add HTTPS

Put nginx/Caddy on your VPS to add HTTPS:

```nginx
# /etc/nginx/sites-available/media
server {
    listen 443 ssl;
    server_name media.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/media.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/media.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8096;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then change floos.toml to bind on localhost:
```toml
[reverse_services]
jellyfin = "127.0.0.1:8096"  # Only nginx can access
```

### Run as System Service

Create `/etc/systemd/system/flooc.service` on home machine:

```ini
[Unit]
Description=Floo Tunnel Client
After=network.target

[Service]
Type=simple
User=yourusername
WorkingDirectory=/home/yourusername/floo
ExecStart=/home/yourusername/floo/flooc flooc.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable flooc
sudo systemctl start flooc
```

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| **Connection refused** | Check VPS firewall allows port 8443 (TCP) |
| **Handshake failed** | Verify PSK and token match exactly on both sides |
| **Can't access Jellyfin** | Ensure Jellyfin runs on 127.0.0.1:8096 locally |
| **Tunnel disconnects** | `reconnect_enabled = true` in flooc.toml (already set) |
| **Slow streaming** | Leave `num_tunnels = 0` (auto) and raise `socket_buffer_size` / `io_batch_bytes` for bigger bursts |
| **Server refuses to start** | Replace placeholder credentials with real ones! |

### Debug Commands

```bash
# Check if Jellyfin is running locally
curl http://127.0.0.1:8096

# Check if VPS port is open
nc -zv YOUR_VPS_IP 8443

# View flooc logs
./flooc flooc.toml  # Watch output for errors
```

---

## 🎯 Advanced: Multiple Services

Want to expose Jellyfin AND Plex? Easy:

**floos.toml** (VPS):
```toml
[reverse_services]
jellyfin = "0.0.0.0:8096"
plex = "0.0.0.0:32400"
```

**flooc.toml** (Home):
```toml
[reverse_services]
jellyfin = "127.0.0.1:8096"
plex = "127.0.0.1:32400"
```

Each service can have its own token:
```toml
[reverse_services]
jellyfin = "0.0.0.0:8096"
jellyfin.token = "friends-only-token"

admin_panel = "0.0.0.0:9000"
admin_panel.token = "admin-secret-token"
```

---

## 💡 Performance Tips

For 4K streaming:
```toml
[advanced]
socket_buffer_size = 8388608     # 8MB buffers
num_tunnels = 0                  # Auto-match CPU cores (set >0 to force)
pin_threads = true               # Keep tunnels on dedicated cores
io_batch_bytes = 131072          # Larger per-stream batch
tcp_nodelay = true               # Lower latency
```

> 💡 Run `kill -USR1 $(pgrep flooc)` or `kill -USR1 $(pgrep floos)` to dump live
> throughput and encryption timing stats while you tune these settings.

For bandwidth monitoring, check your VPS:
```bash
iftop -i eth0  # Monitor traffic in real-time
```

---

## 📱 Mobile Access

Your friends can access your server from their phones too! Just give them:
```
http://YOUR_VPS_IP:8096
```

Or better yet, set up a domain name:
```
http://media.yourdomain.com
```

---

**Questions?** Check the [main README](../../README.md) or open an issue.

**Enjoying Floo?** ⭐ Star the repo and share with friends!
