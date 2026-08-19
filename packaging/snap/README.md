# Floo Snap Package

Official Snap package for Floo - High-performance tunneling in Zig.

## Installation

### From Snap Store (after publishing)

```bash
sudo snap install floo
```

### From Local Build

```bash
# Build the snap
cd packaging
./build-snap.sh 0.3.0

# Install
sudo snap install snap/floo_0.3.0_amd64.snap --dangerous
```

## Usage

### Running Commands

```bash
# Client
floo.flooc --version
floo.flooc flooc.toml

# Server
floo.floos --version
floo.floos floos.toml
```

### Configuration Files

Example configs are located at:
```
/snap/floo/current/share/doc/floo/examples/
```

Copy them to your home directory:
```bash
cp /snap/floo/current/share/doc/floo/examples/*.toml ~/
```

### Running as a Service (Server)

The snap includes a daemon for running floos as a system service:

```bash
# The service uses a default config at /var/snap/floo/common/floos.toml
# Create your config:
sudo mkdir -p /var/snap/floo/common
sudo nano /var/snap/floo/common/floos.toml

# Enable and start the service
sudo snap start floo.floos
sudo snap logs floo.floos

# Check status
sudo snap services floo.floos

# Stop the service
sudo snap stop floo.floos
```

## Permissions

The snap uses strict confinement with the following interfaces:

- **network** - Required for network connections
- **network-bind** - Required to bind to ports
- **network-control** - Required for advanced networking (server only)
- **home** - Read access to home directory for config files

All interfaces are connected automatically on installation.

## Building Locally

### Prerequisites

```bash
# Install snapcraft
sudo snap install snapcraft --classic

# Install LXD (for building)
sudo snap install lxd
sudo lxd init --auto
```

### Build

```bash
cd packaging/snap
snapcraft
```

This creates `floo_VERSION_ARCH.snap` in the packaging/snap directory.

## Publishing to Snap Store

### One-Time Setup

1. **Register the snap name:**
   ```bash
   snapcraft register floo
   ```

2. **Login to Snapcraft:**
   ```bash
   snapcraft login
   ```

3. **Export credentials for CI/CD:**
   ```bash
   snapcraft export-login --snaps=floo --channels=stable snapcraft-token.txt
   # Add contents as SNAPCRAFT_TOKEN secret in GitHub
   ```

### Manual Publishing

```bash
cd packaging/snap

# Upload and release to stable channel
snapcraft upload floo_0.3.0_amd64.snap --release=stable

# Or upload to edge for testing first
snapcraft upload floo_0.3.0_amd64.snap --release=edge
```

### Automated Publishing

The GitHub Actions workflow `.github/workflows/publish-snap.yml` automatically:
- Builds snap for amd64 and arm64
- Publishes to Snap Store on each release (if SNAPCRAFT_TOKEN is set)

## Architecture Support

- **amd64** (x86_64) - Uses Haswell-optimized build
- **arm64** (aarch64) - Uses baseline ARM64 build

## Troubleshooting

### Permission Denied

If you get permission errors accessing config files:

```bash
# Check snap connections
snap connections floo

# Manually connect home interface if needed
sudo snap connect floo:home
```

### Service Not Starting

```bash
# Check logs
sudo snap logs floo.floos -f

# Verify config file exists and is valid
sudo ls -la /var/snap/floo/common/floos.toml
floo.floos --doctor /var/snap/floo/common/floos.toml
```

### Port Already in Use

The snap runs in a confined environment. Ensure no other services are using the same ports.

## Differences from Native Install

- Commands are prefixed: `floo.flooc` and `floo.floos` (can create aliases)
- Config files should be in home directory or `/var/snap/floo/common/`
- Confined environment (strict confinement) for security

## Learn More

- [Snapcraft Documentation](https://snapcraft.io/docs)
- [Floo Documentation](https://github.com/YUX/floo)
