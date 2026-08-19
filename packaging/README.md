# Floo Package Manager Configurations

This directory contains package manager configurations for distributing Floo.

## Homebrew (macOS)

### Option 1: Homebrew Tap (Recommended for ongoing releases)

1. **Create a tap repository** (one-time setup):
   ```bash
   # Create a new GitHub repo named "homebrew-floo"
   # Repository URL will be: https://github.com/YUX/homebrew-floo
   ```

2. **Populate the tap**:
   ```bash
   git clone https://github.com/YUX/homebrew-floo
   cd homebrew-floo
   mkdir -p Formula
   cp packaging/homebrew/floo.rb Formula/
   git add Formula/floo.rb
   git commit -m "Add Floo formula"
   git push
   ```

3. **Update SHA256 checksums** after each release:
   ```bash
   # Download release artifacts
   wget https://github.com/YUX/floo/releases/download/v0.3.0/floo-aarch64-macos-m1.tar.gz
   wget https://github.com/YUX/floo/releases/download/v0.3.0/floo-x86_64-macos-haswell.tar.gz

   # Calculate checksums
   shasum -a 256 floo-aarch64-macos-m1.tar.gz
   shasum -a 256 floo-x86_64-macos-haswell.tar.gz

   # Update Formula/floo.rb with the checksums
   ```

4. **Users install with**:
   ```bash
   brew tap YUX/floo
   brew install floo
   ```

### Option 2: Homebrew Core (More exposure, stricter requirements)

Submit a PR to [homebrew-core](https://github.com/Homebrew/homebrew-core):
- Requires notable project (1000+ stars or significant usage)
- Must meet [formula requirements](https://docs.brew.sh/Acceptable-Formulae)
- See [Contributing Guide](https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request)

## AUR (Arch Linux)

### Publishing to AUR

1. **Set up AUR account** (one-time):
   - Create account at https://aur.archlinux.org/register
   - Add SSH key to your AUR account
   - Configure git: `git config --global user.name "Your Name"`

2. **Clone the AUR package repository**:
   ```bash
   git clone ssh://aur@aur.archlinux.org/floo.git floo-aur
   cd floo-aur
   ```

3. **Update package files** for each release:
   ```bash
   # Copy PKGBUILD
   cp packaging/aur/PKGBUILD .

   # Download release artifacts to calculate checksums
   wget https://github.com/YUX/floo/releases/download/v0.3.0/floo-x86_64-linux-gnu-haswell.tar.gz
   wget https://github.com/YUX/floo/releases/download/v0.3.0/floo-aarch64-linux-gnu.tar.gz

   # Calculate checksums
   sha256sum floo-x86_64-linux-gnu-haswell.tar.gz
   sha256sum floo-aarch64-linux-gnu.tar.gz

   # Update PKGBUILD with checksums and version

   # Generate .SRCINFO
   makepkg --printsrcinfo > .SRCINFO

   # Commit and push
   git add PKGBUILD .SRCINFO
   git commit -m "Update to version 0.3.0"
   git push
   ```

4. **Users install with**:
   ```bash
   yay -S floo
   # or
   paru -S floo
   ```

### Testing AUR Package Locally

```bash
cd packaging/aur
makepkg -si  # Build and install locally
```

## Other Package Managers

### Nix/NixOS

Create a derivation in `nixpkgs`:
- Fork [nixpkgs](https://github.com/NixOS/nixpkgs)
- Add derivation to `pkgs/by-name/fl/floo/package.nix`
- Submit PR

### APT (Debian/Ubuntu)

#### Option 1: Automated Publishing (Recommended)

Use the included scripts and GitHub Actions to automatically build and publish .deb packages.

**One-time setup:**

1. **Create APT repository** (GitHub Pages):
   ```bash
   # Create a new GitHub repo named "floo-apt"
   # Enable GitHub Pages (Settings → Pages → Branch: main)
   ```

2. **Add repository secret**:
   - Go to your main repo Settings → Secrets → Actions
   - Add `APT_REPO_TOKEN` with a personal access token (repo write permissions)

3. **Configure workflow**:
   - Edit `.github/workflows/publish-apt.yml`
   - Update repository name if needed (line 63)

**For each release:**

The workflow automatically runs when you create a GitHub release. You can also trigger manually:
```bash
# Via GitHub Actions UI or CLI
gh workflow run publish-apt.yml -f version=0.3.0
```

**Users install with:**
```bash
curl -fsSL https://yux.github.io/floo-apt/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/floo.gpg
echo 'deb [signed-by=/usr/share/keyrings/floo.gpg] https://yux.github.io/floo-apt stable main' | sudo tee /etc/apt/sources.list.d/floo.list
sudo apt update
sudo apt install floo
```

#### Option 2: Manual Publishing

**Build .deb packages:**
```bash
cd packaging
./build-deb.sh 0.3.0
```

This creates:
- `build-deb/floo_0.3.0-1_amd64.deb`
- `build-deb/floo_0.3.0-1_arm64.deb`

**Test locally:**
```bash
sudo dpkg -i build-deb/floo_0.3.0-1_amd64.deb
flooc --version
```

**Create APT repository:**
```bash
./setup-apt-repo.sh apt-repo 0.3.0
```

This generates a complete APT repository structure in `apt-repo/`.

**Host the repository:**
- Upload to GitHub Pages
- Use services like [Cloudsmith](https://cloudsmith.io/) or [PackageCloud](https://packagecloud.io/) (free for open source)
- Host on your own server

#### Option 3: Submit to Debian/Ubuntu (Long-term)

For official Debian/Ubuntu inclusion:
- Requires Debian Developer or finding a sponsor
- Package must meet [Debian Policy](https://www.debian.org/doc/debian-policy/)
- See [Debian Maintainer Guide](https://www.debian.org/doc/manuals/maint-guide/)

#### GPG Signing (Optional but Recommended)

To sign your APT repository:

1. **Generate GPG key:**
   ```bash
   gpg --full-generate-key
   # Follow prompts, use your email
   ```

2. **Export private key for GitHub Actions:**
   ```bash
   gpg --armor --export-secret-keys YOUR_KEY_ID > private-key.asc
   # Add contents as GPG_PRIVATE_KEY secret in GitHub
   ```

3. **Manual signing:**
   ```bash
   cd apt-repo/dists/stable
   gpg --default-key YOUR_KEY_ID -abs -o Release.gpg Release
   gpg --default-key YOUR_KEY_ID --clearsign -o InRelease Release
   gpg --armor --export YOUR_KEY_ID > ../../pubkey.gpg
   ```

### Snap (Universal Linux)

#### Option 1: Automated Publishing (Recommended)

Use GitHub Actions to automatically build and publish Snap packages.

**One-time setup:**

1. **Register snap name:**
   ```bash
   snapcraft login
   snapcraft register floo
   ```

2. **Export credentials:**
   ```bash
   snapcraft export-login --snaps=floo --channels=stable snapcraft-token.txt
   # Add contents as SNAPCRAFT_TOKEN secret in GitHub repo
   ```

3. **Configure workflow:**
   - The workflow `.github/workflows/publish-snap.yml` is already configured
   - It runs automatically on each release

**For each release:**

Workflow automatically builds and publishes when you create a GitHub release.

**Users install with:**
```bash
sudo snap install floo
```

#### Option 2: Manual Building and Publishing

**Build locally:**
```bash
cd packaging
./build-snap.sh 0.3.0
```

**Test locally:**
```bash
sudo snap install ../snap/floo_0.3.0_amd64.snap --dangerous
floo.flooc --version
floo.floos --version
```

**Publish manually:**
```bash
cd snap
snapcraft login
snapcraft upload floo_0.3.0_amd64.snap --release=stable
```

#### Architecture Support

- **amd64** - Uses Haswell-optimized x86_64 build
- **arm64** - Uses baseline aarch64 build

#### Snap Features

- Strict confinement for security
- Both `flooc` and `floos` included
- Commands: `floo.flooc` and `floo.floos`
- Service mode for `floos` (can run as daemon)
- Example configs in `/snap/floo/current/share/doc/floo/examples/`

See [snap/README.md](snap/README.md) for detailed usage instructions.

### RPM (Fedora/RHEL)

Create `.spec` file for RPM packaging:
- Use `rpmbuild` to create RPM packages
- Consider COPR for hosting

## Release Checklist

When releasing a new version:

- [ ] Update version in `build.zig.zon`
- [ ] Create git tag: `git tag v0.3.0 && git push --tags`
- [ ] Wait for GitHub Actions to build release artifacts
- [ ] Calculate SHA256 checksums: `./packaging/calculate-checksums.sh v0.3.0`
- [ ] Update Homebrew formula with new version and checksums
- [ ] Update AUR PKGBUILD with new version and checksums
- [ ] Push to homebrew-floo tap
- [ ] Push to AUR repository
- [ ] APT packages build and publish automatically via GitHub Actions
- [ ] Snap packages build and publish automatically via GitHub Actions
- [ ] Update README.md installation instructions if needed

## Calculating Checksums

Use the included helper script:

```bash
./packaging/calculate-checksums.sh v0.3.0
```

Or manually:

```bash
# macOS
shasum -a 256 floo-*.tar.gz

# Linux
sha256sum floo-*.tar.gz
```
