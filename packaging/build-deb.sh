#!/bin/bash
#
# Build .deb packages from GitHub release artifacts
# Usage: ./build-deb.sh VERSION
# Example: ./build-deb.sh 0.1.2

set -e

if [ -z "$1" ]; then
 echo "Usage: $0 VERSION"
 echo "Example: $0 0.1.2"
 exit 1
fi

VERSION=$1
RELEASE_TAG="v${VERSION}"
BASE_URL="https://github.com/YUX/floo/releases/download/${RELEASE_TAG}"

# Create build directory
BUILD_DIR="build-deb"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Building .deb packages for Floo v${VERSION}..."
echo ""

# Build for amd64 (x86_64 Haswell)
echo "=== Building amd64 package ==="
ARCH="amd64"
ARTIFACT="floo-x86_64-linux-gnu-haswell.tar.gz"
PACKAGE_DIR="floo_${VERSION}-1_${ARCH}"

mkdir -p "$PACKAGE_DIR"
cd "$PACKAGE_DIR"

# Download and extract
wget -q "${BASE_URL}/${ARTIFACT}"
tar xzf "$ARTIFACT"
mv "x86_64-linux-gnu-haswell"/* .
rm "$ARTIFACT"

# Create debian package structure
mkdir -p DEBIAN
mkdir -p usr/bin
mkdir -p usr/share/doc/floo/examples

# Move binaries
mv flooc usr/bin/
mv floos usr/bin/
chmod 755 usr/bin/flooc usr/bin/floos

# Move documentation
mv README.md usr/share/doc/floo/
mv flooc.toml.example usr/share/doc/floo/examples/
mv floos.toml.example usr/share/doc/floo/examples/

# Create control file
cat > DEBIAN/control << EOF
Package: floo
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Your Name <your.email@example.com>
Homepage: https://github.com/YUX/floo
Description: Secure, high-performance tunneling in Zig
 Floo is a high-throughput tunneling solution written in Zig with zero
 dependencies. It provides secure tunneling using Noise XX protocol with
 multiple AEAD ciphers.
 .
 Features:
 - 29.4 Gbps throughput with AEGIS-128L cipher
 - Zero runtime dependencies
 - Reverse and forward tunneling modes
 - SOCKS5 and HTTP CONNECT proxy support
 - Config changes applied on restart (SIGHUP reload temporarily disabled)
 - Built-in diagnostics (--doctor, --ping)
EOF

# Build package
cd ..
dpkg-deb --build "$PACKAGE_DIR"

echo " Built: ${PACKAGE_DIR}.deb"
echo ""

# Build for arm64 (aarch64)
echo "=== Building arm64 package ==="
ARCH="arm64"
ARTIFACT="floo-aarch64-linux-gnu.tar.gz"
PACKAGE_DIR="floo_${VERSION}-1_${ARCH}"

mkdir -p "$PACKAGE_DIR"
cd "$PACKAGE_DIR"

# Download and extract
wget -q "${BASE_URL}/${ARTIFACT}"
tar xzf "$ARTIFACT"
mv "aarch64-linux-gnu"/* .
rm "$ARTIFACT"

# Create debian package structure
mkdir -p DEBIAN
mkdir -p usr/bin
mkdir -p usr/share/doc/floo/examples

# Move binaries
mv flooc usr/bin/
mv floos usr/bin/
chmod 755 usr/bin/flooc usr/bin/floos

# Move documentation
mv README.md usr/share/doc/floo/
mv flooc.toml.example usr/share/doc/floo/examples/
mv floos.toml.example usr/share/doc/floo/examples/

# Create control file
cat > DEBIAN/control << EOF
Package: floo
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Your Name <your.email@example.com>
Homepage: https://github.com/YUX/floo
Description: Secure, high-performance tunneling in Zig
 Floo is a high-throughput tunneling solution written in Zig with zero
 dependencies. It provides secure tunneling using Noise XX protocol with
 multiple AEAD ciphers.
 .
 Features:
 - 29.4 Gbps throughput with AEGIS-128L cipher
 - Zero runtime dependencies
 - Reverse and forward tunneling modes
 - SOCKS5 and HTTP CONNECT proxy support
 - Config changes applied on restart (SIGHUP reload temporarily disabled)
 - Built-in diagnostics (--doctor, --ping)
EOF

# Build package
cd ..
dpkg-deb --build "$PACKAGE_DIR"

echo " Built: ${PACKAGE_DIR}.deb"
echo ""

cd ..

echo "=== Summary ==="
echo "Packages built in ${BUILD_DIR}/:"
ls -lh "${BUILD_DIR}"/*.deb

echo ""
echo "To install locally:"
echo " sudo dpkg -i ${BUILD_DIR}/floo_${VERSION}-1_amd64.deb"
echo ""
echo "To create APT repository, see: packaging/setup-apt-repo.sh"
