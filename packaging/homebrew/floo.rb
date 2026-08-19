class Floo < Formula
  desc "Secure, high-performance tunneling in Zig. Expose your home services or access remote ones"
  homepage "https://github.com/YUX/floo"
  version "0.3.0"
  license "Apache-2.0"

  if Hardware::CPU.arm?
    url "https://github.com/YUX/floo/releases/download/v0.3.0/floo-aarch64-macos-m1.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  else
    url "https://github.com/YUX/floo/releases/download/v0.3.0/floo-x86_64-macos-haswell.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install "flooc"
    bin.install "floos"
    doc.install "README.md"
    if File.exist?("LICENSE")
      doc.install "LICENSE"
    end
    if Dir.exist?("configs")
      (pkgshare/"examples").install Dir["configs/*.toml"]
    end
  end

  def caveats
    <<~EOS
      Example configuration files are installed to:
        #{pkgshare}/examples/

      To get started:
        1. Copy example configs: cp #{pkgshare}/examples/*.toml .
        2. Edit configs with your settings
        3. Run: flooc flooc.toml (client) or floos floos.toml (server)

      See https://github.com/YUX/floo for complete documentation.
    EOS
  end

  test do
    system "#{bin}/flooc", "--version"
    system "#{bin}/floos", "--version"
  end
end
