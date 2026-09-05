class MlabUnifi < Formula
  desc "CLI over the UniFi APIs, for passive network security work"
  homepage "https://github.com/mlab-sh/mlab-unifi"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-unifi/releases/download/v#{version}/mlab-unifi-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0807df58d6f6783361f0dcc2a1d2d990535bb28265760cda11d0ed5fe4b3f25c"
    else
      url "https://github.com/mlab-sh/mlab-unifi/releases/download/v#{version}/mlab-unifi-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "c5224ae54ecf758495bbe0408d2b90e488f12b62afc937e964f1414b36c1f1fb"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-unifi/releases/download/v#{version}/mlab-unifi-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7eee4b1f9cdd545c388f534a5b9cb0ef3fb1d572936b666194e54e7f5789a93c"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-unifi/releases/download/v#{version}/mlab-unifi-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8e73943a8d3551cd2422c1dd74309fea12fcfa1e6db1a2694dbccdac6c168e92"
    end
  end

  def install
    bin.install "mlab-unifi"
  end

  test do
    assert_match "mlab-unifi", shell_output("#{bin}/mlab-unifi --version")
  end
end
