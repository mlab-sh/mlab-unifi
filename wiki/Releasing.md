# Releasing

One workflow builds mlab-unifi for macOS and Linux and puts everything on the
GitHub release: a tarball per target, a `.deb` and an `.rpm` for Linux, a
checksum file, and a Homebrew formula in this repository pointing at those
assets. It is
[`.github/workflows/release.yml`](https://github.com/mlab-sh/mlab-unifi/blob/main/.github/workflows/release.yml),
and it only runs when someone asks it to.

There is no package repository to host, nothing to sign, and no bucket
credentials anywhere in the pipeline. The release page is the only place
artifacts live.

## Cutting a release

1. Bump `version` in `Cargo.toml`, run `cargo build` so `Cargo.lock` follows,
   commit.
2. Run the **Release** workflow from the Actions tab.

The version is read from `Cargo.toml`, never typed anywhere else, so the tag,
the archive names, the packages and the formula cannot disagree with the binary
they contain.

## What it builds

| Target | Runner | Ships as |
| --- | --- | --- |
| `x86_64-apple-darwin` | macos-latest | tarball, Homebrew |
| `aarch64-apple-darwin` | macos-latest | tarball, Homebrew |
| `x86_64-unknown-linux-gnu` | ubuntu-22.04 | tarball, Homebrew, `.deb`, `.rpm` |
| `aarch64-unknown-linux-gnu` | ubuntu-22.04 | tarball, Homebrew, `.deb`, `.rpm` |

The Linux runner is pinned to 22.04 rather than latest on purpose. A glibc
binary never runs against a glibc older than the one it was linked with, so
building on 24.04 (glibc 2.39) would produce packages that refuse to start on
Debian 12 and Ubuntu 22.04. Pinning lowers the floor to glibc 2.35.

The ARM64 Linux build is a cross build, which needs more than a linker: rustls
compiles C through ring, so the job installs `gcc-aarch64-linux-gnu` and points
`CC`, `AR` and the linker at it.

A test gate runs first: `cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test --locked`. Nothing is built for release if any of the three fails.

## The Linux packages

`cargo deb` and `cargo generate-rpm` both read their metadata from
`Cargo.toml`, so the two package descriptions live next to the version they
describe.

Two details are load-bearing:

- **`--no-strip` on the `.deb`.** The release profile already strips the
  binary; letting cargo-deb strip it again would run the host `strip` against
  the aarch64 binary and fail the cross build.
- **The rpm binary is staged at `pkg/` first.** cargo-deb rewrites
  `target/release` to `target/<triple>/release` when it is given a target;
  cargo-generate-rpm takes its asset paths literally, so pointing them at
  `target/release` would silently package the host build, which on a cross run
  is the wrong architecture entirely.

The rpm payload is gzip rather than the zstd default, so rpm 4.14 (RHEL 8 and
its rebuilds) can still read it.

## Checksums

Nothing signs these assets, so the release carries a `SHA256SUMS` file covering
every file in it. That is what a manual download can be checked against:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

The Homebrew formula carries the four tarball checksums itself, so `brew
install` verifies them without anyone thinking about it.

## What the job commits back

`Formula/mlab-unifi.rb`, with the four fresh checksums. It is generated, so it
should not be edited by hand.
