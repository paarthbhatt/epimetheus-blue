# Releases and assets

Epimetheus Blue publishes tagged **experimental prereleases** on GitHub with a
fixed set of assets. This page documents what each asset contains, how it is
produced, how to verify it, and the maintainer procedure used to freeze and
publish a release. Per-release notes live in `docs/RELEASE-vX.Y.Z.md` and are
mirrored in the GitHub release body.

## Release model

- Releases use annotated `vX.Y.Z` tags; the tag points at the exact release
  commit and is the source of truth for the source archive.
- Releases stay **prerelease** until the project explicitly declares them
  stable. They are not Microsoft Defender-equivalent or independently audited
  security software; read [LIMITATIONS.md](LIMITATIONS.md) before relying on
  them.
- **Published assets are immutable.** Never replace a file after publishing:
  downstream `PKGBUILD` checksums reference them.
- Every release carries `BUILD_INFO.txt` (exact commit, toolchain, archive
  hashes, validation results) and `SHA256SUMS` (checksums of every other
  asset). Neither is a signature.
- Installation never enables services, firewall policy, system DNS or cleanup.
  Activation is always a separate, confirmed action.

## Asset inventory (v0.6.0)

| Asset | Contents | Produced by |
|---|---|---|
| `epimetheus-blue-0.6.0-source.tar.gz` | Frozen source tree at the tag, `epimetheus-blue-0.6.0/` prefix. Excludes `packaging/PKGBUILD` and `packaging/.SRCINFO` so the checksum cannot reference itself. | `git ls-tree` file list + `tar` |
| `epimetheus-blue-0.6.0-linux-x86_64.tar.gz` | Tested `blue` and `blue-firewall-helper` executables plus root docs, `docs/`, `scripts/`, `packaging/` and the browser companion. No Rust toolchain or sudo needed to install. | `cargo build --release --locked --workspace` + `tar` |
| `epimetheus-blue-0.6.0-1-x86_64.pkg.tar.zst` | Arch binary package. **Unsigned.** | `makepkg` from the frozen source archive |
| `epimetheus-blue-0.6.0-1.src.tar.gz` | Arch source package (`PKGBUILD` + frozen source). | `makepkg --source` |
| `epimetheus-blue-0.6.0.SRCINFO` | Package metadata generated from `PKGBUILD`. | `makepkg --printsrcinfo` |
| `PKGBUILD` | Build recipe containing the frozen source checksum. | Repository `packaging/PKGBUILD` |
| `epimetheus-blue-search-guard-0.5.0.zip` | Browser companion; load unpacked in Chromium/Brave. Version tracks `browser-extension/manifest.json`. | `zip` of extension sources + bundled fonts |
| `BUILD_INFO.txt` | Source/native/package hashes, toolchain, validation record. | Written after validation |
| `SHA256SUMS` | Checksums of all other assets. | `sha256sum` |

## Verifying a download

```bash
sha256sum -c SHA256SUMS
```

Checksums detect corruption or a mismatched file. They are **not** signatures,
an audit, or proof of reproducible builds; the project does not yet sign
releases. Compare the checksum against the value quoted in `BUILD_INFO.txt`
and this repository before installing. See [INSTALL.md](INSTALL.md) for the
install paths and [USAGE.md](USAGE.md) for first-run guidance.

## Freeze and publish procedure (maintainer)

Run from a clean checkout of the release commit. All builds run as the desktop
user; no privileged host changes are part of publishing.

1. **Bump versions**: workspace `Cargo.toml`, `Cargo.lock` (via a cargo run),
   `packaging/PKGBUILD` `pkgver`, `browser-extension/manifest.json`, and the
   version references in `README.md`, `docs/INSTALL.md`, `docs/USAGE.md`,
   `docs/LIMITATIONS.md` and the issue template.
2. **Write `docs/RELEASE-vX.Y.Z.md`** from the previous release notes, with an
   honest validation table. Only record checks that actually ran.
3. **Validate**: workspace tests, `clippy -D warnings`, `fmt --check`,
   `scripts/check-invariants.sh`, extension validator and popup tests,
   `scripts/test-install-local.py`, shell/desktop/systemd checks, gitleaks, and
   the harmless EICAR drill in a temporary state directory.
4. **Freeze the source archive**: build the file list from the staged tree
   (`git write-tree` + `git ls-tree`), drop `packaging/PKGBUILD` and
   `packaging/.SRCINFO`, and `tar` with the `epimetheus-blue-X.Y.Z/` prefix.
   Record its SHA-256.
5. **Patch the recipe**: put the source hash in `packaging/PKGBUILD`, then
   regenerate `packaging/.SRCINFO` with `makepkg --printsrcinfo`. Commit the
   release and create the annotated tag.
6. **Build the remaining assets**: native archive (thin-LTO, stripped binaries,
   no `BLUE_EXTENSION_DIR` override), extension zip, `makepkg` from the frozen
   source, `makepkg --source`, and a renamed `.SRCINFO` copy.
7. **Record provenance**: write `BUILD_INFO.txt` (commit, toolchain, hashes,
   validation, and anything that could not be run), then generate
   `SHA256SUMS` over all other assets.
8. **Publish**: `gh release create vX.Y.Z --prerelease` with the release notes
   as the body and all nine assets attached. Re-check the published hashes.

If any source file changes after step 4, restart at step 4: the frozen archive,
`PKGBUILD` checksum and every downstream artifact must be rebuilt from the
final tree.

## Release notes index

| Version | Notes |
|---|---|
| v0.6.0 | [RELEASE-v0.6.0.md](RELEASE-v0.6.0.md) |
| v0.5.0 | [RELEASE-v0.5.0.md](RELEASE-v0.5.0.md) |
