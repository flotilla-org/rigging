#!/usr/bin/env bash
# Build the exact connect-only client/server used by the dedicated SSH proof.
set -euo pipefail
source_dir=$(realpath "$1")
output_dir=$(realpath -m "$2")
cleat_revision=00c072b207dc943f6c93fe3b6b09abaa257695a6

cd "$source_dir"
test "$(git rev-parse HEAD)" = "$cleat_revision"
test -z "$(git status --porcelain)"
# Rust, Zig and Ghostty are pinned by this source revision. Cleat's preparation
# script verifies the Zig archive checksum and checks out the exact Ghostty SHA.
rust_version=$(awk '
  $0 == "[toolchain]" { in_section = 1; next }
  in_section && /^\[/ { exit }
  in_section && $1 == "channel" && $2 == "=" { gsub(/"/, "", $3); print $3; found = 1; exit }
  END { if (!found) exit 1 }
' rust-toolchain.toml)
rustup toolchain install "$rust_version" --profile minimal
# Ghostty's Linux build otherwise targets the build machine's CPU, so a cached
# binary can die with SIGILL on an older runner. These flags are build-only.
for flag in -Demit-xcframework=false -Dcpu=baseline; do
  grep -Fq -- "$flag" tools/ghostty-toolchain.toml ||
    sed -i "s/^build_step = \(.*\)-Demit-lib-vt=true /build_step = \1-Demit-lib-vt=true $flag /" tools/ghostty-toolchain.toml
  grep -Fq -- "$flag" tools/ghostty-toolchain.toml
done
./tools/prepare-ghostty-vt.sh
test -f .tools/ghostty-install/lib/libghostty-vt.a
find .tools/ghostty-install/lib -maxdepth 1 \( -name 'libghostty-vt.so' -o -name 'libghostty-vt.dylib' \) -delete
# Restore the pinned manifest before Cargo records source provenance; the
# static library is ready.
git restore tools/ghostty-toolchain.toml
cargo +"$rust_version" build -p cleat --release --locked --features ghostty-vt
mkdir -p "$output_dir"
install -m 0755 target/release/cleat "$output_dir/cleat"
if ldd "$output_dir/cleat" | grep -q ghostty-vt; then
  echo 'cleat proof requires a self-contained Ghostty VT build' >&2
  exit 1
fi
{
  printf 'cleat_repository=https://github.com/flotilla-org/cleat\ncleat_revision=%s\n' "$cleat_revision"
  printf 'ghostty_revision=%s\n' "$(git -C .tools/ghostty-src rev-parse HEAD)"
  printf 'ghostty_build_extra=-Demit-xcframework=false\n'
  cat tools/ghostty-toolchain.toml
  rustc +"$rust_version" --version --verbose
  cargo +"$rust_version" --version
  "$output_dir/cleat" version
  sha256sum "$output_dir/cleat"
  ssh -V 2>&1
  "${TENDER_TEST_SSHD:-/usr/sbin/sshd}" -V 2>&1
  # Distribution package versions supplement the actual binaries above.
  dpkg-query -W openssh-client openssh-server || true
} | tee "$output_dir/provenance.txt"
