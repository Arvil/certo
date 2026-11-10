#!/usr/bin/env bash
# Install the pinned cargo dev tools used by certo, locally and in CI.
#
#   .devcontainer/install-tools.sh                    # install all tools
#   .devcontainer/install-tools.sh cargo-audit        # install only the named ones
#
# Single source of truth for tool versions: bump them here.
set -euo pipefail

declare -A VERSIONS=(
  [cargo-audit]=0.22.2
  [cargo-cyclonedx]=0.5.10
  [cargo-auditable]=0.7.7
)

tools=("$@")
if [ "${#tools[@]}" -eq 0 ]; then
  tools=("${!VERSIONS[@]}")
fi

for tool in "${tools[@]}"; do
  version="${VERSIONS[$tool]:?unknown tool: $tool}"
  cargo install --locked "$tool@$version"
done
