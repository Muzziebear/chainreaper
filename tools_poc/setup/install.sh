#!/usr/bin/env bash
# Reproducible install of the GMX security tooling PoC stack.
# Target env: Debian 13, Python 3.12 + pipx, Node via nvm, passwordless sudo.
set -uo pipefail

echo "==> PATH + node manager"
export PATH="/usr/local/py-utils/bin:$HOME/.cargo/bin:$HOME/.foundry/bin:$HOME/.bifrost/bin:$PATH"
export NVM_DIR=/usr/local/share/nvm; source "$NVM_DIR/nvm.sh" 2>/dev/null || true

echo "==> Rust (for aderyn, heimdall, ityfuzz)"
command -v cargo >/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

echo "==> Foundry (forge/cast/anvil)"
command -v forge >/dev/null || { curl -L https://foundry.paradigm.xyz | bash; "$HOME/.foundry/bin/foundryup"; }

echo "==> Node versions (V1 needs 16, V2 needs 22)"
nvm install 16 >/dev/null 2>&1; nvm install 22 >/dev/null 2>&1

echo "==> Python tools via pipx"
pipx install slither-analyzer
pipx install solc-select
pipx install crytic-compile          # echidna/medusa need this on PATH
pipx install semgrep
pipx install eth-wake                 # 'wake'
pipx install halmos
pipx install mythril
pipx inject mythril "setuptools<81"   # py3.12 needs pkg_resources; modern setuptools removed it
pipx inject slither-analyzer slitherin
pipx install "git+https://github.com/RareSkills/vertigo-rs"   # 'vertigo'

echo "==> solc versions"
solc-select install 0.6.12; solc-select install 0.8.20

echo "==> Rust tools"
cargo install aderyn
curl -L https://get.heimdall.rs | bash && PATH="$HOME/.cargo/bin:$PATH" "$HOME/.bifrost/bin/bifrost"  # builds heimdall

echo "==> npm global tools"
npm install -g surya eth-scribble

echo "==> Binary releases (echidna, medusa, gambit) -> tools_poc/bin"
BIN="$(dirname "$0")/../bin"; mkdir -p "$BIN"; cd "$BIN"
ECH=$(curl -sS https://api.github.com/repos/crytic/echidna/releases/latest | grep -oE 'https[^"]*x86_64-linux[^"]*' | head -1)
curl -sSL "$ECH" -o e.tgz && tar xzf e.tgz && rm e.tgz && chmod +x echidna
MED=$(curl -sS https://api.github.com/repos/crytic/medusa/releases/latest | grep -oE 'https[^"]*linux[^"]*' | head -1)
curl -sSL "$MED" -o m.tgz && tar xzf m.tgz && rm m.tgz && chmod +x medusa
GAM=$(curl -sS https://api.github.com/repos/Certora/gambit/releases/latest | grep -oE 'https[^"]*linux[^"]*' | head -1)
curl -sSL "$GAM" -o gambit && chmod +x gambit

echo "==> Libraries"
POC="$(dirname "$0")/.."
git clone --depth 1 https://github.com/crytic/properties.git "$POC/properties" 2>/dev/null || true
git clone --depth 1 https://github.com/Picodes/4naly3er.git   "$POC/4naly3er"   2>/dev/null || true

echo "==> gmx-source prep"
# V1: needs env.json + node16
( cd "$POC/../gmx-source/gmx-contracts" && cp -n env.example.json env.json && nvm use 16 && npm install --no-audit --no-fund )
# V2: needs --legacy-peer-deps --ignore-scripts (else @parcel/watcher gyp build fails -> rollback)
( cd "$POC/../gmx-source/gmx-synthetics" && npm install --no-audit --no-fund --legacy-peer-deps --ignore-scripts )

echo "==> done. See ../README.md for per-tool usage."
