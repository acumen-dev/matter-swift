#!/usr/bin/env bash
# setup.sh
# Copyright 2026 Monagle Pty Ltd
#
# Build chip-cert and chip-tool from the connectedhomeip reference implementation.
# Binaries are placed in Tools/RefImpl/bin/ and cached by CI.
#
# Usage:
#   ./Tools/RefImpl/setup.sh           # build both chip-cert and chip-tool
#   ./Tools/RefImpl/setup.sh chip-cert # build chip-cert only (faster)
#   ./Tools/RefImpl/setup.sh chip-tool # build chip-tool only
#   ./Tools/RefImpl/setup.sh all-clusters-app # build the all-clusters device app only
#
# "all" builds chip-cert, chip-tool and chip-all-clusters-app.
# chip-tool, all-clusters-app (and all) additionally need node + npm (brew install node)
# on Apple Silicon without Rosetta, to build the ZAP code generator.
#
# Prerequisites (macOS):
#   brew install git-lfs python3 pkg-config
#   xcode-select --install
#
# The connectedhomeip repo is cloned to /tmp/swift-matter-refimpl/ (not inside
# this project) because pigweed/GN cannot build in paths containing spaces.
# The /tmp clone is ephemeral — only the final binaries in Tools/RefImpl/bin/
# are kept. If /tmp is cleared (e.g. reboot), the clone/build repeats
# automatically on the next run (~10–15 min).
#
# Override the build directory with:  CHIP_BUILD_DIR=/path/to/dir ./setup.sh

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
VERSION_FILE="$SCRIPT_DIR/CONNECTEDHOMEIP_VERSION"
TARGET="${1:-all}"

# ── Prerequisite checks ─────────────────────────────────────────────────────

MISSING=()

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        MISSING+=("$1")
    fi
}

check_cmd git
check_cmd git-lfs
check_cmd python3
check_cmd pkg-config
case "$TARGET" in
    chip-tool|all-clusters-app|all)
        if [ "$(uname -m)" = "arm64" ] && ! /usr/bin/arch -x86_64 /usr/bin/true &>/dev/null; then
            check_cmd node
            check_cmd npm
        fi ;;
esac

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "ERROR: Missing required tools: ${MISSING[*]}"
    echo ""
    echo "Install on macOS with:"
    echo "  brew install ${MISSING[*]}"
    echo ""
    echo "Also ensure Xcode command-line tools are installed:"
    echo "  xcode-select --install"
    exit 1
fi

# Ensure git-lfs is initialised for this user
git lfs install --skip-repo &>/dev/null || true

# Read the pinned version
VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")
echo ">>> connectedhomeip version: $VERSION"

mkdir -p "$BIN_DIR"

# ── Idempotent binary check ─────────────────────────────────────────────────

already_built() {
    case "$TARGET" in
        chip-cert) [[ -x "$BIN_DIR/chip-cert" ]] ;;
        chip-tool)  [[ -x "$BIN_DIR/chip-tool" ]] ;;
        all-clusters-app) [[ -x "$BIN_DIR/chip-all-clusters-app" ]] ;;
        all)        [[ -x "$BIN_DIR/chip-cert" && -x "$BIN_DIR/chip-tool" && -x "$BIN_DIR/chip-all-clusters-app" ]] ;;
        *)          return 1 ;;
    esac
}

if already_built; then
    echo ">>> $TARGET already built — nothing to do."
    echo "    To force rebuild: rm Tools/RefImpl/bin/* && $0 $TARGET"
    ls -lh "$BIN_DIR/"
    exit 0
fi

# ── Build directory ─────────────────────────────────────────────────────────
# pigweed/GN cannot handle paths with spaces. Use /tmp by default; override
# with CHIP_BUILD_DIR if you want persistence across reboots.

BUILD_BASE="${CHIP_BUILD_DIR:-/tmp/swift-matter-refimpl}"
REPO_DIR="$BUILD_BASE/connectedhomeip-${VERSION}"

# Sanity-check: reject paths with spaces (GN will fail cryptically otherwise)
if [[ "$REPO_DIR" == *" "* ]]; then
    echo "ERROR: Build path contains spaces: $REPO_DIR"
    echo "  Set CHIP_BUILD_DIR to a path without spaces."
    exit 1
fi

mkdir -p "$BUILD_BASE"
echo ">>> Build directory: $REPO_DIR"

# ── Clone (without recursive submodules) ────────────────────────────────────

if [ ! -d "$REPO_DIR/.git" ]; then
    echo ">>> Cloning connectedhomeip (shallow, tag $VERSION, no submodules)..."
    git clone \
        --depth 1 \
        --branch "$VERSION" \
        https://github.com/project-chip/connectedhomeip.git \
        "$REPO_DIR"
else
    echo ">>> connectedhomeip already cloned"
fi

cd "$REPO_DIR"

# ── Initialise only the submodules needed for chip-cert / chip-tool ─────────
# Platform vendor SDKs (silabs, nxp, ti, etc.) are multi-GB with git-lfs
# blobs — we skip them entirely.

REQUIRED_SUBMODULES=(
    third_party/pigweed/repo
    third_party/boringssl/repo
    third_party/nlassert/repo
    third_party/nlio/repo
    third_party/nlunit-test/repo
    third_party/jsoncpp/repo
    third_party/mbedtls/repo
    third_party/editline/repo
    third_party/nlfaultinjection/repo
    third_party/openthread/repo
    third_party/libwebsockets/repo
    third_party/nanopb/repo
    third_party/perfetto/repo
)

submodule_ready() {
    local sub="$1"
    # A submodule is ready if it has a .git reference AND contains files.
    # A partially-cloned submodule may have .git but be otherwise empty.
    if { [ -d "$sub/.git" ] || [ -f "$sub/.git" ]; } && [ "$(ls -A "$sub" 2>/dev/null | head -2 | wc -l)" -gt 1 ]; then
        return 0
    fi
    return 1
}

echo ">>> Initialising required submodules..."
for sub in "${REQUIRED_SUBMODULES[@]}"; do
    if submodule_ready "$sub"; then
        echo "    $sub  ✓"
        continue
    fi
    echo "    $sub  (cloning...)"
    git submodule update --init --depth 1 -- "$sub" 2>&1 || {
        echo "    WARNING: $sub not available at $VERSION (skipped)"
    }
done

# Verify the critical pigweed submodule is present
if [ ! -f "third_party/pigweed/repo/pw_env_setup/util.sh" ]; then
    echo ""
    echo "ERROR: pigweed submodule not initialised correctly."
    echo "  Expected: $REPO_DIR/third_party/pigweed/repo/pw_env_setup/util.sh"
    echo ""
    echo "Try removing and re-cloning:"
    echo "  rm -rf $REPO_DIR"
    echo "  $0 $TARGET"
    exit 1
fi

# ── Bootstrap / activate the pigweed build environment ──────────────────────
# - First run: bootstraps into .environment/ (~5–10 min, downloads tools)
# - Subsequent runs: re-activates the cached environment (seconds)

export PW_ENVIRONMENT_ROOT="${PW_ENVIRONMENT_ROOT:-$REPO_DIR/.environment}"

# The default environment.json pulls the ZAP code generator from a CIPD path
# that needs a Google login (fails non-interactively). Use the CIPD-free config;
# ZAP itself (needed by chip-tool and all-clusters-app) comes from ensure_zap_cli below.
export PW_CONFIG_FILE="${PW_CONFIG_FILE:-scripts/setup/environment_no_cipd.json}"

if [ ! -f "$PW_ENVIRONMENT_ROOT/activate.sh" ] || [ ! -s "$PW_ENVIRONMENT_ROOT/activate.sh" ]; then
    echo ""
    echo ">>> First-time setup: bootstrapping pigweed toolchain..."
    echo "    This downloads GN, protobuf, and Python packages into:"
    echo "    $PW_ENVIRONMENT_ROOT"
    echo "    Estimated time: 5–10 minutes (cached on subsequent runs)"
    echo ""
fi

# activate.sh uses unbound variables and non-zero exits internally.
# Relax strict mode so it can run, then re-enable.
set +eu
source scripts/activate.sh
_activate_rc=$?
set -eu

if [ "$_activate_rc" -ne 0 ]; then
    echo ""
    echo "ERROR: pigweed environment activation failed (exit $_activate_rc)"
    echo ""
    echo "Common fixes:"
    echo "  1. Delete and re-bootstrap:  rm -rf '$PW_ENVIRONMENT_ROOT' && $0 $TARGET"
    echo "  2. Full clean rebuild:       rm -rf '$REPO_DIR' && $0 $TARGET"
    echo "  3. Check Python 3:           python3 --version"
    echo "  4. Xcode CLT:                xcode-select --install"
    exit 1
fi

# Verify GN is available
if ! command -v gn &>/dev/null; then
    echo ""
    echo "ERROR: 'gn' not found on PATH after pigweed activation."
    echo "  Try a clean bootstrap:  rm -rf '$PW_ENVIRONMENT_ROOT' && $0 $TARGET"
    exit 1
fi

# ── Build requested targets ───────────────────────────────────────────────────
# Use minimal GN args. The Darwin platform default includes BLE/Wi-Fi support
# which we don't need, but disabling them causes compile errors due to
# unguarded references in connectedhomeip v1.4. Let it compile — chip-cert
# and chip-tool don't call BLE code at runtime.

GN_OUT="out/darwin"
# treat_warnings_as_errors=false: the pinned tag trips -Wdeprecated-literal-operator
# (Span.h `operator"" _span`) under current Apple clang.
GN_ARGS='chip_build_tests=false treat_warnings_as_errors=false'

ensure_gn_out() {
    echo ">>> Configuring build..."
    gn gen "$GN_OUT" --args="$GN_ARGS"
}

# chip-tool and the example need `zap-cli` (code generator) at build time. The pigweed CIPD
# copy needs a Google login, and the public GitHub release is x86_64-only even
# for "mac-arm64" (needs Rosetta). On Apple Silicon we therefore build ZAP from
# source (node + tsc; the Electron/SPA UI is not needed) and wrap it as zap-cli.
ensure_zap_cli() {
    command -v zap-cli &>/dev/null && return 0
    local zap_ver zap_dir
    zap_ver=$(tr -d '[:space:]' < scripts/setup/zap.version)
    zap_dir="$BUILD_BASE/zap-$zap_ver"
    if [ ! -x "$zap_dir/zap-cli" ]; then
        if [ "$(uname -m)" = "arm64" ] && ! /usr/bin/arch -x86_64 /usr/bin/true &>/dev/null; then
            command -v node &>/dev/null || { echo "ERROR: node is required to build zap (brew install node)"; exit 1; }
            echo ">>> Building zap-cli $zap_ver from source (no Rosetta)..."
            rm -rf "$zap_dir"; mkdir -p "$zap_dir"
            git clone --depth 1 --branch "$zap_ver" https://github.com/project-chip/zap.git "$zap_dir/src"
            ( cd "$zap_dir/src" \
              && npm install --omit=optional --legacy-peer-deps --no-audit --no-fund \
              && npx tsc --build ./tsconfig.json \
              && npx copyfiles './src-electron/**/*.sql' './src-electron/icons/*' ./dist/ )
            # Wrapper: connectedhomeip parses a `Version: x.y.z` line from --version.
            cat > "$zap_dir/zap-cli" <<WRAP
#!/usr/bin/env bash
if [ "\$1" = "--version" ]; then echo "Version: ${zap_ver#v}" | sed 's/-nightly//;s/\.0\([0-9]\)/.\1/g'; exit 0; fi
exec node --unhandled-rejections=strict "$zap_dir/src/dist/src-electron/main-process/main.js" "\$@"
WRAP
            chmod +x "$zap_dir/zap-cli"
        else
            echo ">>> Fetching zap-cli $zap_ver (mac-x64)..."
            rm -rf "$zap_dir"; mkdir -p "$zap_dir"
            curl -fL -o "$zap_dir/zap.zip" \
                "https://github.com/project-chip/zap/releases/download/$zap_ver/zap-mac-x64.zip"
            unzip -q "$zap_dir/zap.zip" -d "$zap_dir"
        fi
    fi
    export ZAP_INSTALL_PATH="$zap_dir"
}

build_chip_cert() {
    ensure_gn_out
    echo ">>> Building chip-cert..."
    ninja -C "$GN_OUT" chip-cert
    cp "$GN_OUT/chip-cert" "$BIN_DIR/chip-cert"
    echo ">>> chip-cert → $BIN_DIR/chip-cert"
}

build_chip_tool() {
    ensure_zap_cli
    ensure_gn_out
    echo ">>> Building chip-tool..."
    ninja -C "$GN_OUT" chip-tool
    cp "$GN_OUT/chip-tool" "$BIN_DIR/chip-tool"
    echo ">>> chip-tool → $BIN_DIR/chip-tool"
}

# The all-clusters example acts as a Matter device on localhost. It uses its
# own GN root (the Linux example builds the POSIX platform layer on Darwin).
build_all_clusters_app() {
    ensure_zap_cli
    local out="out/all-clusters-app"
    # treat_warnings_as_errors=false: the pinned tag trips -Wdeprecated-literal-operator
    # (Span.h `operator"" _span`) under current Apple clang.
    gn gen "$out" --root=examples/all-clusters-app/linux \
        --args='chip_build_tests=false treat_warnings_as_errors=false'
    echo ">>> Building chip-all-clusters-app..."
    ninja -C "$out" chip-all-clusters-app
    cp "$out/chip-all-clusters-app" "$BIN_DIR/"
    echo ">>> chip-all-clusters-app → $BIN_DIR/chip-all-clusters-app"
}

case "$TARGET" in
    chip-cert) build_chip_cert ;;
    chip-tool)  build_chip_tool  ;;
    all-clusters-app) build_all_clusters_app ;;
    all)
        build_chip_cert
        build_chip_tool
        build_all_clusters_app
        ;;
    *)
        echo "Unknown target: $TARGET. Use chip-cert, chip-tool, all-clusters-app, or all."
        exit 1
        ;;
esac

echo ""
echo ">>> Done. Binaries:"
ls -lh "$BIN_DIR/"
