#!/usr/bin/env bash
set -e

# ---------------------------------------------------------
# build-kpm.sh – Build a single KPM from kpms/<name>/
#
# Usage:
#   ./build-kpm.sh [kpm_name] [toolchain_prefix]
#
# Examples:
#   ./build-kpm.sh pubg_driver
#   ./build-kpm.sh demo-hello
# ---------------------------------------------------------

KPM_NAME="${1:-wanbai-driver}"
KP_DIR="$(pwd)"

# Default to the downloaded bare-metal compiler path in the compiler folder if no second argument is provided
DEFAULT_COMPILER="${KP_DIR}/compiler/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-"
TARGET_COMPILE="${2:-$DEFAULT_COMPILER}"
KPM_DIR="kpms/${KPM_NAME}"

# ---------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------

if [ ! -d "$KPM_DIR" ]; then
    echo "[!] KPM directory '${KPM_DIR}' not found."
    echo "    Available KPMs:"
    ls kpms/
    exit 1
fi

if ! command -v "${TARGET_COMPILE}gcc" &>/dev/null; then
    echo "[!] Toolchain '${TARGET_COMPILE}gcc' not found in PATH."
    echo "    Install it, or pass the correct prefix as the second argument."
    exit 1
fi

# ---------------------------------------------------------
# Build
# ---------------------------------------------------------

echo "┌─────────────────────────────────────────┐"
echo "│  Building KPM: ${KPM_NAME}"
echo "│  Toolchain   : ${TARGET_COMPILE}gcc"
echo "│  KP root     : ${KP_DIR}"
echo "└─────────────────────────────────────────┘"

(
    cd "$KPM_DIR"
    TARGET_COMPILE="$TARGET_COMPILE" KP_DIR="$KP_DIR" make clean
    TARGET_COMPILE="$TARGET_COMPILE" KP_DIR="$KP_DIR" make
)

# Find the output .kpm file
KPM_FILE=$(find "$KPM_DIR" -maxdepth 1 -name "*.kpm" | head -n 1)

if [ -z "$KPM_FILE" ]; then
    echo "[!] No .kpm file produced – check build output above."
    exit 1
fi

echo ""
echo "✓ Done! Output: ${KPM_FILE}"
echo ""
echo "To load on device:"
echo "  adb push ${KPM_FILE} /data/local/tmp/"
echo "  adb push <kpatch_binary>  /data/local/tmp/"
echo "  adb shell su -c '/data/local/tmp/kpatch load /data/local/tmp/$(basename "$KPM_FILE")'"
echo "  adb shell su -c 'ls -la /dev/wanbai'"
