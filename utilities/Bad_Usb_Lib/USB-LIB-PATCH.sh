#!/usr/bin/env bash

echo "[*] BadUSB ESP32 Core Patcher (NO BACKUP)"
echo "-------------------------------------------------------"

# ------------------------------------------------------------------
# PATHS (SCRIPT IS INSIDE Bad_Usb_Lib)
# ------------------------------------------------------------------

BADUSB_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Arduino packages path (Linux + macOS)
if [ -d "$HOME/.arduino15/packages" ]; then
    ARDUINO_PKGS="$HOME/.arduino15/packages"
elif [ -d "$HOME/Library/Arduino15/packages" ]; then
    ARDUINO_PKGS="$HOME/Library/Arduino15/packages"
else
    echo "[ERROR] Arduino packages folder not found"
    exit 1
fi

# ------------------------------------------------------------------
# SANITY CHECKS
# ------------------------------------------------------------------

# Collect payload files (exclude scripts)
mapfile -t PAYLOAD_FILES < <(
    find "$BADUSB_ROOT" -type f \
        ! -name "*.sh" \
        ! -name "*.ps1"
)

if [ "${#PAYLOAD_FILES[@]}" -eq 0 ]; then
    echo "[ERROR] No payload files found in Bad_Usb_Lib"
    exit 1
fi

# ------------------------------------------------------------------
# ENUMERATE ALL ESP32 CORES (ALL VENDORS / ALL VERSIONS)
# ------------------------------------------------------------------

CORES=()

while IFS= read -r core; do
    CORES+=("$core")
done < <(
    find "$ARDUINO_PKGS" -type d -path "*/hardware/esp32/*/cores/esp32"
)

if [ "${#CORES[@]}" -eq 0 ]; then
    echo "[ERROR] No ESP32 cores found"
    exit 1
fi

# ------------------------------------------------------------------
# PATCH PROCESS
# ------------------------------------------------------------------

for CORE in "${CORES[@]}"; do

    VENDOR="$(basename "$(dirname "$(dirname "$(dirname "$CORE")")")")"
    VERSION="$(basename "$(dirname "$(dirname "$CORE")")")"

    echo
    echo "[*] Vendor: $VENDOR | Version: $VERSION"

    for SRC in "${PAYLOAD_FILES[@]}"; do

        RELATIVE="${SRC#$BADUSB_ROOT/}"
        TARGET="$CORE/$RELATIVE"
        TARGET_DIR="$(dirname "$TARGET")"

        if [ ! -d "$TARGET_DIR" ]; then
            mkdir -p "$TARGET_DIR"
            echo "    [INFO] Created dir: $RELATIVE"
        fi

        if [ -f "$TARGET" ]; then
            SRC_HASH="$(shasum -a 256 "$SRC" | awk '{print $1}')"
            DST_HASH="$(shasum -a 256 "$TARGET" | awk '{print $1}')"

            if [ "$SRC_HASH" = "$DST_HASH" ]; then
                echo "    [OK] Already identical: $RELATIVE"
                continue
            fi
        fi

        cp -f "$SRC" "$TARGET"
        echo "    [PATCH] Overwritten: $RELATIVE"
    done

    echo "    [DONE] Core patched"
done

echo
echo "[DONE] All ESP32 cores patched"
echo "[INFO] Restart Arduino IDE before compiling"
