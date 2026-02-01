#!/usr/bin/env bash
set -e

echo "[*] Universal ESP32 Arduino Core patcher (Linux / macOS)"
echo "-------------------------------------------------------"

# ---------------------------------------------------------
# OS detection
# ---------------------------------------------------------
OS="$(uname -s)"

case "$OS" in
  Linux)
    OS_NAME="Linux"
    ;;
  Darwin)
    OS_NAME="macOS"
    ;;
  *)
    echo "[ERROR] Unsupported OS: $OS"
    exit 1
    ;;
esac

echo "[*] Detected OS: $OS_NAME"

# ---------------------------------------------------------
# Arduino packages path detection
# ---------------------------------------------------------
PKG_ROOT=""

# Arduino IDE 2.x (Linux + macOS modern)
if [ -d "$HOME/.arduino15/packages" ]; then
  PKG_ROOT="$HOME/.arduino15/packages"
fi

# Arduino IDE 1.x legacy macOS fallback
if [ -z "$PKG_ROOT" ] && [ "$OS_NAME" = "macOS" ] && [ -d "$HOME/Library/Arduino15/packages" ]; then
  PKG_ROOT="$HOME/Library/Arduino15/packages"
fi

if [ -z "$PKG_ROOT" ]; then
  echo "[ERROR] Arduino packages folder not found"
  exit 1
fi

echo "[*] Using Arduino packages path:"
echo "    $PKG_ROOT"

FOUND=0

# ---------------------------------------------------------
# Scan all vendors / versions
# ---------------------------------------------------------
for VENDOR in "$PKG_ROOT"/*; do
  [ -d "$VENDOR" ] || continue

  ESP32_ROOT="$VENDOR/hardware/esp32"
  [ -d "$ESP32_ROOT" ] || continue

  for VERSION in "$ESP32_ROOT"/*; do
    [ -d "$VERSION" ] || continue

    PLATFORM="$VERSION/platform.txt"
    VENDOR_NAME="$(basename "$VENDOR")"
    VERSION_NAME="$(basename "$VERSION")"

    echo
    echo "[*] Vendor: $VENDOR_NAME | Version: $VERSION_NAME"

    if [ ! -f "$PLATFORM" ]; then
      echo "    [WARN] platform.txt not found, skipping"
      continue
    fi

    FOUND=1

    # -----------------------------------------------------
    # CHECKS
    # -----------------------------------------------------

    # Check -w in build.extra_flags.esp32*
    WARN_OK=1
    if grep -E '^build\.extra_flags\.esp32.*=' "$PLATFORM" | grep -vq -- '-w'; then
      WARN_OK=0
    fi

    # Check linker muldefs
    MULDEFS_OK=0
    if grep -Eq '^compiler\.c\.elf\.extra_flags=.*-z,muldefs' "$PLATFORM"; then
      MULDEFS_OK=1
    fi

    if [ "$WARN_OK" -eq 1 ] && [ "$MULDEFS_OK" -eq 1 ]; then
      echo "    [OK] Already fully patched"
      continue
    fi

    # -----------------------------------------------------
    # BACKUP
    # -----------------------------------------------------

    if [ ! -f "$PLATFORM.bak" ]; then
      cp "$PLATFORM" "$PLATFORM.bak"
      echo "    [INFO] Backup created"
    else
      echo "    [INFO] Backup already exists"
    fi

    # -----------------------------------------------------
    # PATCH build.extra_flags.*
    # -----------------------------------------------------

    if [ "$WARN_OK" -eq 0 ]; then
      echo "    [PATCH] Adding -w to build.extra_flags.esp32*"
      sed -i.bak2 -E \
        's/^(build\.extra_flags\.esp32[^=]*=)([^-]|$)/\1-w \2/' \
        "$PLATFORM"
      rm -f "$PLATFORM.bak2"
    else
      echo "    [OK] build.extra_flags already patched"
    fi

    # -----------------------------------------------------
    # PATCH linker muldefs
    # -----------------------------------------------------

    if [ "$MULDEFS_OK" -eq 0 ]; then
      echo "    [PATCH] Adding linker flag -Wl,-z,muldefs"

      if grep -q '^compiler\.c\.elf\.extra_flags=' "$PLATFORM"; then
        sed -i.bak2 -E \
          's/^compiler\.c\.elf\.extra_flags=(.*)$/compiler.c.elf.extra_flags=\1 -Wl,-z,muldefs/' \
          "$PLATFORM"
      else
        echo 'compiler.c.elf.extra_flags=-Wl,-z,muldefs' >> "$PLATFORM"
      fi

      rm -f "$PLATFORM.bak2"
    else
      echo "    [OK] linker muldefs already present"
    fi

    echo "    [DONE] Patch applied"
  done
done

if [ "$FOUND" -eq 0 ]; then
  echo "[ERROR] No ESP32 Arduino cores found"
  exit 1
fi

# ------------------------------------------------------------------
# OPTIONAL BADUSB PATCH
# ------------------------------------------------------------------

BADUSB_PATCH="$(cd "$(dirname "$0")/.." && pwd)/Bad_Usb_Lib/USB-LIB-PATCH.sh"

if [ -f "$BADUSB_PATCH" ]; then
    echo
    echo "[INFO] BadUSB patch script detected:"
    echo "       $BADUSB_PATCH"
    echo
    read -p "Do you want to run the BadUSB patch now? (y/N) " ans

    case "$ans" in
        y|Y|yes|YES)
            echo "[INFO] Running BadUSB patch..."
            bash "$BADUSB_PATCH"
            ;;
        *)
            echo "[INFO] BadUSB patch skipped by user"
            ;;
    esac
else
    echo
    echo "[INFO] No BadUSB patch script found, skipping"
fi


echo
echo "[DONE] All ESP32 Arduino cores (all vendors) processed"
echo "[INFO] Restart Arduino IDE before compiling"
