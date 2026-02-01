Write-Host "[*] BadUSB ESP32 Core Patcher (NO BACKUP)"
Write-Host "-------------------------------------------------------"

# ------------------------------------------------------------------
# PATHS (SCRIPT IS INSIDE Bad_Usb_Lib)
# ------------------------------------------------------------------

$BadUsbRoot  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArduinoPkgs = Join-Path $env:LOCALAPPDATA "Arduino15\packages"

# ------------------------------------------------------------------
# SANITY CHECKS
# ------------------------------------------------------------------

if (!(Test-Path $ArduinoPkgs)) {
    Write-Host "[ERROR] Arduino packages folder not found"
    exit 1
}

$payloadFiles = Get-ChildItem $BadUsbRoot -Recurse -File |
    Where-Object { $_.Name -notmatch '\.ps1$' }

if ($payloadFiles.Count -eq 0) {
    Write-Host "[ERROR] No payload files found in Bad_Usb_Lib"
    exit 1
}

# ------------------------------------------------------------------
# ENUMERATE ALL ESP32 CORES (ALL VENDORS / ALL VERSIONS)
# ------------------------------------------------------------------

$cores = @()

Get-ChildItem $ArduinoPkgs -Directory | ForEach-Object {
    $esp32Root = Join-Path $_.FullName "hardware\esp32"
    if (Test-Path $esp32Root) {
        Get-ChildItem $esp32Root -Directory | ForEach-Object {
            $corePath = Join-Path $_.FullName "cores\esp32"
            if (Test-Path $corePath) {
                $cores += [PSCustomObject]@{
                    Vendor  = $_.Parent.Parent.Parent.Name
                    Version = $_.Name
                    Core    = $corePath
                }
            }
        }
    }
}

if ($cores.Count -eq 0) {
    Write-Host "[ERROR] No ESP32 cores found"
    exit 1
}

# ------------------------------------------------------------------
# PATCH PROCESS
# ------------------------------------------------------------------

foreach ($c in $cores) {

    Write-Host ""
    Write-Host "[*] Vendor: $($c.Vendor) | Version: $($c.Version)"

    foreach ($src in $payloadFiles) {

        $relative = $src.FullName.Substring($BadUsbRoot.Length).TrimStart('\')
        $target   = Join-Path $c.Core $relative
        $targetDir = Split-Path $target -Parent

        if (!(Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            Write-Host "    [INFO] Created dir: $relative"
        }

        if (Test-Path $target) {
            $srcHash = (Get-FileHash $src.FullName -Algorithm SHA256).Hash
            $dstHash = (Get-FileHash $target -Algorithm SHA256).Hash

            if ($srcHash -eq $dstHash) {
                Write-Host "    [OK] Already identical: $relative"
                continue
            }
        }

        Copy-Item $src.FullName $target -Force
        Write-Host "    [PATCH] Overwritten: $relative"
    }

    Write-Host "    [DONE] Core patched"
}

Write-Host ""
Write-Host "[DONE] All ESP32 cores patched"
Write-Host "[INFO] Restart Arduino IDE before compiling"
