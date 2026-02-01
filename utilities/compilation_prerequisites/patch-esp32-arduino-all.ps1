function Show-UEACPBanner {

    Write-Output "================================================================="
    Write-Output "|                                                               |"
    Write-Output "|        __    __   _______     ___       ______ .______        |"
    Write-Output "|       |  |  |  | |   ____|   /   \     /      ||   _  \       |"
    Write-Output "|       |  |  |  | |  |__     /  ^  \   |  ,----'|  |_)  |      |"
    Write-Output "|       |  |  |  | |   __|   /  /_\  \  |  |     |   ___/       |"
    Write-Output "|       |   `--'  | |  |____ /  _____  \ |  `----. |  |           |"
    Write-Output "|        \______/  |_______/__/     \__\ \______|| _|           |"
    Write-Output "|                                                               |"
    Write-Output "|            UNIVERSAL ESP32 ARDUINO CORE PATCHER               |"
    Write-Output "|                 Deauth / Raw WiFi / BadUSB                    |"
    Write-Output "|                  Research & Lab use only                      |"
    Write-Output "|                Made with <3 by 7h30th3r0n3                    |"
    Write-Output "|                                                               |"
    Write-Output "================================================================="
    Write-Output ""
}


Clear-Host
Show-UEACPBanner


$pkgRoot = Join-Path $env:LOCALAPPDATA 'Arduino15\packages'

if (!(Test-Path $pkgRoot)) {
    Write-Host '[ERROR] Arduino packages folder not found'
    exit 1
}

# Find ALL vendors providing an esp32 hardware core
$cores = Get-ChildItem $pkgRoot -Directory | ForEach-Object {
    $p = Join-Path $_.FullName 'hardware\esp32'
    if (Test-Path $p) {
        Get-ChildItem $p -Directory | ForEach-Object {
            [PSCustomObject]@{
                Vendor  = $_.Parent.Parent.Parent.Name
                Version = $_.Name
                Path    = $_.FullName
            }
        }
    }
}

if (!$cores) {
    Write-Host '[ERROR] No ESP32 Arduino cores found'
    exit 1
}

foreach ($c in $cores) {

    Write-Host ''
    Write-Host ('[*] Vendor: ' + $c.Vendor + ' | Version: ' + $c.Version)

    $platform = Join-Path $c.Path 'platform.txt'
    if (!(Test-Path $platform)) {
        Write-Host '    [WARN] platform.txt not found, skipping'
        continue
    }

    $content = Get-Content -Path $platform -Encoding ASCII

    # ---------------------------------------------------------
    # CHECKS
    # ---------------------------------------------------------

    # build.extra_flags.* -> must contain -w
    $warnLines = $content | Where-Object { $_ -match '^build.extra_flags\.esp32.*=' }
    $warnOK = $true
    foreach ($l in $warnLines) {
        if ($l -notmatch '-w') { $warnOK = $false }
    }

    # linker muldefs
    $muldefsOK = $false
    foreach ($l in $content) {
        if ($l -match '^compiler\.c\.elf\.extra_flags=.*-z,muldefs') {
            $muldefsOK = $true
        }
    }

    if ($warnOK -and $muldefsOK) {
        Write-Host '    [OK] Already fully patched'
        continue
    }

    # ---------------------------------------------------------
    # BACKUP
    # ---------------------------------------------------------

    $backup = $platform + '.bak'
    if (!(Test-Path $backup)) {
        Copy-Item $platform $backup
        Write-Host '    [INFO] Backup created'
    } else {
        Write-Host '    [INFO] Backup already exists'
    }

    # ---------------------------------------------------------
    # PATCH build.extra_flags.*
    # ---------------------------------------------------------

    if (-not $warnOK) {
        Write-Host '    [PATCH] Adding -w to build.extra_flags.esp32*'
        $content = $content -replace '^(build.extra_flags\.esp32[^=]*=)(?!.*-w)', '$1-w '
    } else {
        Write-Host '    [OK] build.extra_flags already patched'
    }

    # ---------------------------------------------------------
    # PATCH linker muldefs
    # ---------------------------------------------------------

    if (-not $muldefsOK) {
        Write-Host '    [PATCH] Adding linker flag -Wl,-z,muldefs'

        $patched = $false
        for ($i = 0; $i -lt $content.Length; $i++) {
            if ($content[$i] -match '^compiler\.c\.elf\.extra_flags=') {
                if ($content[$i] -eq 'compiler.c.elf.extra_flags=') {
                    $content[$i] = 'compiler.c.elf.extra_flags=-Wl,-z,muldefs'
                } else {
                    $content[$i] = $content[$i] + ' -Wl,-z,muldefs'
                }
                $patched = $true
                break
            }
        }

        if (-not $patched) {
            $content += 'compiler.c.elf.extra_flags=-Wl,-z,muldefs'
        }
    } else {
        Write-Host '    [OK] linker muldefs already present'
    }

    # ---------------------------------------------------------
    # WRITE BACK
    # ---------------------------------------------------------

    Set-Content -Path $platform -Value $content -Encoding ASCII
    Write-Host '    [DONE] Patch applied'
}




# ------------------------------------------------------------------
# OPTIONAL BADUSB PATCH
# ------------------------------------------------------------------

$BadUsbPatch = Join-Path (Split-Path $PSScriptRoot -Parent) "Bad_Usb_Lib\USB-LIB-PATCH.ps1"

if (Test-Path $BadUsbPatch) {

    Write-Host ""
    Write-Host "[INFO] BadUSB patch script detected:"
    Write-Host "       $BadUsbPatch"
    Write-Host ""
    $answer = Read-Host "Do you want to run the BadUSB patch now? (y/N)"

    if ($answer -match '^(y|Y|yes|YES)$') {
        Write-Host "[INFO] Running BadUSB patch..."
        powershell -ExecutionPolicy Bypass -File $BadUsbPatch
    } else {
        Write-Host "[INFO] BadUSB patch skipped by user"
    }

} else {
    Write-Host ""
    Write-Host "[INFO] No BadUSB patch script found, skipping"
}

Write-Host ''
Write-Host '[DONE] All ESP32 Arduino cores (all vendors) processed'
Write-Host '[INFO] Restart Arduino IDE before compiling'

