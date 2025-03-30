#!/bin/bash
#From nemo project https://github.com/n0xa/m5stick-nemo/tree/main/deauth_prerequisites

baseFolder="$HOME/.arduino15/packages/m5stack/hardware/esp32"

# Find the latest version of the folder
latestVersion="$(find "${baseFolder}" -maxdepth 1 -type d -exec basename {} \; | sed '/esp32/d' | sort -V -r | head -n 1)"

if [ -z "${latestVersion}" ]; then
    echo "No version found."
    read -p "Press Enter to exit."
    exit 1
fi

# Full path to the file to be edited
file="${baseFolder}/${latestVersion}/platform.txt"
backupFile="${baseFolder}/${latestVersion}/platform.txt.bkp"
prefix="build.extra_flags.esp32"
option=" -w "

prefix2="compiler.c.elf.libs.esp32"
option2=" -zmuldefs "

readyMark="##EVIL_DEAUTH_READY##"

# Check if the ready mark already exists in the file
if grep -q "${readyMark}" "${file}"; then
    echo "The file is already OK."
    read -p "Press Enter to exit."
    exit 0
fi

# Create a backup copy of the original file
cp "${file}" "${backupFile}"

# Use awk to insert options after the first equals sign on lines with specified prefixes
awk -v prefix="${prefix}" -v option="${option}" -v prefix2="${prefix2}" -v option2="${option2}" '{
    if ($0 ~ "^" prefix) {
        sub(/=/, "=" option);
        print;
    } else if ($0 ~ "^" prefix2) {
        sub(/=/, "=" option2);
        print;
    } else {
        print;
    }
}' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"

# Add the ready mark to the end of the file
echo "${readyMark}" >> "${file}"

echo "Done."
