# Utilities

This folder groups standalone tools used by the project. Each tool lives in its own directory (or subfolder) and has a dedicated `README.md` with full usage, prerequisites, and examples.

## Contents (short overview)

### `Bad_Usb_Lib/`
USB HID / keyboard layout library and patch scripts (from Bruce).  
Use it when building firmware that needs USB keyboard injection or custom layouts.  
It belongs here because it must be copied into the Arduino ESP32 USB library path before compiling.  
See the folder README for exact paths and patch steps.

### `CCTV-Stream-Scripts/`
Minimal MJPEG-over-HTTP streamers for webcam, screen capture, or MP4 playback.  
Use them to quickly provide a live video feed to another device (LAN or local).  
They are included because they are zero-dependency tools that pair well with the project’s devices.  
See the folder README for requirements and usage.

### `compilation_prerequisites/`
Patches Arduino ESP32 cores to enable raw 802.11 frame usage (and optional BadUSB core patch).  
Use it before compiling firmware that needs deauth or low-level Wi‑Fi frames.  
It lives here to centralize the prerequisite patching scripts for multiple OSes.  
See the folder README for the rationale and exact procedure.

### `FindMyMap/`
Apple Find My Offline Finding forensic/analysis toolkit that decrypts reports and builds an interactive HTML map.  
Use it to visualize collected Find My reports with timelines, filters, and exports.  
It is part of utilities because it’s a standalone post‑processing/analysis step.  
See the folder README for required files and usage.

### `pcap2hccapx/`
Extracts handshakes/PMKID from PCAP and converts them to hccapx.  
Use it when you need to prepare captures for password auditing workflows.  
It’s included as a dedicated conversion helper with clear prerequisites.  
See the folder README for tools needed and how to run it.

### `Pygle/`
Offline Wi‑Fi map generator from wardriving CSVs (WiGLE‑like HTML visualization).  
Use it to explore collected Wi‑Fi data without uploading to external services.  
It’s here as a simple, self‑contained visualization tool.  
See the folder README for requirements and output details.

### `ReverseTCPControlServer/`
Asyncio proxy that relays traffic between an ESP32 and a client over a reverse TCP link.  
Use it when the device must connect outward but a client still needs to reach it.  
It’s included because it enables remote control without direct inbound access.  
See the folder README for networking setup notes.

### `wardriving/`
Scripts that merge multiple wardriving CSV logs into a single output file.  
Use it when you have many capture files and want one consolidated dataset.  
It lives here as a small helper for streamlining uploads or analysis.  
See the folder README (or script header) for usage.

### `WigleOpenFinder/`
Uses OSM Nominatim + Wigle API to list open Wi‑Fi SSIDs around a city.  
Use it for quick reconnaissance of open networks in a geographic area.  
It’s included because it bridges location search with Wigle data lookup.  
See the folder README for API requirements and usage.

Open the `README.md` inside each folder for full details.
