# 🧰 Utilities

This directory contains **standalone helper tools** used by the project.  
Each utility is isolated in its own folder (or subfolder) and ships with a dedicated `README.md` detailing:

- Purpose
- Prerequisites
- Installation
- Usage examples

These tools are not core firmware components, but **support development, analysis, reconnaissance, or post-processing workflows**.

---

## 📦 Contents Overview

### 🔌 Bad_Usb_Lib/
**USB HID / Keyboard Injection Library**

- USB HID & keyboard layout library (originally from *Bruce*)
- Required for firmware needing:
  - USB keyboard injection
  - Custom keyboard layouts
- Must be **copied into the Arduino ESP32 USB library path** before compilation

📌 *Why here?*  
Because it requires manual patching of Arduino core files and is reused across multiple firmwares.

➡️ See the folder `README.md` for:
- Exact paths
- Patch steps
- Compatibility notes

---

### 🎥 CCTV-Stream-Scripts/
**Minimal MJPEG-over-HTTP Streaming Tools**

- Lightweight MJPEG streamers for:
  - Webcam
  - Screen capture
  - MP4 playback
- Designed for LAN or local streaming
- Zero external dependencies

📌 *Why here?*  
These scripts pair well with the project’s devices to provide quick live video feeds.

➡️ See the folder `README.md` for:
- Requirements
- Launch commands
- Example use cases

---

### 📡 compilation_prerequisites/
**ESP32 Core Patching Utilities**

- Patches Arduino ESP32 cores to enable:
  - Raw 802.11 frame injection (deauth, low-level Wi-Fi)
  - Optional BadUSB core support
- Cross-platform scripts (Linux / macOS / Windows)

📌 *Why here?*  
Centralizes **mandatory prerequisite patches** required before compiling advanced firmware.

➡️ See the folder `README.md` for:
- Rationale
- Supported core versions
- Step-by-step procedure

---

### 📍 FindMyMap/
**Apple “Find My” Offline Finding Analysis Toolkit**

- Decrypts Apple Find My Offline Finding reports
- Generates an **interactive HTML map** with:
  - Timelines
  - Filters
  - Export options

📌 *Why here?*  
This is a standalone **post-processing & forensic analysis** utility.

➡️ See the folder `README.md` for:
- Required input files
- Decryption steps
- Map generation workflow

---

### 🔐 pcap2hccapx/
**PCAP → HCCAPX Conversion Helper**

- Extracts:
  - WPA handshakes
  - PMKIDs
- Converts captures into `hccapx` format

📌 *Why here?*  
Dedicated helper for preparing captures for **password auditing workflows**.

➡️ See the folder `README.md` for:
- Required tools
- Supported capture formats
- Conversion examples

---

### 🗺️ Pygle/
**Offline Wi-Fi Mapping Tool**

- Generates a WiGLE-like HTML map
- Works from wardriving CSV files
- Fully offline (no external uploads)

📌 *Why here?*  
Provides a **self-contained visualization** alternative to online services.

➡️ See the folder `README.md` for:
- Input format
- Output structure
- Visualization options

---

### 🔁 ReverseTCPControlServer/
**Reverse TCP Control Proxy**

- Asyncio-based TCP relay
- Allows a client to control an ESP32 that:
  - Initiates outbound connections
  - Is behind NAT / firewall

📌 *Why here?*  
Enables **remote control without inbound access**, ideal for constrained networks.

➡️ See the folder `README.md` for:
- Network topology
- Launch instructions
- Example scenarios

---

### 🚗 wardriving/
**Wardriving CSV Merger**

- Merges multiple wardriving CSV logs
- Produces a single consolidated dataset

📌 *Why here?*  
Small but useful helper for **cleanup, analysis, or bulk uploads**.

➡️ See the folder `README.md` or script header for usage details

---

### 🌍 WigleOpenFinder/
**Open Wi-Fi Reconnaissance Tool**

- Uses:
  - OpenStreetMap Nominatim
  - WiGLE API
- Lists open Wi-Fi SSIDs around a given city

📌 *Why here?*  
Bridges **geolocation search** with **WiGLE data reconnaissance**.

➡️ See the folder `README.md` for:
- API requirements
- Configuration
- Example queries

---

## 📖 Documentation

Each utility directory contains its own `README.md`.  
Always refer to the local documentation for **exact usage, limitations, and prerequisites**.

---
