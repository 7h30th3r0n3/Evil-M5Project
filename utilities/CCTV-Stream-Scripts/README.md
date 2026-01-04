# CCTV Stream (MJPEG over HTTP)

Simple, zero-dependency web servers to stream MJPEG over HTTP from:
- a webcam (`cctv.py`),
- your screen (`cctv-screenshot.py`),
- or an MP4 file (`cctv-mp4.py`).

Open the stream by placing url on CCTV_live file to see it on cardputer directly or in any browser at `http://<server-ip>:8080` or , or embed it in HTML using `<img src="http://<server-ip>:8080" />`.

**Note**: These are minimal servers intended for local/LAN use. There is no authentication or TLS. Run only on trusted networks.

**Repository content**
- `cctv.py`: webcam MJPEG server
- `cctv.exe`: EXE version of cctv.py 
- `cctv-screenshot.py`: screen-capture MJPEG server
- `cctv-mp4.py`: MP4-to-MJPEG server (loops)

## Requirements

- Python 3.8+
- Packages:
  - `opencv-python` (OpenCV)
  - `numpy`
  - `mss` (only needed for `cctv-screenshot.py`)

Install:
- Linux/macOS: `python3 -m pip install opencv-python numpy mss`
- Windows: `py -m pip install opencv-python numpy mss`

## Quick Start

- Recommended (screen capture with good balance):
  - `python3 ./cctv-screenshot.py --width 160 --height 120 --fps 20 --quality 70`
- View the stream:
  - From the same machine: `http://localhost:8080`
  - From another device on the LAN: `http://<server-ip>:8080`

Tip: On Windows use `python` instead of `python3`, e.g. `python cctv-screenshot.py ...`.

## Scripts

### `cctv.py` — Webcam to MJPEG

- Purpose: Streams frames from the default camera as MJPEG over HTTP.
- Run: `python cctv.py`
- Open: `http://localhost:8080`
- Defaults (edit in the file if needed):
  - `BIND_IP=0.0.0.0` (accessible from LAN)
  - `PORT=8080`
  - `WIDTH=160`, `HEIGHT=120`
  - JPEG quality ~70 (set in `cv2.imencode`)
  - Frame pacing ≈ 25 FPS (`FPS_DELAY=0.04`)
- Notes:
  - Uses `cv2.VideoCapture(0, cv2.CAP_DSHOW)` (directshow) on Windows; adjust if needed on other OS.

### `cctv-screenshot.py` — Screen to MJPEG

- Purpose: Captures your screen (or a region/monitor) and streams MJPEG.
- Run (recommended preset):
  - `python3 ./cctv-screenshot.py --width 160 --height 120 --fps 20 --quality 70`
- Options:
  - `--bind` (default `0.0.0.0`), `--port` (default `8080`)
  - `--width`, `--height` (downscale target)
  - `--fps` (target FPS)
  - `--quality` (JPEG quality 0–100)
  - `--monitor` (monitor index, default `1` = primary)
  - `--region` (`left,top,width,height`, e.g. `"0,0,640,360"`)
- Examples:
  - Second monitor, 320×180 @ 15 FPS: `python3 ./cctv-screenshot.py --monitor 2 --width 320 --height 180 --fps 15`
  - Specific region: `python3 ./cctv-screenshot.py --region "100,100,800,450" --width 320 --height 180 --fps 20`

### `cctv-mp4.py` — MP4 to MJPEG (Looping)

- Purpose: Plays an MP4 and serves frames as MJPEG, looping at the end.
- Run: `python cctv-mp4.py -f path/to/video.mp4 [-s 1.0]`
- Open: `http://localhost:8080`
- Options:
  - `-f, --file` Path to MP4 (if omitted, you’ll be prompted)
  - `-s, --speed` Playback speed multiplier (e.g. `0.5`, `1.0`, `1.5`)
- Internals/defaults:
  - Resizes to `160×120`, JPEG quality `20` (edit constants in file to change)

## Clients and Embedding

- Browser: open `http://<server-ip>:8080` directly.
- HTML: `<img src="http://<server-ip>:8080" alt="MJPEG stream" />`
- Many players (e.g. VLC) can open MJPEG over HTTP by URL.

## Tips & Troubleshooting

- No auth/TLS: Streams are unencrypted and unauthenticated. Run only on trusted networks.
- Firewall: Ensure port `8080` is allowed inbound on the host.
- Performance: Lower `--width/--height`, `--fps`, or `--quality` if CPU is high.
- Multiple clients: `cctv-screenshot.py` uses a threaded HTTP server; multiple viewers are supported.
- Dependencies: If `cv2`/`numpy`/`mss` are missing, install via pip as shown above.

