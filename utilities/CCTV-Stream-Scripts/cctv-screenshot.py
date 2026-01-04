import time
import socket
import select
import argparse

import cv2
import numpy as np
import mss

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


def parse_args():
    p = argparse.ArgumentParser(description="Screen -> MJPEG (optimized)")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--width", type=int, default=160)
    p.add_argument("--height", type=int, default=120)
    p.add_argument("--fps", type=float, default=10.0)
    p.add_argument("--quality", type=int, default=60)  # 0-100
    p.add_argument("--monitor", type=int, default=1)   # 1 = écran principal
    p.add_argument("--region", default="", help='Format: left,top,width,height (ex: "0,0,640,360")')
    return p.parse_args()


ARGS = parse_args()

BIND_IP = ARGS.bind
PORT = ARGS.port
WIDTH = ARGS.width
HEIGHT = ARGS.height
TARGET_FPS = max(0.1, ARGS.fps)
FRAME_TIME = 1.0 / TARGET_FPS
JPEG_QUALITY = int(np.clip(ARGS.quality, 0, 100))


# Optionnel: parfois ça réduit les micro-stutters OpenCV sur petites configs
try:
    cv2.setNumThreads(1)
except Exception:
    pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MJPEGHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # plus stable pour MJPEG long-running

    def do_GET(self):
        # TCP tuning léger (sans forcer flush agressif)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-cache, private")
        self.send_header("Pragma", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        sct = mss.mss()

        # Choix de la zone à capturer
        if ARGS.region:
            l, t, w, h = [int(x) for x in ARGS.region.split(",")]
            monitor = {"left": l, "top": t, "width": w, "height": h}
        else:
            monitor = sct.monitors[ARGS.monitor]

        # Pacing propre: horloge + deadline (évite busy loop)
        next_t = time.monotonic()

        try:
            while True:
                now = time.monotonic()
                if now < next_t:
                    time.sleep(next_t - now)
                else:
                    # si on est en retard, on recale (drop implicite)
                    next_t = now
                next_t += FRAME_TIME

                # Si socket pas writable, on drop la frame sans bloquer
                _, writable, _ = select.select([], [self.connection], [], 0)
                if not writable:
                    continue

                shot = sct.grab(monitor)

                # Optimisation majeure: pas de np.array(...) ni cvtColor
                # shot.raw = BGRA bytes -> view numpy -> on prend BGR ([:,:,:3])
                img = np.frombuffer(shot.raw, dtype=np.uint8).reshape((shot.height, shot.width, 4))
                img = img[:, :, :3]  # BGR (view)

                # Resize (INTER_AREA pour downscale)
                frame = cv2.resize(img, (WIDTH, HEIGHT), interpolation=cv2.INTER_AREA)

                # Assurer contiguïté avant encode (évite copies cachées)
                frame = np.ascontiguousarray(frame)

                ok, enc = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
                if not ok:
                    continue

                jpeg = enc.tobytes()

                # 1 seule écriture par frame (réduit syscalls et jitter)
                header = (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n"
                    + f"Content-Length: {len(jpeg)}\r\n\r\n".encode()
                )
                payload = header + jpeg + b"\r\n"
                self.wfile.write(payload)

        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        return


def main():
    server = ThreadedHTTPServer((BIND_IP, PORT), MJPEGHandler)
    print(f"[+] Screen MJPEG optimized: http://<IP_LAN>:{PORT}")
    print(f"[+] {WIDTH}x{HEIGHT} @ {TARGET_FPS} fps, quality={JPEG_QUALITY}, monitor={ARGS.monitor}, region={ARGS.region or 'full'}")
    server.serve_forever()


if __name__ == "__main__":
    main()

