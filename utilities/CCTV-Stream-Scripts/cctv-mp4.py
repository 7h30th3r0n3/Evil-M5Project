import cv2
import time
import argparse
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

BIND_IP = "0.0.0.0"
PORT = 8080

WIDTH = 160
HEIGHT = 120
JPEG_QUALITY = 20


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--file", help="MP4 file")
    p.add_argument("-s", "--speed", type=float, default=1.0)
    return p.parse_args()


args = parse_args()

VIDEO_PATH = args.file or input("[?] Path to video file: ").strip()
SPEED = args.speed

cap_test = cv2.VideoCapture(VIDEO_PATH)
if not cap_test.isOpened():
    print("[!] Cannot open video")
    sys.exit(1)

FPS = cap_test.get(cv2.CAP_PROP_FPS)
BASE_FRAME_TIME = 1.0 / FPS
FRAME_TIME = BASE_FRAME_TIME / SPEED
TOTAL_FRAMES = int(cap_test.get(cv2.CAP_PROP_FRAME_COUNT))
cap_test.release()

print(f"[+] FPS={FPS:.2f}  speed=x{SPEED}")


class MJPEGHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "multipart/x-mixed-replace; boundary=frame"
        )
        self.end_headers()

        cap = cv2.VideoCapture(VIDEO_PATH)
        if not cap.isOpened():
            return

        start_time = time.monotonic()
        last_sent_frame = -1

        try:
            while True:
                now = time.monotonic()
                elapsed = now - start_time

                # frame théorique à envoyer (temps maître)
                expected_frame = int(elapsed / FRAME_TIME)

                # rebouclage
                if expected_frame >= TOTAL_FRAMES:
                    start_time = time.monotonic()
                    expected_frame = 0
                    last_sent_frame = -1

                # si client lent → drop frames
                if expected_frame <= last_sent_frame:
                    time.sleep(0.001)
                    continue

                cap.set(cv2.CAP_PROP_POS_FRAMES, expected_frame)
                ret, frame = cap.read()
                if not ret:
                    continue

                last_sent_frame = expected_frame

                frame = cv2.resize(frame, (WIDTH, HEIGHT),
                                   interpolation=cv2.INTER_AREA)

                ret, jpeg = cv2.imencode(
                    ".jpg",
                    frame,
                    [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
                )
                if not ret:
                    continue

                self.wfile.write(b"--frame\r\n")
                self.wfile.write(b"Content-Type: image/jpeg\r\n")
                self.wfile.write(
                    f"Content-Length: {len(jpeg)}\r\n\r\n".encode()
                )
                self.wfile.write(jpeg.tobytes())
                self.wfile.write(b"\r\n")

        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            cap.release()

    def log_message(self, *_):
        return


HTTPServer((BIND_IP, PORT), MJPEGHandler).serve_forever()

