import cv2
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

BIND_IP = "0.0.0.0"   # accessible depuis tout le LAN
PORT = 8080
WIDTH = 160
HEIGHT = 120
FPS_DELAY = 0.04

class MJPEGHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "multipart/x-mixed-replace; boundary=frame"
        )
        self.end_headers()

        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

        # Force la résolution côté driver (si supportée)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, WIDTH)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, HEIGHT)

        if not cap.isOpened():
            return

        try:
            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                # Sécurité : resize logiciel si le driver ignore CAP_PROP
                frame = cv2.resize(frame, (WIDTH, HEIGHT),
                                   interpolation=cv2.INTER_AREA)

                ret, jpeg = cv2.imencode(
                    ".jpg",
                    frame,
                    [cv2.IMWRITE_JPEG_QUALITY, 70]
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

                time.sleep(FPS_DELAY)

        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            cap.release()

    def log_message(self, format, *args):
        return  # silence logs HTTP


def main():
    server = HTTPServer((BIND_IP, PORT), MJPEGHandler)
    print(f"[+] MJPEG disponible sur http://<IP_LAN>:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

