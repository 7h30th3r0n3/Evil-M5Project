#!/usr/bin/env python3
# ============================================================================
#  evil-wifi-radar-extcap.py  -  Wireshark extcap for the Evil-Cardputer
#  "WiFi Radar" feature (DragonRadar port).
#
#  When you are in the WiFi Radar screen on the Cardputer, the firmware streams
#  captured frames as a pcap stream over its USB CDC serial: 802.11 + radiotap
#  (LINKTYPE_IEEE802_11_RADIOTAP, 127) in WiFi mode, or Bluetooth LE LL with a
#  pseudo-header (256) in BLE mode. It starts on the byte 'S', stops on 'X',
#  and switches radio on 'W' (WiFi) / 'B' (BLE). This extcap drives that.
#
#  Install:
#    chmod +x evil-wifi-radar-extcap.py
#    # find the personal extcap folder for your Wireshark build:
#    #   tshark -G folders | grep -i extcap
#    EXTCAP=$(tshark -G folders | awk -F'\t' '/Personal Extcap/{print $2}')
#    mkdir -p "$EXTCAP" && ln -s "$PWD/evil-wifi-radar-extcap.py" "$EXTCAP/"
#  Open the "WiFi Radar" feature on the Cardputer FIRST (it owns the serial line
#  only while that screen is open), then in Wireshark pick "Evil WiFi Radar" or
#  "Evil WiFi Radar (BLE)", set the serial port (default /dev/ttyACM0), start.
#
#  Stdlib only (no pyserial). The serial port is opened raw via termios.
#  SPDX-License-Identifier: GPL-3.0-or-later
#  Copyright (c) 7h30th3r0n3
# ============================================================================
import sys, os, argparse, signal, tty, termios, glob

IFACE = "evilwifiradar"
DISPLAY = "Evil WiFi Radar"
IFACE_BLE = "evilwifiradar-ble"
DISPLAY_BLE = "Evil WiFi Radar (BLE)"

def resolve_port(port):
    # requested port exists -> keep it; else take the first /dev/ttyACM*
    # (the device sometimes re-enumerates ACM0->ACM1 after a reflash)
    if port and os.path.exists(port):
        return port
    cands = sorted(glob.glob("/dev/ttyACM*")) or sorted(glob.glob("/dev/ttyUSB*"))
    return cands[0] if cands else port

def cmd_interfaces():
    print("extcap {version=1.1}{help=Evil-Cardputer WiFi Radar passive 2.4GHz sniffer (WiFi + BLE)}")
    print("interface {value=%s}{display=%s}" % (IFACE, DISPLAY))
    print("interface {value=%s}{display=%s}" % (IFACE_BLE, DISPLAY_BLE))

def cmd_dlts(iface):
    if iface == IFACE_BLE:
        print("dlt {number=256}{name=BLUETOOTH_LE_LL_WITH_PHDR}{display=Bluetooth LE LL plus pseudo-header}")
    else:
        print("dlt {number=127}{name=IEEE802_11_RADIOTAP}{display=802.11 plus radiotap}")

def cmd_config():
    print("arg {number=0}{call=--port}{display=Serial port}{type=string}"
          "{default=/dev/ttyACM0}{tooltip=Evil-Cardputer USB CDC device}")

def open_serial_raw(port):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY)
    try:
        tty.setraw(fd)
        a = termios.tcgetattr(fd)
        a[2] |= (termios.CLOCAL | termios.CREAD)   # ignore modem lines, enable rx
        termios.tcsetattr(fd, termios.TCSANOW, a)
    except Exception:
        pass
    return fd

def drain(fd, ms=250):
    import select
    end = ms / 1000.0
    while True:
        r, _, _ = select.select([fd], [], [], end)
        if not r:
            return
        try:
            if not os.read(fd, 4096):
                return
        except OSError:
            return

def cmd_capture(port, fifo, iface):
    port = resolve_port(port)
    ser = open_serial_raw(port)
    mode = b'B' if iface == IFACE_BLE else b'W'   # force the matching radio mode

    def stop(*_):
        try: os.write(ser, b'X')
        except Exception: pass
        try: os.close(ser)
        except Exception: pass
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # clean start: stop any prior stream, select the radio mode, flush, fresh stream
    try: os.write(ser, b'X' + mode)
    except Exception: pass
    drain(ser, 400)                       # allow the WiFi<->BLE switch to settle

    out = os.open(fifo, os.O_WRONLY)      # blocks until Wireshark opens the read end

    try: os.write(ser, b'S')              # firmware sends the pcap global header + records
    except Exception: pass

    try:
        while True:
            data = os.read(ser, 8192)
            if not data:
                continue
            os.write(out, data)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try: os.write(ser, b'X')
        except Exception: pass
        try: os.close(ser)
        except Exception: pass
        try: os.close(out)
        except Exception: pass

def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--extcap-interfaces", action="store_true")
    p.add_argument("--extcap-dlts", action="store_true")
    p.add_argument("--extcap-config", action="store_true")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--extcap-interface", default="")
    p.add_argument("--extcap-version", default="")
    p.add_argument("--fifo", default="")
    p.add_argument("--port", default="/dev/ttyACM0")
    args, _ = p.parse_known_args()

    if args.extcap_interfaces:
        cmd_interfaces(); return
    if args.extcap_dlts:
        cmd_dlts(args.extcap_interface); return
    if args.extcap_config:
        cmd_config(); return
    if args.capture:
        if not args.fifo:
            sys.stderr.write("no --fifo given\n"); sys.exit(1)
        cmd_capture(args.port, args.fifo, args.extcap_interface); return
    cmd_interfaces()

if __name__ == "__main__":
    main()
