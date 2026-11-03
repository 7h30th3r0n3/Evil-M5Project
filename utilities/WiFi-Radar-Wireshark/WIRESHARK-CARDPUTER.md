# Evil-Cardputer as a Wireshark interface

Turn the Cardputer's **WiFi Radar** / **BLE Radar** feature into a live capture
interface that shows up directly in Wireshark's interface list, no command line
needed. The firmware streams captured frames as a pcap stream over its USB CDC
serial; the `evil-wifi-radar-extcap.py` extcap drives that and pipes it into
Wireshark.

- WiFi mode: 802.11 + radiotap (`LINKTYPE_IEEE802_11_RADIOTAP`, 127)
- BLE mode: Bluetooth LE LL + pseudo-header (`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`, 256)
- 100% passive, receive-only. No transmit, no injection.

---

## 1. Requirements

- A Cardputer flashed with the firmware that has **WiFi Radar** and **BLE Radar**
  in the menu (v1.5.7).
- Wireshark installed natively (not Flatpak/Snap, or the extcap folder differs).
- Your user in the `dialout` group so you can open `/dev/ttyACM*` without sudo:
  ```
  sudo usermod -aG dialout "$USER"   # then log out/in once
  ```
- Python 3 (stdlib only, no pyserial needed).

---

## 2. Install the extcap (one time)

Link the script into Wireshark's Personal Extcap folder:

```sh
cd tools
chmod +x evil-wifi-radar-extcap.py
EXTCAP=$(tshark -G folders | awk -F'\t' '/Personal Extcap/{print $2}')
mkdir -p "$EXTCAP"
ln -sf "$PWD/evil-wifi-radar-extcap.py" "$EXTCAP/"
```

Check Wireshark sees it (this is the enumeration the GUI uses):

```sh
wireshark -D | grep -i evil
# 15. evilwifiradar (Evil WiFi Radar)
# 16. evilwifiradar-ble (Evil WiFi Radar (BLE))
```

If `wireshark -D` lists them but the GUI does not, the GUI just needs a refresh:
**Capture menu -> Refresh Interfaces**, or restart Wireshark (it enumerates
extcaps at startup).

---

## 3. On the Cardputer: open the radar FIRST

The firmware only listens on the serial line while the radar screen is open.
Open it BEFORE you start the capture in Wireshark:

- For the **Evil WiFi Radar** interface -> open **WiFi Radar** on the device.
- For the **Evil WiFi Radar (BLE)** interface -> open **BLE Radar** on the device.

The radio is fixed by the feature you open (the extcap cannot switch it), so the
on-device menu and the Wireshark interface must match.

You can also arm the pcap stream by hand on the device: press **`p`** and a red
**REC** shows top-right. The extcap does this for you with the `S` byte, so you
do not have to, but REC is how you confirm the stream is live.

---

## 4. In Wireshark: capture

1. Plug the Cardputer in. It enumerates as `/dev/ttyACM0` (sometimes ACM1 after a
   reflash; the extcap auto-falls back to the first `/dev/ttyACM*` it finds).
2. In the interface list, double-click **Evil WiFi Radar** (or **Evil WiFi Radar
   (BLE)**).
3. To change the port: click the gear next to the interface name, set **Serial
   port**, start.

Frames land live. Filter examples:

```
wlan.fc.type_subtype == 0x08     # 802.11 beacons
wlan.fc.type == 0                # management frames
```

---

## 5. One-liner (CLI, no GUI)

Same thing from a terminal, straight into tshark:

```sh
# open WiFi Radar on the device first, then:
FIFO=/tmp/evilradar.pcap
mkfifo "$FIFO"
tools/evil-wifi-radar-extcap.py --capture --extcap-interface evilwifiradar \
  --port /dev/ttyACM0 --fifo "$FIFO" &
tshark -i "$FIFO"
```

Swap `evilwifiradar` for `evilwifiradar-ble` (and open BLE Radar instead) for BLE.

---

## 6. How it works

```
Cardputer WiFi/BLE Radar  --(USB CDC serial, pcap stream)-->  extcap  --(FIFO)-->  Wireshark
```

- The extcap sends `X` (stop any prior stream) then `S` (start). The firmware
  answers with the pcap global header (`0xa1b2c3d4`) and then frame records, each
  with a 13-byte radiotap header.
- `rdrPollSerialCmd()` handles `S` (start), `X` (stop), `Q` (quit to menu). The
  `W`/`B` bytes are ignored on purpose: the radio is fixed per feature.
- On stop, the extcap sends `X` so the device stops streaming cleanly.

---

## 7. Troubleshooting

- **Not in the Wireshark list** but `wireshark -D` shows it: refresh interfaces
  or restart the GUI. Check **Capture -> Manage Interfaces** that it is not hidden.
- **Nothing captured / hangs at start**: the radar screen is not open on the
  device, or you picked the WiFi interface while BLE Radar is open (or vice
  versa). The serial line is only served while the matching radar is on screen.
- **Permission denied on `/dev/ttyACM0`**: you are not in `dialout`, or another
  program (another Wireshark capture, a serial monitor) holds the port.
- **Wrong port**: unplug/replug and check `ls /dev/ttyACM*`; set it via the gear
  icon or `--port`.
