# EvilRelay - NFC reader app for EMV relay with a Cardputer

Android app that plays the **reader side** of an NFC/ISO-DEP relay, so you only
need **one Cardputer + HAT** instead of two.

```
Real card ──NFC──> 📱 EvilRelay (reader) ──WiFi/TCP──> Cardputer+HAT (emulator) ──NFC──> Terminal/POS
```

The phone reads the real card (reader mode `IsoDep`) and relays the APDUs to the
Cardputer over WiFi. The Cardputer emulates the card against the terminal.
Research / education on your own hardware, with the same limits as any real
relay (RRP).

## Why the phone as reader (and not emulator)

- Android's `IsoDep.transceive()` handles ISO-DEP on its own (block numbers +
  chaining), giving clean, robust responses even on large certificates > 256 B.
- Android in **emulation** (HCE) randomizes the UID and does not let you control
  ATS/SAK, so the terminal rejects it. Emulation therefore stays on the Cardputer.

## Build

No external dependency (pure Android framework).

**Android Studio (easiest)**:
1. `File > Open` and select the `EvilRelayAPK/` folder.
2. Let it sync Gradle (it downloads AGP 8.1.4 / Kotlin 1.9.22 by itself).
3. `Build > Build Bundle(s)/APK(s) > Build APK(s)`, or plug in the phone and `Run`.
   The APK lands in `app/build/outputs/apk/debug/app-debug.apk`.

**Command line** (if the Android SDK is installed and `ANDROID_HOME` is set):
```bash
cd EvilRelayAPK
gradle assembleDebug        # or ./gradlew if you add the wrapper
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

minSdk 21, compileSdk 34. Requires a phone with **NFC**.

## Usage

1. **Cardputer**: Cap NFC > **Relay/Emul** > **APK (WiFi phone)**.
   It brings up a SoftAP `EvilRelay` (pass `evilrelay1234`, IP `192.168.4.1:5566`)
   and waits for the phone.
2. **Phone**: connect WiFi to `EvilRelay`.
3. Open **EvilRelay**, check the IP (`192.168.4.1`), then **hold the card against
   the back of the phone**. The app sends the identity and relays the APDUs. The
   Cardputer, placed on the terminal's antenna, emulates the card.

## TCP protocol (same as the firmware)

Frame: `[0x5A][type][seq][lenHi][lenLo][payload]`

| type | direction | payload |
|------|-----------|---------|
| 1 IDENT | phone -> CP | `[uidLen][uid…][atqa0][atqa1][sak][atsLen][ats…]` |
| 2 REQ   | CP -> phone | APDU from the terminal |
| 3 RESP  | phone -> CP | response from the card |

## Known limits

- **Reconstructed ATS**: Android only exposes the *historical bytes*, not the raw
  ATS. The app rebuilds a well-formed ATS (`TL,0x78,0x80,0xE0,0x00,hist…`) with
  the real historical bytes, accepted by most EMV terminals.
- **RRP**: a terminal that measures RF round-trip time (Relay Resistance Protocol)
  will decline, a wall common to every relay (NFCGate included).
- **Presence check**: the app sets `EXTRA_READER_PRESENCE_CHECK_DELAY=5000` so
  Android does not disturb the relayed ISO-DEP session.
