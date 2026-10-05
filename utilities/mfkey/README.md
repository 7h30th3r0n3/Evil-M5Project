# Host tools - Evil-Cardputer

## mfkey32 (MIFARE Classic key recovery)

The mfkey32 solver needs a few MB of transient RAM, so it runs **on a PC**, not
on the Cardputer (ESP32-S3 with no usable PSRAM in this build). The split of
work:

1. **On the Cardputer** - `Cap NFC > "Emul MIFARE"` (mode 11). The Cardputer
   emulates the identity of a presented card and captures the `{nt, nr, ar}`
   nonces sent by a real reader, logging them to the SD card in
   `/evil/mfkey_nonces.txt` (one line per nonce). You need **at least 2 auths**
   on the same sector/key (present the card to the reader twice).

2. **On a PC** - copy `mfkey_nonces.txt` from the SD card, then:

   ```sh
   g++ -std=c++17 -O2 mfkey_solve.cpp -o mfkey_solve
   ./mfkey_solve mfkey_nonces.txt
   ```

   Output: the 48-bit key A/B for each solved (cuid, block).

Line format (written by the firmware):
```
cuid=%08X blk=%d key=%c nt=%08X nr=%08X ar=%08X
```

### Files
- `mfkey.h` - standalone port of crapto1 / mfkey32 (`mfk_` prefix), validated by
  synthetic round-trip. Shareable with the firmware (all `static inline`).
- `mfkey_solve.cpp` - host CLI: parses the nonce file, groups, solves.

The crypto logic (`mfkey.h`) is the same as the one referenced by the firmware;
only the heavy solver stays offline for memory reasons.
