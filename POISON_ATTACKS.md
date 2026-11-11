# PoisonMesh / PoisonCore — LoRa pentest PoC launchers

Two standalone LoRa pentest Proof-of-Concepts by Teno, integrated into the
Evil-Cardputer UI as two menu entries placed just above **Settings**:

* **PoisonMesh** → targets **Meshtastic** (CVE-2024-51500, CVE-2025-55293)
* **PoisonCore** → targets **MeshCore** (GHSA draft: CWE-345 / CWE-290 / CWE-294)

**Hardware:** Cardputer ADV + Cap LoRa-1262 (Semtech **SX1262**, 850–960 MHz).
The SX1262 is brought up / torn down around each attack, so the Poison radio
layer never clashes with the existing LoRaWAN / "totem" LoRa code (only one is
active at a time).

> **Authorized use only.** Run these only against your own networks or with
> explicit permission. They transmit on LoRa and are disruptive by design.

---

## Navigation (Cardputer keys)

| Keys | In a list | In a number field (`numInput`) |
|------|-----------|--------------------------------|
| `;` / `.` | up / down | **+1 / −1** |
| `,` / `/` | — | **−10 / +10** |
| `ENTER` | open / confirm | confirm |
| `BKSP` | back | cancel |

Attacks are blocked until a preset is confirmed (**Setup LoRa (RF)** for
PoisonMesh, **Config RF** for PoisonCore). While a live attack runs, `BKSP`
stops it.

---

## PoisonMesh (Meshtastic)

Pure Meshtastic logic: manual protobuf serialization, AES-CTR with the public
Meshtastic PSK (LongFast public channel), per-attack packet builders, an RX
parser and a live NodeDB fed passively in the background.

| # | Attack | What it does |
|---|--------|--------------|
| — | **Setup LoRa (RF)** | Pick LoRa region (US…JP) and modem preset (ShortTurbo…VeryLongSlow, default LongFast) + slot. The channel frequency is derived from region + preset and applied to the SX1262. Must be set before any attack. |
| 1 | **Flood Nodes** | Mass injection of phantom nodes with random names and hardware IDs to pollute the target mesh's node DB. Parameters: node count, duration. |
| 2 | **MeshGrow** *(toggle)* | Periodic injection of nodes at random GPS positions. Toggle ON / OFF. |
| 3 | **Namechange** | Rename an existing (discovered) node, choosing an arbitrary board / hardware model. Parameters: long name, short name, duration. |
| 4 | **Position Poison** | Relocate a target node to a preset destination (Malvinas, Egypt, Australia, Rome). Parameters: target node, duration. |
| 5 | **Mesh Move** *(toggle)* | Auto-relocate **every** discovered node, renaming each one as "Moved". |
| 6 | **Mesh Impersonator** | Impersonate a node to send text messages, with optional repeat count. Parameters: target node, message, count. |
| 7 | **PKI Poison** | **CVE-2025-55293** — wipe a target node's stored public key, breaking PKI and enabling identity spoofing. Parameters: target node, duration. |
| 8 | **ChattyMesh** *(toggle)* | Continuous impersonation of random nodes with random text; random 2–6 s delay. Toggle ON / OFF. |
| 9 | **GhostMesh** | Persistent phantom node (manual name + X25519 key derived from the node id) kept for the whole session, from which you can announce the node and spoof text messages. |

**CVE-2024-51500** — LoRa amplification / DoS.
**CVE-2025-55293** — PKI key poisoning (exploited by *PKI Poison*).

---

## PoisonCore (MeshCore)

Sibling PoC for MeshCore: Ed25519 identity, MeshCore framing (adverts, GRP_TXT,
DM), AES-128-ECB + HMAC-SHA256 crypto (ported to mbedtls to avoid pulling in the
rweather/Crypto library). SX1262 sync word **0x12**.

| Attack | What it does |
|--------|--------------|
| **Config RF** | Preset / Freq / BW / SF / CR / TxPwr editor. Review and edit before any TX. Must be set before any attack. |
| **Announce Flood** | Flood MeshCore adverts. *Refresh* mode (own identity, timestamp++) or *Sybil* mode (a new identity per advert). |
| **Channel / DM Spoof** | Post on the Public channel as any spoofed sender name, or DM a sniffed node. Abuses the unauthenticated GRP_TXT sender string. |
| **CoreImpersonator** | Spoof a sender name on the Public channel (picked from a sniffed node or typed by hand). |
| **GhostSwarm** *(auto)* | Churn of ephemeral identities: announce + a few channel messages, then regenerate the identity and repeat. |
| **DarkMirror** *(auto)* | Listen for Public-channel GRP_TXT messages, then replay them with a live timestamp (skips MeshCore's dedup). |
| **Regen Identity** | Generate a fresh Ed25519 keypair + name (reset) for cost-free Sybil identities. |
| **Recon / Sniffer** | Passive RX only; lists the adverts and nodes observed on the mesh. |

**GHSA draft** — unauthenticated sender identity + weak replay
(CWE-345 / CWE-290 / CWE-294).
