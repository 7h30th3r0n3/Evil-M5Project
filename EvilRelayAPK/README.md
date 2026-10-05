# EvilRelay — APK lecteur NFC pour relais EMV avec un Cardputer

Application Android qui joue le **côté lecteur** d'un relais NFC/ISO-DEP, pour
n'avoir besoin que d'**un seul Cardputer + HAT** (au lieu de deux).

```
Vraie carte ──NFC──> 📱 EvilRelay (reader) ──WiFi/TCP──> Cardputer+HAT (émul) ──NFC──> Terminal/TPE
```

Le téléphone lit la vraie carte (mode reader `IsoDep`) et relaie les APDU au
Cardputer par WiFi. Le Cardputer émule la carte devant le terminal. Recherche /
éducation sur ton propre matériel — mêmes limites qu'un vrai relais (RRP).

## Pourquoi le téléphone en lecteur (et pas en émulateur)

- `IsoDep.transceive()` d'Android gère l'ISO-DEP tout seul (block numbers +
  chaînage) → réponses propres, robuste, même sur gros certificats > 256 o.
- Android en **émulation** (HCE) randomise l'UID et ne laisse pas contrôler
  ATS/SAK → le terminal rejette. Donc l'émulation reste côté Cardputer.

## Build

Aucune dépendance externe (pur framework Android).

**Android Studio (le plus simple)** :
1. `File → Open` → sélectionne le dossier `EvilRelayAPK/`.
2. Laisse-le synchroniser Gradle (télécharge AGP 8.1.4 / Kotlin 1.9.22 tout seul).
3. `Build → Build Bundle(s)/APK(s) → Build APK(s)`, ou branche le tel et `Run ▶`.
   L'APK sort dans `app/build/outputs/apk/debug/app-debug.apk`.

**Ligne de commande** (si SDK Android installé, `ANDROID_HOME` défini) :
```bash
cd EvilRelayAPK
gradle assembleDebug        # ou ./gradlew si tu ajoutes le wrapper
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

minSdk 21, compileSdk 34. Nécessite un téléphone avec **NFC**.

## Utilisation

1. **Cardputer** : Cap NFC → **Relay/Emul** → **APK (WiFi phone)**.
   Il monte un SoftAP `EvilRelay` (pass `evilrelay1234`, IP `192.168.4.1:5566`)
   et attend le téléphone.
2. **Téléphone** : connecte le WiFi à `EvilRelay`.
3. Lance **EvilRelay**, vérifie l'IP (`192.168.4.1`), **pose la carte au dos du
   tel**. L'app envoie l'identité + relaie les APDU. Le Cardputer, posé sur
   l'antenne du terminal, émule la carte.

## Protocole TCP (identique au firmware)

Trame : `[0x5A][type][seq][lenHi][lenLo][payload]`

| type | sens | payload |
|------|------|---------|
| 1 IDENT | tel → CP | `[uidLen][uid…][atqa0][atqa1][sak][atsLen][ats…]` |
| 2 REQ   | CP → tel | APDU du terminal |
| 3 RESP  | tel → CP | réponse de la carte |

## Limites connues

- **ATS reconstruit** : Android n'expose que les *historical bytes*, pas l'ATS
  brut. L'app reconstruit un ATS bien formé (`TL,0x78,0x80,0xE0,0x00,hist…`)
  avec les vrais historical bytes — accepté par la plupart des terminaux EMV.
- **RRP** : un terminal qui mesure le temps RF (Relay Resistance Protocol)
  déclinera — mur commun à tout relais (NFCGate compris).
- **Presence check** : l'app met `EXTRA_READER_PRESENCE_CHECK_DELAY=5000` pour
  qu'Android ne perturbe pas la session ISO-DEP relayée.
