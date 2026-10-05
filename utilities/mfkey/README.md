# Outils host — Evil-Cardputer

## mfkey32 (récupération de clefs MIFARE Classic)

Le solveur mfkey32 pèse ~1-4 Mo de RAM transitoire : il tourne **sur PC**, pas
sur le Cardputer (ESP32-S3 sans PSRAM utilisable dans ce build). Le partage des
tâches :

1. **Sur le Cardputer** — `Cap NFC → "Emul MIFARE"` (mode 11). Le Cardputer
   émule l'identité d'une carte présentée et capture les nonces `{nt, nr, ar}`
   envoyés par un vrai lecteur, en les journalisant sur SD dans
   `/evil/mfkey_nonces.txt` (une ligne par nonce). Il faut **au moins 2 auths**
   sur le même secteur/clef (présente la carte 2× au lecteur).

2. **Sur PC** — récupère `mfkey_nonces.txt` depuis la SD, puis :

   ```sh
   g++ -std=c++17 -O2 mfkey_solve.cpp -o mfkey_solve
   ./mfkey_solve mfkey_nonces.txt
   ```

   Sortie : la clef A/B 48 bits par (cuid, bloc) résolu.

Format de ligne (écrit par le firmware) :
```
cuid=%08X blk=%d key=%c nt=%08X nr=%08X ar=%08X
```

### Fichiers
- `mfkey.h` — portage autonome de crapto1 / mfkey32 (préfixe `mfk_`), validé par
  round-trip synthétique. Partageable avec le firmware (tout `static inline`).
- `mfkey_solve.cpp` — CLI host : parse le fichier de nonces, groupe, résout.

La logique crypto (`mfkey.h`) est la même que celle citée par le firmware ; seul
le solveur lourd reste offline pour raison de mémoire.
