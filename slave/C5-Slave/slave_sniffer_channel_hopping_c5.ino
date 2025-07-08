#include <esp_wifi.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi_types.h>  // pour wifi_tx_info_t
#include <SD.h>

// -----------------------------------------------------------------------------
// 1) Paramètres globaux
// -----------------------------------------------------------------------------

// Taille max d'une trame Wi-Fi et fragmentation ESP-NOW
#define MAX_FRAME_SIZE       2346
#define ESPNOW_MAX_DATA_LEN  250
const uint16_t MAX_FRAGMENT_SIZE = ESPNOW_MAX_DATA_LEN
    - sizeof(uint16_t)      // frame_len
    - sizeof(uint8_t)       // fragment_number
    - sizeof(bool)          // last_fragment
    - sizeof(uint8_t);      // boardID

// Canal “d’origine” auquel on revient pour envoyer (ici on choisit 1)
#define CHANNEL  1

// Liste exhaustive des canaux “logiques” (2.4 GHz : 1→14, puis 5 GHz : 36→165)
static const uint8_t channelsList[] = {
  // 2.4 GHz
   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  // 5 GHz (mêmes valeurs que channelsToHop)
  36, 40, 44, 48, 52, 56, 60, 64,
 100,104,108,112,116,120,124,128,132,136,140,
 //USA
 144,149,153,157,161,165
};
static const size_t NUM_CHANNELS = sizeof(channelsList) / sizeof(channelsList[0]);  // = 39

// Tableau des canaux sur lesquels on “hoppe” en capture
const uint8_t channelsToHop[] = {
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
//EU channel 
};
const size_t numChannels = sizeof(channelsToHop) / sizeof(channelsToHop[0]);

// Durée sur chaque canal (en ms) avant de passer au suivant
const unsigned long dwellTimeMs = 250;

// Adresse de broadcast pour ESP-NOW
uint8_t broadcastAddress[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// -----------------------------------------------------------------------------
// 2) Définitions des structures de fragmentation + buffers
// -----------------------------------------------------------------------------

typedef struct {
  uint16_t frame_len;
  uint8_t  fragment_number;
  bool     last_fragment;
  uint8_t  boardID;                       // Cet octet sera dynamique
  uint8_t  frame[MAX_FRAGMENT_SIZE];
} wifi_frame_fragment_t;

wifi_frame_fragment_t wifiFrameFragment;

// Variables de capture (sniffer promiscuous)
bool    firstEAPOLCaptured     = false;
uint8_t apBSSID[6];
bool    beaconCaptured         = false;
bool    allFramesCollected     = false;

const int MAX_EAPOL_FRAMES = 4;
uint8_t eapolFrames[MAX_EAPOL_FRAMES][MAX_FRAME_SIZE];
int     eapolFrameLengths[MAX_EAPOL_FRAMES];
int     eapolFramesCaptured = 0;

uint8_t beaconFrame[MAX_FRAME_SIZE];
int     beaconFrameLength = 0;

// File d’attente de fragments à envoyer en ESP-NOW
typedef struct {
  uint8_t data[ESPNOW_MAX_DATA_LEN];
  size_t  len;
} fragment_queue_item_t;

#define FRAGMENT_QUEUE_SIZE  20
fragment_queue_item_t fragmentQueue[FRAGMENT_QUEUE_SIZE];
int  fragmentQueueStart = 0;
int  fragmentQueueEnd   = 0;
bool isSending               = false;
bool waitingForSendCompletion= false;

// Pour le hopping et calcul de BOARD_ID
size_t       currentChannelIndex = 0;
unsigned long lastHopTime        = 0;
uint8_t      BOARD_ID            = 0;   // Ser’llera mis à jour à chaque saut

// -----------------------------------------------------------------------------
// 3) Fonctions utilitaires pour la file de fragmentation
// -----------------------------------------------------------------------------

void enqueueFragment(const uint8_t* data, size_t len) {
  int nextEnd = (fragmentQueueEnd + 1) % FRAGMENT_QUEUE_SIZE;
  if (nextEnd == fragmentQueueStart) {
    Serial.println("Fragment queue is full!");
    return;
  }
  memcpy(fragmentQueue[fragmentQueueEnd].data, data, len);
  fragmentQueue[fragmentQueueEnd].len = len;
  fragmentQueueEnd = nextEnd;
}

void sendNextFragment() {
  if (fragmentQueueStart == fragmentQueueEnd) {
    isSending = false;
    return;
  }
  isSending = true;
  esp_err_t result = esp_now_send(
    broadcastAddress,
    fragmentQueue[fragmentQueueStart].data,
    fragmentQueue[fragmentQueueStart].len
  );
  if (result != ESP_OK) {
    Serial.printf("Error sending fragment: %s (%d)\n",
                  esp_err_to_name(result), result);
    isSending = false;
  }
}

// -----------------------------------------------------------------------------
// 4) Réinitialisation de l’état de capture (après envoi)
// -----------------------------------------------------------------------------

void resetCaptureState() {
  firstEAPOLCaptured     = false;
  beaconCaptured         = false;
  allFramesCollected     = false;
  eapolFramesCaptured    = 0;
  memset(apBSSID, 0, sizeof(apBSSID));
  memset(eapolFrames, 0, sizeof(eapolFrames));
  memset(eapolFrameLengths, 0, sizeof(eapolFrameLengths));
  memset(beaconFrame, 0, sizeof(beaconFrame));
  beaconFrameLength      = 0;
}

// -----------------------------------------------------------------------------
// 5) Callback ESP-NOW pour notifier la fin d’envoi d’un fragment
// -----------------------------------------------------------------------------

void onDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("Fragment sent successfully");
    digitalWrite(8, LOW);
    delay(50);
    digitalWrite(8, HIGH);
  } else {
    Serial.printf("Failed to send fragment: %d\n", status);
  }

  // On passe à l'élément suivant dans la file
  fragmentQueueStart = (fragmentQueueStart + 1) % FRAGMENT_QUEUE_SIZE;

  // Si plus rien à envoyer, on arrête l’envoi et on revient en capture
  if (fragmentQueueStart == fragmentQueueEnd) {
    isSending = false;
    if (waitingForSendCompletion) {
      waitingForSendCompletion = false;
      // Retour au canal “d’origine” (1) pour poursuivre la capture
      esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);
      delay(10);
      Serial.printf("Returning to channel %d to continue capture.\n", CHANNEL);
      resetCaptureState();
    }
    return;
  }
  // Sinon, on continue à envoyer le fragment suivant
  sendNextFragment();
}

// -----------------------------------------------------------------------------
// 6) Fonctions de détection paquet (EAPOL / Beacon)
// -----------------------------------------------------------------------------

bool mac_cmp(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

bool isEAPOL(const wifi_promiscuous_pkt_t* pkt) {
  const uint8_t *pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 38) return false;
  uint16_t fc = (pl[1]<<8) | pl[0];
  uint8_t type = (fc & 0x000C)>>2;
  if (type != 2) return false;
  uint8_t subtype = (fc & 0x00F0)>>4;
  bool hasQoS = subtype & 0x08;
  int hdr = 24 + (hasQoS?2:0);
  return pl[hdr]==0xAA && pl[hdr+1]==0xAA && pl[hdr+2]==0x03
      && pl[hdr+6]==0x88 && pl[hdr+7]==0x8E;
}

bool isBeacon(const wifi_promiscuous_pkt_t* pkt) {
  const uint8_t *pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return false;
  uint16_t fc = (pl[1]<<8) | pl[0];
  uint8_t type = (fc & 0x000C)>>2;
  uint8_t subtype = (fc & 0x00F0)>>4;
  return (type==0 && subtype==8);
}

void extractBSSID(const uint8_t* pl, uint16_t fc, uint8_t* bssid) {
  uint8_t type   = (fc & 0x000C)>>2;
  uint8_t toDS   = (fc & 0x0100)>>8;
  uint8_t fromDS = (fc & 0x0200)>>9;
  if (type==0) {
    memcpy(bssid, pl+16, 6);
  } else if (type==2) {
    if (!toDS && !fromDS)        memcpy(bssid, pl+16, 6);
    else if ( toDS && !fromDS)   memcpy(bssid, pl+4,  6);
    else if (!toDS &&  fromDS)   memcpy(bssid, pl+10, 6);
    else                         memset(bssid,0,6);
  } else {
    memset(bssid,0,6);
  }
}

// -----------------------------------------------------------------------------
// 7) Reçoit en mode promiscuous et, si 4 EAPOL + 1 Beacon, déclenche l'envoi
// -----------------------------------------------------------------------------

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t t) {
  if (allFramesCollected) return;
  auto *pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *pl = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  uint16_t fc = (pl[1]<<8)|pl[0];
  uint8_t bssid[6];
  extractBSSID(pl, fc, bssid);

  if (isEAPOL(pkt)) {
    if (!firstEAPOLCaptured) {
      memcpy(apBSSID, bssid, 6);
      firstEAPOLCaptured = true;
      memcpy(eapolFrames[eapolFramesCaptured], pl, len);
      eapolFrameLengths[eapolFramesCaptured++] = len;
      Serial.println("First EAPOL captured!");
    }
    else if (mac_cmp(apBSSID,bssid) && eapolFramesCaptured < MAX_EAPOL_FRAMES) {
      memcpy(eapolFrames[eapolFramesCaptured], pl, len);
      eapolFrameLengths[eapolFramesCaptured++] = len;
      Serial.printf("EAPOL #%d captured!\n", eapolFramesCaptured);
    }
  }
  else if (isBeacon(pkt) && firstEAPOLCaptured && mac_cmp(apBSSID,bssid) && !beaconCaptured) {
    // On enlève les 4 bytes de CRC/Wi-Fi header si nécessaire
    len -= 4;
    memcpy(beaconFrame, pl, len);
    beaconFrameLength = len;
    beaconCaptured = true;
    Serial.println("Beacon frame captured!");
  }

  // Dès qu'on a 4 EAPOL + 1 Beacon, on passe en mode envoi
  if ( firstEAPOLCaptured &&
       eapolFramesCaptured >= MAX_EAPOL_FRAMES &&
       beaconCaptured && !allFramesCollected ) {
    allFramesCollected = true;
    Serial.println("4 EAPOL + 1 Beacon -> ESP-NOW send");

    // 1) On bascule temporairement sur le canal 1 pour envoyer
    esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);
    delay(10);
    Serial.println("Switching to channel 1 for ESP-NOW send");

    // 2) On (re)ajoute le peer broadcast
    if (esp_now_is_peer_exist(broadcastAddress)) {
      esp_now_del_peer(broadcastAddress);
    }
    esp_now_peer_info_t peerInfo = {};
    memcpy(peerInfo.peer_addr, broadcastAddress, 6);
    peerInfo.channel = 0;   // broadcast
    peerInfo.encrypt = false;
    peerInfo.ifidx   = WIFI_IF_STA;
    esp_now_add_peer(&peerInfo);

    waitingForSendCompletion = true;

    // 3) On fragmente la beacon + chaque EAPOL et on les met en file
    //    NB : à ce stade, BOARD_ID a déjà été calculé lors du dernier hop
    uint8_t* dataPtr;
    for (int i = 0; i < eapolFramesCaptured; i++) {
      // d’abord la beacon
      if (i == 0) {
        queueFrameFragments(beaconFrame, beaconFrameLength);
      }
      // puis chaque EAPOL successif
      queueFrameFragments(eapolFrames[i], eapolFrameLengths[i]);
    }
  }
}

// -----------------------------------------------------------------------------
// 8) Fonction qui fragmente un buffer en paquets ESP-NOW et les enfile
// -----------------------------------------------------------------------------

void queueFrameFragments(const uint8_t* data, uint16_t len) {
  uint16_t bytes_sent = 0;
  uint8_t  frag_num   = 0;

  while (bytes_sent < len) {
    uint16_t bytes_to_send = min(MAX_FRAGMENT_SIZE, (uint16_t)(len - bytes_sent));
    wifiFrameFragment.frame_len       = bytes_to_send;
    wifiFrameFragment.fragment_number = frag_num++;
    wifiFrameFragment.last_fragment   = (bytes_sent + bytes_to_send >= len);
    wifiFrameFragment.boardID         = BOARD_ID;   // ← *PRINCIPAL* : on utilise la valeur dynamique

    memcpy(wifiFrameFragment.frame,
           data + bytes_sent,
           bytes_to_send);

    enqueueFragment((uint8_t*)&wifiFrameFragment,
                    sizeof(wifi_frame_fragment_t));
    bytes_sent += bytes_to_send;
  }

  if (!isSending) {
    sendNextFragment();
  }
}

// -----------------------------------------------------------------------------
// 9) Fonction pour passer au canal suivant (et mettre à jour BOARD_ID)
// -----------------------------------------------------------------------------

void hopToNextChannel() {
  currentChannelIndex = (currentChannelIndex + 1) % numChannels;
  uint8_t newPhysicalChannel = channelsToHop[currentChannelIndex];
  esp_wifi_set_channel(newPhysicalChannel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("Hopping slave → channel %d\n", newPhysicalChannel);

  // On cherche l’index dans channelsList[] pour savoir quel BOARD_ID envoyer
  for (size_t i = 0; i < NUM_CHANNELS; i++) {
    if (channelsList[i] == newPhysicalChannel) {
      BOARD_ID = i + 1; 
      break;
    }
  }
}

// -----------------------------------------------------------------------------
// 10) Setup() : initialisation Wi-Fi, ESP-NOW, SD, promiscuous, etc.
// -----------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  pinMode(8, OUTPUT);
  WiFi.mode(WIFI_STA);

  // 10.1) Initialisation ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    return;
  }
  esp_now_register_send_cb(onDataSent);

  // 10.2) Initialisation carte SD (pour pcap)
  if (!SD.begin()) {
    Serial.println("SD card initialization failed");
    // On ne stoppe pas le programme : on peut continuer sans enregistrer de pcap
  } else {
    Serial.println("SD card initialized successfully");
  }

  // 10.3) Handler promiscuous pour sniffer
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

  // 10.4) Démarrage sur le premier canal de channelsToHop (36)
  currentChannelIndex = 0;
  uint8_t firstCh = channelsToHop[0];
  esp_wifi_set_channel(firstCh, WIFI_SECOND_CHAN_NONE);
  Serial.printf("Slave starting hop on channel %d\n", firstCh);

  // 10.5) Calcul du BOARD_ID correspondant à ce premier canal
  for (size_t i = 0; i < NUM_CHANNELS; i++) {
    if (channelsList[i] == firstCh) {
      BOARD_ID = i + 1;
      break;
    }
  }
  lastHopTime = millis();
}

// -----------------------------------------------------------------------------
// 11) Loop() : on fait tourner le hopping tant qu’on n’est pas en train d’envoyer
// -----------------------------------------------------------------------------

void loop() {
  unsigned long now = millis();

  // Si on est en train d’envoyer ou qu’on attend la fin d’envoi, on ne hoppera pas
  if (isSending || waitingForSendCompletion) {
    return;
  }

  // Sinon, on passe au canal suivant si le délai est écoulé
  if (now - lastHopTime >= dwellTimeMs) {
    hopToNextChannel();
    lastHopTime = now;
  }
}
