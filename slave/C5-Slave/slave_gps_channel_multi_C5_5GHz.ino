#include <esp_now.h>
#include <WiFi.h>

// Keep as all zeroes so we do a broadcast
uint8_t broadcastAddress[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
esp_now_peer_info_t peerInfo;

// Number of MAC addresses to track
#define mac_history_len 100

struct mac_addr {
  unsigned char bytes[6];
};
struct mac_addr mac_history[mac_history_len];
unsigned int mac_history_cursor = 0;

// Structure example to send data
typedef struct struct_message {
  char bssid[64];
  char ssid[32];
  char encryptionType[16];
  int32_t channel;
  int32_t rssi;
  int boardID;
} struct_message;

// Create a struct_message called myData
struct_message myData;

unsigned long lastTime = 0;
unsigned long timerDelay = 10;  // send readings timer

// List of channels for hopping (user can modify this)
int channelList[] = {
//2.4ghz  
1,2,3,4,5,6,7,8,9,10,11,12,13,14,

//5ghz  
36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

int numChannels = sizeof(channelList) / sizeof(channelList[0]);

// Callback when data is sent (new signature in recent ESP-NOW)
void OnDataSent(const wifi_tx_info_t *tx_info, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println((status == ESP_NOW_SEND_SUCCESS) ? "Delivery Success" : "Delivery Fail");
}

void save_mac(unsigned char *mac) {
  if (mac_history_cursor >= mac_history_len) {
    mac_history_cursor = 0;
  }
  struct mac_addr tmp;
  for (int x = 0; x < 6; x++) {
    tmp.bytes[x] = mac[x];
  }

  mac_history[mac_history_cursor] = tmp;
  mac_history_cursor++;
  Serial.print("Mac history length: ");
  Serial.println(mac_history_cursor);
}

boolean seen_mac(unsigned char *mac) {
  struct mac_addr tmp;
  for (int x = 0; x < 6; x++) {
    tmp.bytes[x] = mac[x];
  }

  for (int x = 0; x < mac_history_len; x++) {
    // compare tmp vs mac_history[x]
    boolean match = true;
    for (int y = 0; y < 6; y++) {
      if (tmp.bytes[y] != mac_history[x].bytes[y]) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

void setup() {
  pinMode(8, OUTPUT);  // Définir la broche en sortie

  // Init Serial Monitor
  Serial.begin(115200);

  pinMode(2, OUTPUT);       // Setup built-in LED
  WiFi.mode(WIFI_STA);      // Set device as a Wi-Fi Station

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Register the new‐style callback
  esp_now_register_send_cb(OnDataSent);

  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  // Add peer
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Failed to add peer");
    return;
  }
}

void loop() {
  if ((millis() - lastTime) > timerDelay) {
    for (int i = 0; i < numChannels; i++) {  // Loop through the selected channels
      int channel = channelList[i];          
      int n = WiFi.scanNetworks(false, true, false, 500, channel);
      if (n == 0) {
        Serial.print("No networks found on channel ");
        Serial.println(channel);
      } else {
        for (int8_t j = 0; j < n; j++) {  // renamed inner loop to j
          if (seen_mac(WiFi.BSSID(j))) {
            Serial.println("Already seen this MAC");
            continue;
          }

          String MacString = WiFi.BSSIDstr(j);
          MacString.toCharArray(myData.bssid, 64);

          String AP = WiFi.SSID(j);
          AP.toCharArray(myData.ssid, 32);

          // Set encryption type
          String EncTy;
          switch (WiFi.encryptionType(j)) {
            case WIFI_AUTH_OPEN:
              EncTy = "Open";
              break;
            case WIFI_AUTH_WEP:
              EncTy = "WEP";
              break;
            case WIFI_AUTH_WPA_PSK:
              EncTy = "WPA PSK";
              break;
            case WIFI_AUTH_WPA2_PSK:
              EncTy = "WPA2 PSK";
              break;
            case WIFI_AUTH_WPA_WPA2_PSK:
              EncTy = "WPA/WPA2 PSK";
              break;
            case WIFI_AUTH_WPA2_ENTERPRISE:
              EncTy = "WPA2 Enterprise";
              break;
            default:
              EncTy = "Unknown";
              break;
          }
          EncTy.toCharArray(myData.encryptionType, 16);

          myData.channel = channel;    // Store current channel
          myData.rssi = WiFi.RSSI(j);
          myData.boardID = channel;    // Set boardID equal to channel number

          Serial.print("Sending data for channel ");
          Serial.println(channel);

          save_mac(WiFi.BSSID(j));
          esp_now_send(broadcastAddress, (uint8_t *)&myData, sizeof(myData));
          digitalWrite(8, LOW);
          delay(50);
          digitalWrite(8, HIGH);
        }
      }
    }
    lastTime = millis();
  }
}
