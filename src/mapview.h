// ============================================================================
//  mapview.h - Vue carte OFFLINE + tracking de position facon Strava.
//  Tuiles 256x256 PNG dans /evil/maps/{z}/{x}/{y}.png (preparees par tools/
//  map_tiles_downloader.py). Dessin direct via M5GFX drawPngFile (pas de gros
//  framebuffer -> OK sans PSRAM). Superpose : position GPS, geofences, et la
//  TRACE enregistree (distance + vitesse), exportable en GPX (Strava/Komoot).
//  Touches : fleches (;/./,//) = pan, = / - = zoom, g = suivi, r = rec, DEL = sortie.
//  Appele depuis geofenceMenu() (wigle_geofence.h) -> cf. declaration anticipee.
// ============================================================================
#pragma once
#include <math.h>
#include <time.h>
#include <SD.h>

extern TinyGPSPlus gps;            // defini dans le .ino
extern HardwareSerial cardgps;     // UART GPS

namespace mapview {

static const int TILE = 256;
static const int ZMIN = 13, ZMAX = 17;      // niveaux telecharges (voir tools/map_tiles_downloader.py)
static const int MAXTRK = 1200;             // points de trace max (heap, ~9.6 Ko)

// Epoch UTC (secondes) depuis la date/heure GPS, pour horodater chaque point GPX.
// 0 = pas d'heure GPS valide (le <time> est alors omis sur ce point). Algo days-from-civil
// (H. Hinnant), independant du fuseau : l'heure GPS est deja de l'UTC.
static uint32_t mvGpsEpoch() {
  if (!gps.date.isValid() || !gps.time.isValid() || gps.date.year() < 2020) return 0;
  int y = gps.date.year(), m = gps.date.month(), d = gps.date.day();
  int hh = gps.time.hour(), mm = gps.time.minute(), ss = gps.time.second();
  y -= (m <= 2);
  long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  long days = era * 146097L + (long)doe - 719468L;
  return (uint32_t)(days * 86400L + hh * 3600L + mm * 60L + ss);
}

static void deg2tilef(double lat, double lon, int z, double& xf, double& yf) {
  double n = (double)(1 << z);
  xf = (lon + 180.0) / 360.0 * n;
  yf = (1.0 - asinh(tan(lat * M_PI / 180.0)) / M_PI) / 2.0 * n;
}
static void tilef2deg(double xf, double yf, int z, double& lat, double& lon) {
  double n = (double)(1 << z);
  lon = xf / n * 360.0 - 180.0;
  lat = atan(sinh(M_PI * (1.0 - 2.0 * yf / n))) * 180.0 / M_PI;
}

// Vue carte. startLat/startLon = centre initial (ex Caen si pas de fix GPS).
// Base des tuiles : /evil/maps si present, sinon /maps (robuste a une migration SD.rename ratee).
static inline const char* tileBase() { return SD.exists("/evil/maps") ? "/evil/maps" : "/maps"; }

void mapViewUI(double startLat, double startLon) {
  auto& d = M5Cardputer.Display;
  // Migration des tuiles vers /evil/maps (tout sous /evil). SD.rename = instantane (entree de
  // repertoire, pas de copie) et marche meme si l'hote a laisse le FAT "dirty"/RO.
  if (SD.exists("/maps") && !SD.exists("/evil/maps")) {
    d.fillScreen(TFT_BLACK); d.setTextColor(TFT_CYAN, TFT_BLACK); d.setTextSize(1);
    d.setCursor(6, 40); d.print("Migrating /maps -> /evil/maps ...");
    SD.mkdir("/evil");
    SD.rename("/maps", "/evil/maps");
  }
  const char* mb = tileBase();                 // /evil/maps ou /maps (fallback)
  const int W = d.width(), H = d.height();
  int z = 16;
  double cLat = startLat, cLon = startLon;
  bool followGps = true;
  GeoCtx geo = geoLoad();
  bool need = true; uint32_t lastGps = 0;
  char banner[48] = ""; uint32_t bannerUntil = 0; uint16_t bannerCol = TFT_GREEN;  // feedback entree/sortie zone

  // trace (heap -> aucun impact RAM au boot)
  float* tLat = (float*)malloc(MAXTRK * sizeof(float));
  float* tLon = (float*)malloc(MAXTRK * sizeof(float));
  uint32_t* tTime = (uint32_t*)malloc(MAXTRK * sizeof(uint32_t));   // epoch UTC/point (0 = pas d'heure)
  bool trkOk = (tLat && tLon && tTime);
  int tN = 0; bool rec = false; double distM = 0.0; float lastSpd = 0.0f;

  auto pan = [&](int dpx, int dpy) {
    double xf, yf; deg2tilef(cLat, cLon, z, xf, yf);
    xf += (double)dpx / TILE; yf += (double)dpy / TILE;
    tilef2deg(xf, yf, z, cLat, cLon);
    followGps = false; need = true;
  };

  // double buffer : on dessine tout dans un sprite off-screen puis push -> zero flicker.
  // repli si la RAM manque (createSprite echoue) : dessin direct SANS clear (on reecrit par-dessus).
  M5Canvas cv(&d);
  cv.setColorDepth(16); bool spr = cv.createSprite(W, H);   // 64 Ko : plein ecran, vraie couleur
  if (!spr) { cv.setColorDepth(8); spr = cv.createSprite(W, H); }  // repli 32 Ko (RAM) : double-buffer quand meme, 256 couleurs
  lgfx::LovyanGFX* g = spr ? (lgfx::LovyanGFX*)&cv : (lgfx::LovyanGFX*)&d;

  for (;;) {
    while (cardgps.available()) gps.encode(cardgps.read());
    bool fix = gps.location.isValid();
    double gLat = fix ? gps.location.lat() : 0, gLon = fix ? gps.location.lng() : 0;
    if (fix && gps.speed.isValid()) lastSpd = gps.speed.kmph();

    // geofence : detection entree/sortie (meme geoCheck que le check de fond) + action
    if (fix) {
      char zn[24] = "", za[28] = "";
      int ev = geoCheck(geo, (float)gLat, (float)gLon, zn, sizeof(zn), za, sizeof(za));
      if (ev != 0) {
        char iso[25] = ""; uint32_t ep = mvGpsEpoch();   // horodatage UTC de l'entree/sortie de zone
        if (ep) { time_t tt = (time_t)ep; struct tm tmv; gmtime_r(&tt, &tmv); strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tmv); }
        geoLogEvent(zn, ev, (float)gLat, (float)gLon, iso[0] ? iso : nullptr);
        bannerCol = (ev > 0) ? TFT_GREEN : TFT_ORANGE;
        snprintf(banner, sizeof(banner), "%s zone: %s", ev > 0 ? "ENTER" : "EXIT", zn);
        bannerUntil = millis() + 2500; need = true;
        if (ev > 0 && za[0]) {                      // zone avec action -> on la lance
          d.fillRect(0, H / 2 - 14, W, 28, TFT_DARKGREEN);
          d.setTextColor(TFT_WHITE, TFT_DARKGREEN); d.setTextSize(1);
          d.setCursor(6, H / 2 - 6); d.printf("ENTER %s -> %s", zn, za);
          delay(900);
          ::runByName(za);                          // lance le module (bloquant), retour carte ensuite
          need = true;
        }
      }
    }

    // enregistrement : nouveau point si on a bouge de >5 m
    if (rec && trkOk && fix) {
      if (tN == 0) { tLat[tN] = gLat; tLon[tN] = gLon; tTime[tN] = mvGpsEpoch(); tN++; need = true; }
      else {
        double seg = geoDistM(tLat[tN - 1], tLon[tN - 1], gLat, gLon);
        if (seg >= 5.0 && tN < MAXTRK) { distM += seg; tLat[tN] = gLat; tLon[tN] = gLon; tTime[tN] = mvGpsEpoch(); tN++; need = true; }
      }
    }
    if (followGps && fix && millis() - lastGps > 1200) { cLat = gLat; cLon = gLon; lastGps = millis(); need = true; }
    if (banner[0] && millis() >= bannerUntil) { banner[0] = 0; need = true; }  // efface la banniere expiree

    if (need) {
      need = false;
      if (!spr) d.startWrite();
      if (spr) g->fillScreen(TFT_BLACK);     // clear UNIQUEMENT l'off-screen (direct: tuiles reecrivent par-dessus)
      double xf, yf; deg2tilef(cLat, cLon, z, xf, yf);
      int tx0 = (int)floor(xf), ty0 = (int)floor(yf);
      int missing = 0;
      for (int tx = tx0 - 1; tx <= tx0 + 1; tx++)
        for (int ty = ty0 - 1; ty <= ty0 + 1; ty++) {
          int sx = (int)lround(W / 2.0 - (xf - tx) * TILE);
          int sy = (int)lround(H / 2.0 - (yf - ty) * TILE);
          if (sx <= -TILE || sx >= W || sy <= -TILE || sy >= H) continue;
          char pj[56], pp[56];
          snprintf(pj, sizeof(pj), "%s/%d/%d/%d.jpg", mb, z, tx, ty);   // satellite (ESRI, JPEG)
          snprintf(pp, sizeof(pp), "%s/%d/%d/%d.png", mb, z, tx, ty);   // street (OSM, PNG)
          if (SD.exists(pj)) g->drawJpgFile(SD, pj, sx, sy);
          else if (SD.exists(pp)) g->drawPngFile(SD, pp, sx, sy);
          else { missing++; g->fillRect(sx < 0 ? 0 : sx, sy < 0 ? 0 : sy, TILE, TILE, 0x2104); }
        }
      // trace (polyligne projetee)
      if (trkOk && tN > 1) {
        int px0 = 0, py0 = 0; bool have = false;
        for (int i = 0; i < tN; i++) {
          double gx, gy; deg2tilef(tLat[i], tLon[i], z, gx, gy);
          int px = (int)lround(W / 2.0 + (gx - xf) * TILE);
          int py = (int)lround(H / 2.0 + (gy - yf) * TILE);
          if (have && !(px0 < -5 && px < -5) && !(px0 > W + 5 && px > W + 5))
            g->drawLine(px0, py0, px, py, TFT_MAGENTA);
          px0 = px; py0 = py; have = true;
        }
      }
      // geofences
      for (int i = 0; i < geo.count; i++) {
        double gx, gy; deg2tilef(geo.zones[i].lat, geo.zones[i].lon, z, gx, gy);
        int px = (int)lround(W / 2.0 + (gx - xf) * TILE);
        int py = (int)lround(H / 2.0 + (gy - yf) * TILE);
        if (px < -30 || px > W + 30 || py < -30 || py > H + 30) continue;
        double mPerTile = 40075016.686 * cos(geo.zones[i].lat * M_PI / 180.0) / (double)(1 << z);
        int rpx = (int)(geo.zones[i].radius / mPerTile * TILE);
        if (rpx > 2 && rpx < 500) g->drawCircle(px, py, rpx, TFT_ORANGE);
        g->fillCircle(px, py, 3, TFT_ORANGE);
      }
      // marqueur position (centre)
      if (fix) { g->fillCircle(W / 2, H / 2, 4, followGps ? TFT_RED : TFT_BLUE); g->drawCircle(W / 2, H / 2, 6, TFT_WHITE); }
      else { g->drawLine(W/2-5, H/2, W/2+5, H/2, TFT_RED); g->drawLine(W/2, H/2-5, W/2, H/2+5, TFT_RED); }
      // barre haut : zoom / gps / suivi / manquant
      g->fillRect(0, 0, W, 12, menuSelectedBackgroundColor);
      g->setTextColor(menuTextFocusedColor, menuSelectedBackgroundColor); g->setTextSize(1); g->setCursor(2, 2);
      g->printf("z%d %s %s", z, fix ? "GPS" : "no-fix", followGps ? "follow" : "free");
      if (!followGps && fix) { g->setTextColor(TFT_CYAN, menuSelectedBackgroundColor); g->print("  g=GPS"); }  // revenir au point GPS
      if (missing) { g->setTextColor(TFT_ORANGE, menuSelectedBackgroundColor); g->setCursor(W - 60, 2); g->printf("%d miss", missing); }
      // bottom bar : track (dist / speed / rec)
      g->fillRect(0, H - 10, W, 10, menuSelectedBackgroundColor);
      g->setTextColor(rec ? TFT_RED : menuTextUnFocusedColor, menuSelectedBackgroundColor); g->setCursor(2, H - 9);
      if (trkOk) g->printf("%s %.2fkm %.0fkm/h  =/-zoom r=rec", rec ? "REC" : "---", distM / 1000.0, lastSpd);
      else g->print("track n/a (RAM)  =/- zoom  DEL exit");
      // banniere entree/sortie de zone
      if (banner[0] && millis() < bannerUntil) {
        g->fillRoundRect(8, 15, W - 16, 18, 4, bannerCol);
        g->setTextColor(TFT_BLACK, bannerCol); g->setTextSize(1);
        g->setCursor(14, 20); g->print(banner);
      }
      if (spr) cv.pushSprite(0, 0);          // 1 seul transfert ecran -> pas de flicker
      else d.endWrite();
    }

    cardUpdate();
    if (kp('`') || kp(KEY_BACKSPACE)) { backDebounce(); break; }
    if (kp('=') || kp('+')) { if (z < ZMAX) { z++; need = true; } delay(160); }
    if (kp('-') || kp('_')) { if (z > ZMIN) { z--; need = true; } delay(160); }
    if (kp('g')) { followGps = !followGps;                 // g = revenir a ma position GPS / suivi
                   if (followGps && fix) { cLat = gLat; cLon = gLon; lastGps = millis(); }  // recentrage immediat
                   need = true; delay(220); }
    if (kp('r')) { rec = !rec; need = true; delay(240); }
    if (kp(';')) { pan(0, -48); delay(80); }
    if (kp('.')) { pan(0, +48); delay(80); }
    if (kp(',')) { pan(-48, 0); delay(80); }
    if (kp('/')) { pan(+48, 0); delay(80); }
    delay(8);
  }
  if (spr) cv.deleteSprite();

  // export GPX de la trace (importable Strava / Komoot / etc.)
  if (trkOk && tN > 1) {
    SD.mkdir("/evil"); SD.mkdir("/evil/tracks");
    char fn[48]; int k = 0;
    do { snprintf(fn, sizeof(fn), "/evil/tracks/trk_%03d.gpx", k++); } while (SD.exists(fn) && k < 1000);
    File f = SD.open(fn, FILE_WRITE);
    if (f) {
      f.print(F("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<gpx version=\"1.1\" creator=\"EvilCardputer\" xmlns=\"http://www.topografix.com/GPX/1/1\">\n<trk><name>EvilCardputer</name><trkseg>\n"));
      for (int i = 0; i < tN; i++) {
        f.printf("<trkpt lat=\"%.6f\" lon=\"%.6f\">", (double)tLat[i], (double)tLon[i]);
        if (tTime[i]) {                                   // horodatage UTC si l'heure GPS etait valide
          time_t tt = (time_t)tTime[i]; struct tm tmv; gmtime_r(&tt, &tmv);
          char ts[25]; strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tmv);
          f.printf("<time>%s</time>", ts);
        }
        f.print("</trkpt>\n");
      }
      f.print(F("</trkseg></trk></gpx>\n"));
      f.close();
      d.fillScreen(TFT_BLACK); d.setTextColor(TFT_GREEN, TFT_BLACK); d.setCursor(4, 40);
      d.printf("GPX track saved:\n %s\n %d pts  %.2f km", fn, tN, distM / 1000.0);
      delay(2200);
    }
  }
  if (tLat) free(tLat);
  if (tLon) free(tLon);
  if (tTime) free(tTime);
  geoFree(geo);
}

} // namespace mapview
