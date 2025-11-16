#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, glob, argparse, datetime, base64, struct, hashlib, json, sqlite3, webbrowser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# ========= Crypto helpers =========

def sha256(data: bytes) -> bytes:
    h = hashlib.new("sha256")
    h.update(data)
    return h.digest()

def decrypt(enc_data: bytes, algorithm_dkey, mode) -> bytes:
    decryptor = Cipher(algorithm_dkey, mode, default_backend()).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()

def decode_tag(data: bytes):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], "big")
    status = int.from_bytes(data[9:10], "big")
    return {"lat": latitude, "lon": longitude, "conf": confidence, "status": status}

# ========= Keys =========

def load_privkeys(prefix: str = ""):
    base_dir = os.path.dirname(os.path.realpath(__file__))
    privkeys = {}
    names = {}
    for keyfile in glob.glob(os.path.join(base_dir, prefix + "*.keys")):
        hashed_adv = priv = ""
        name = os.path.basename(keyfile)[len(prefix):-5]
        with open(keyfile, "r", encoding="utf-8") as f:
            for line in f:
                k = line.rstrip("\n").split(": ")
                if k[0] == "Private key":
                    priv = k[1]
                elif k[0] == "Hashed adv key":
                    hashed_adv = k[1]
        if priv and hashed_adv:
            privkeys[hashed_adv] = priv
            names[hashed_adv] = name
        else:
            print(f"[WARN] Couldn't find key pair in {keyfile}")
    return privkeys, names

# ========= DB decrypt =========

def decrypt_reports_from_db(hours: int, prefix: str, db_path: str = None, tag_filter: str = None):
    base_dir = os.path.dirname(os.path.realpath(__file__))
    if db_path is None:
        db_path = os.path.join(base_dir, "reports.db")

    privkeys, names = load_privkeys(prefix)

    sq3db = sqlite3.connect(db_path)
    sq3 = sq3db.cursor()

    unix_now = int(datetime.datetime.now().timestamp())
    startdate = unix_now - (60 * 60 * hours)

    query = """
        SELECT id_short, timestamp, payload, id, statusCode
        FROM reports
        WHERE timestamp >= ?
    """
    params = [startdate]
    if tag_filter:
        query += " AND id_short = ?"
        params.append(tag_filter)
    query += " ORDER BY timestamp ASC"

    sq3.execute(query, params)
    rows = sq3.fetchall()
    sq3.close()
    sq3db.close()

    tags = []
    for id_short, timestamp, payload_b64, hashed_id, status_code in rows:
        if hashed_id not in privkeys:
            continue

        priv_int = int.from_bytes(base64.b64decode(privkeys[hashed_id]), "big")
        data = base64.b64decode(payload_b64)

        # Same "fix" as earlier scripts
        if len(data) > 88:
            data = data[:4] + data[5:]

        try:
            eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5:62])
            shared_key = ec.derive_private_key(priv_int, ec.SECP224R1(), default_backend()).exchange(ec.ECDH(), eph_key)
            symmetric_key = sha256(shared_key + b"\x00\x00\x00\x01" + data[5:62])
            decryption_key = symmetric_key[:16]
            iv = symmetric_key[16:]
            enc_data = data[62:72]
            tag_bytes = data[72:]
            decrypted = decrypt(enc_data, algorithms.AES(decryption_key), modes.GCM(iv, tag_bytes))
            tag = decode_tag(decrypted)
        except Exception as e:
            print(f"[WARN] Decrypt failed for {id_short} at {timestamp}: {e}")
            continue

        tag["timestamp"] = timestamp
        tag["isodatetime"] = datetime.datetime.fromtimestamp(timestamp).isoformat()
        tag["key"] = id_short
        tag["goog"] = f"https://maps.google.com/maps?q={tag['lat']},{tag['lon']}"
        tag["statusCode"] = status_code
        tags.append(tag)

    return tags

# ========= HTML generator =========

def generate_html_map(tags, output_file: str = "map.html"):
    if not tags:
        print("[INFO] No decrypted locations to plot.")
        return

    tags_sorted = sorted(tags, key=lambda t: t["timestamp"])
    center_lat = tags_sorted[0]["lat"]
    center_lon = tags_sorted[0]["lon"]
    tag_keys = sorted({t["key"] for t in tags_sorted})
    points_js = json.dumps(tags_sorted, ensure_ascii=False)

    options_html = "\n".join([f'            <option value="{k}">{k}</option>' for k in tag_keys])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>FindMy Forensic Tracker v3</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />

<!-- Leaflet + Heatmap -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>

<style>
:root {{
  --bg: #ffffff;
  --fg: #111111;
  --panel: #f5f5f5;
  --accent: #0a84ff;
  --muted: #888;
}}
.dark {{
  --bg: #0f1115;
  --fg: #e6e6e6;
  --panel: #171a21;
  --accent: #4ea1ff;
  --muted: #aaa;
}}
html, body {{ height: 100%; margin: 0; background: var(--bg); color: var(--fg); font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; }}
#app {{ height: 100%; display: grid; grid-template-columns: 320px 1fr; grid-template-rows: auto 1fr auto; grid-template-areas:
  "top top"
  "side map"
  "controls controls";
}}
#topbar {{ grid-area: top; background: var(--panel); display: flex; gap: 8px; align-items: center; padding: 8px 10px; border-bottom: 1px solid #0001; flex-wrap: wrap; }}
#sidebar {{ grid-area: side; border-right: 1px solid #0001; overflow: auto; background: var(--panel); }}
#map {{ grid-area: map; height: 100%; width: 100%; }}
#controls {{ grid-area: controls; background: var(--panel); padding: 8px 10px; border-top: 1px solid #0001; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
#stats {{ margin-left: auto; color: var(--muted); }}
select, input, button {{ background: var(--bg); color: var(--fg); border: 1px solid #0002; border-radius: 6px; padding: 6px 8px; }}
button.active {{ background: var(--accent); color: white; border-color: var(--accent); }}
button.icon {{ width: 36px; height: 34px; display: inline-grid; place-items: center; }}
#timeSlider {{ width: 320px; }}
.details {{ font-size: 12px; color: var(--muted); }}
.item {{ padding: 8px 10px; border-bottom: 1px solid #0002; cursor: pointer; }}
.item:hover {{ background: #0001; }}
.item .title {{ font-weight: 600; }}
.legend {{ position: absolute; bottom: 10px; right: 10px; background: var(--panel); padding: 6px 8px; border-radius: 6px; box-shadow: 0 0 15px rgba(0,0,0,0.2); font-size: 12px; }}
.color-box {{ display: inline-block; width: 12px; height: 12px; margin-right: 4px; vertical-align: middle; }}
@media (max-width: 1000px) {{
  #app {{ grid-template-columns: 1fr; grid-template-rows: auto auto 1fr auto; grid-template-areas:
    "top"
    "side"
    "map"
    "controls";
  }}
  #sidebar {{ max-height: 240px; }}
}}
</style>
</head>
<body>
<div id="app" class="">
  <div id="topbar">
    <label>Tag:</label>
    <select id="tagSelect">
      <option value="__ALL__">All</option>
{options_html}
    </select>

    <button id="prevPoint" class="icon" title="Previous point">⏮️</button>
    <button id="playPause" class="icon" title="Play/Pause">▶️</button>
    <button id="nextPoint" class="icon" title="Next point">⏭️</button>
    <button id="loopToggle" class="icon" title="Loop">🔁</button>

    <span>Speed:</span>
    <div id="speedButtons" style="display:flex; gap:4px;">
      <button data-speed="0.5">x0.5</button>
      <button data-speed="1">x1</button>
      <button data-speed="2">x2</button>
      <button data-speed="3" class="active">x3</button>
      <button data-speed="4">x4</button>
    </div>

    <button id="jumpBack10" title="-10s">-10s</button>
    <button id="jumpFwd10" title="+10s">+10s</button>
    <button id="resetBtn" title="Reset to start">Reset</button>

    <button id="tileOSM" class="active">OSM</button>
    <button id="tileSAT">Satellite</button>
    <button id="darkMode">Dark</button>
    <button id="heatToggle">Heatmap</button>

    <button id="exportGPX">Export GPX (visible)</button>
    <button id="exportJSON">Export JSON</button>

    <span id="stats">Distance: 0 m | Avg: 0 km/h | Points: 0</span>
  </div>

  <div id="sidebar"></div>
  <div id="map"></div>

  <div id="controls">
    <label>From:</label>
    <input type="datetime-local" id="fromTime">
    <label>To:</label>
    <input type="datetime-local" id="toTime">

    <label>Jump to:</label>
    <input type="datetime-local" id="jumpToTime" title="Jump to specific time">

    <label>Time:</label>
    <input type="range" id="timeSlider" min="0" max="100" value="100" step="1">
    <span id="currentTime" class="details">--</span>
  </div>
</div>

<div class="legend" id="legendBox">
  <div><b>Time color scale</b></div>
  <div><span class="color-box" style="background:hsl(240,100%,50%);"></span>Oldest</div>
  <div><span class="color-box" style="background:hsl(0,100%,50%);"></span>Newest</div>
  <div><span class="color-box" style="border:2px solid #000;background:hsl(0,100%,50%);"></span>Last point</div>
</div>

<script>
// ========= Data =========
const ALL_TAG = "__ALL__";
const allPoints = {points_js};

// ========= Map setup =========
const map = L.map('map').setView([{center_lat}, {center_lon}], 15);
const osm = L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
  maxZoom: 19, attribution: '&copy; OpenStreetMap contributors'
}});
const esriSat = L.tileLayer('https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
  maxZoom: 19, attribution: 'Esri'
}});
osm.addTo(map);

const markerLayer = L.layerGroup().addTo(map);
const polylineLayer = L.layerGroup().addTo(map);
let heatLayer = null; // toggled later

// ========= UI elements =========
const tagSelect = document.getElementById("tagSelect");
const timeSlider = document.getElementById("timeSlider");
const playPauseBtn = document.getElementById("playPause");
const prevBtn = document.getElementById("prevPoint");
const nextBtn = document.getElementById("nextPoint");
const loopToggle = document.getElementById("loopToggle");
const speedButtons = document.querySelectorAll("#speedButtons button");
const currentTimeLabel = document.getElementById("currentTime");
const fromTime = document.getElementById("fromTime");
const toTime = document.getElementById("toTime");
const jumpToTime = document.getElementById("jumpToTime");
const jumpBack10 = document.getElementById("jumpBack10");
const jumpFwd10 = document.getElementById("jumpFwd10");
const resetBtn = document.getElementById("resetBtn");
const tileOSM = document.getElementById("tileOSM");
const tileSAT = document.getElementById("tileSAT");
const darkModeBtn = document.getElementById("darkMode");
const heatToggleBtn = document.getElementById("heatToggle");
const exportGPXBtn = document.getElementById("exportGPX");
const exportJSONBtn = document.getElementById("exportJSON");
const statsEl = document.getElementById("stats");
const sidebar = document.getElementById("sidebar");
const appRoot = document.getElementById("app");

// ========= State =========
let animationInterval = null;
let playbackSpeed = 3; // default x3
let loopMode = false;
let currentIndex = 0;

let filteredByTag = [];
let timeDomain = {{ minTs: 0, maxTs: 0 }};
let currentVisible = []; // points after time-window + slider cut

// ========= Helpers =========
function colorForTimestamp(ts, minT, maxT) {{
  const t = (ts - minT) / Math.max(1, (maxT - minT));
  const hue = 240 - 240 * t;
  return `hsl(${{hue}},100%,50%)`;
}}
function unixToLocalDatetimeValue(ts) {{
  // returns 'YYYY-MM-DDTHH:MM' local
  const d = new Date(ts * 1000);
  const z = new Date(d.getTime() - d.getTimezoneOffset()*60000);
  return z.toISOString().slice(0,16);
}}
function parseDatetimeLocal(val) {{
  if (!val) return null;
  return Math.floor(new Date(val).getTime() / 1000);
}}
function clamp(v,min,max) {{ return Math.min(Math.max(v,min),max); }}
function computeBounds(points) {{
  if (points.length === 0) return null;
  const latlngs = points.map(p => [p.lat, p.lon]);
  return L.latLngBounds(latlngs);
}}
function haversineDistanceMeters(lat1, lon1, lat2, lon2) {{
  const R = 6371000;
  const toRad = x => x * Math.PI / 180;
  const dLat = toRad(lat2-lat1);
  const dLon = toRad(lon2-lon1);
  const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;
  return 2*R*Math.asin(Math.sqrt(a));
}}
function sumDistance(points) {{
  let d = 0;
  for (let i=0;i<points.length-1;i++) {{
    d += haversineDistanceMeters(points[i].lat, points[i].lon, points[i+1].lat, points[i+1].lon);
  }}
  return d;
}}
function avgSpeedKmh(points) {{
  if (points.length < 2) return 0;
  const dt = (points[points.length-1].timestamp - points[0].timestamp) / 3600.0;
  const distKm = sumDistance(points)/1000.0;
  if (dt <= 0) return 0;
  return distKm/dt;
}}
function updateStats(points) {{
  const d = sumDistance(points);
  const avg = avgSpeedKmh(points);
  statsEl.textContent = `Distance: ${{d.toFixed(0)}} m | Avg: ${{avg.toFixed(2)}} km/h | Points: ${{points.length}}`;
}}

// ========= Rendering =========
function drawPolyline(points, minT, maxT) {{
  for (let i = 0; i < points.length - 1; i++) {{
    const p1 = points[i], p2 = points[i+1];
    const color = colorForTimestamp(p1.timestamp, minT, maxT);
    L.polyline([[p1.lat,p1.lon],[p2.lat,p2.lon]], {{ color, weight: 3, opacity: 0.85 }}).addTo(polylineLayer);
  }}
}}
function renderSidebar(points) {{
  sidebar.innerHTML = "";
  points.forEach((p, idx) => {{
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <div class="title">${{p.key}} — #${{idx+1}}</div>
      <div class="details">${{p.isodatetime}}</div>
      <div class="details">${{p.lat.toFixed(6)}}, ${{p.lon.toFixed(6)}} | conf ${{p.conf}}</div>
    `;
    div.addEventListener("click", () => {{
      currentIndex = idx;
      timeSlider.value = p.timestamp;
      updateTimeFilter(p.timestamp, true);
    }});
    sidebar.appendChild(div);
  }});
}}

function applyFiltersForKey(key) {{
  // Tag filter
  filteredByTag = allPoints.filter(p => key === ALL_TAG || p.key === key);
  if (filteredByTag.length === 0) {{
    timeDomain.minTs = 0;
    timeDomain.maxTs = 0;
    return;
  }}
  timeDomain.minTs = Math.min(...filteredByTag.map(p => p.timestamp));
  timeDomain.maxTs = Math.max(...filteredByTag.map(p => p.timestamp));

  // Set time inputs defaults (full range)
  fromTime.value = unixToLocalDatetimeValue(timeDomain.minTs);
  toTime.value = unixToLocalDatetimeValue(timeDomain.maxTs);

  // Slider domain
  timeSlider.min = timeDomain.minTs;
  timeSlider.max = timeDomain.maxTs;
  timeSlider.value = timeDomain.maxTs;

  updateTimeFilter(timeDomain.maxTs, true);
  renderSidebar(filteredByTag);
}}

function updateTimeFilter(tsLimit, fitBounds=false) {{
  markerLayer.clearLayers();
  polylineLayer.clearLayers();

  if (filteredByTag.length === 0) return;

  const fromTs = parseDatetimeLocal(fromTime.value) ?? timeDomain.minTs;
  const toTs = parseDatetimeLocal(toTime.value) ?? timeDomain.maxTs;

  const timeWindow = filteredByTag.filter(p => p.timestamp >= fromTs && p.timestamp <= toTs);
  const visible = timeWindow.filter(p => p.timestamp <= tsLimit);

  currentVisible = visible;

  if (visible.length === 0) {{
    currentTimeLabel.textContent = "--";
    updateStats([]);
    return;
  }}

  const minT = Math.min(...timeWindow.map(p => p.timestamp));
  const maxT = Math.max(...timeWindow.map(p => p.timestamp));
  const last = visible[visible.length - 1];

  currentTimeLabel.textContent = new Date(tsLimit*1000).toISOString().replace('T',' ').split('.')[0] + "Z";

  // Polylines with time-gradient
  drawPolyline(visible, minT, maxT);

  // Markers
  visible.forEach(p => {{
    const color = colorForTimestamp(p.timestamp, minT, maxT);
    const isLast = (p.timestamp === last.timestamp);
    L.circleMarker([p.lat, p.lon], {{
      radius: isLast ? 8 : 4,
      color: isLast ? "#000" : color,
      fillColor: color,
      fillOpacity: isLast ? 0.9 : 0.7,
      weight: isLast ? 3 : 1.5
    }}).addTo(markerLayer)
      .bindPopup(`<b>${{p.key}}</b><br>${{p.isodatetime}}<br>${{p.lat.toFixed(6)}}, ${{p.lon.toFixed(6)}}<br>Conf: ${{p.conf}} | Status: ${{p.status}}<br><a target="_blank" href="https://maps.google.com/maps?q=${{p.lat}},${{p.lon}}">Open in Google Maps</a>`);
  }});

  // Heatmap (if enabled)
  if (heatLayer && map.hasLayer(heatLayer)) {{
    const heatData = timeWindow.map(p => [p.lat, p.lon, Math.max(0.2, Math.min(1.0, p.conf/10))]);
    heatLayer.setLatLngs(heatData);
  }}

  // Fit bounds if requested
  if (fitBounds) {{
    const b = computeBounds(timeWindow);
    if (b) map.fitBounds(b.pad(0.08));
  }}

  // Update current index near tsLimit
  const nearest = timeWindow.findIndex(p => p.timestamp >= tsLimit);
  if (nearest >= 0) currentIndex = nearest;

  // Update stats
  updateStats(visible);
}}

// ========= Controls =========
tagSelect.addEventListener("change", () => applyFiltersForKey(tagSelect.value));

timeSlider.addEventListener("input", e => {{
  const ts = parseInt(e.target.value);
  updateTimeFilter(ts);
}});

playPauseBtn.addEventListener("click", () => {{
  if (animationInterval) {{
    clearInterval(animationInterval); animationInterval = null; playPauseBtn.textContent = "▶️";
  }} else {{
    playPauseBtn.textContent = "⏸️";
    let t = parseInt(timeSlider.value);
    animationInterval = setInterval(() => {{
      const step = Math.max(1, ((timeDomain.maxTs - timeDomain.minTs) / 200)) * playbackSpeed;
      t += step;
      if (t >= timeDomain.maxTs) {{
        if (loopMode) {{
          t = timeDomain.minTs;
        }} else {{
          clearInterval(animationInterval); animationInterval = null; playPauseBtn.textContent = "▶️"; return;
        }}
      }}
      timeSlider.value = t;
      updateTimeFilter(t);
    }}, 100);
  }}
}});

prevBtn.addEventListener("click", () => {{
  if (filteredByTag.length === 0) return;
  const fromTs = parseDatetimeLocal(fromTime.value) ?? timeDomain.minTs;
  const toTs = parseDatetimeLocal(toTime.value) ?? timeDomain.maxTs;
  const windowPts = filteredByTag.filter(p => p.timestamp >= fromTs && p.timestamp <= toTs);
  currentIndex = Math.max(0, currentIndex - 1);
  const ts = windowPts.length ? windowPts[currentIndex].timestamp : timeDomain.minTs;
  timeSlider.value = ts;
  updateTimeFilter(ts, false);
}});

nextBtn.addEventListener("click", () => {{
  if (filteredByTag.length === 0) return;
  const fromTs = parseDatetimeLocal(fromTime.value) ?? timeDomain.minTs;
  const toTs = parseDatetimeLocal(toTime.value) ?? timeDomain.maxTs;
  const windowPts = filteredByTag.filter(p => p.timestamp >= fromTs && p.timestamp <= toTs);
  currentIndex = Math.min(windowPts.length - 1, currentIndex + 1);
  const ts = windowPts.length ? windowPts[currentIndex].timestamp : timeDomain.maxTs;
  timeSlider.value = ts;
  updateTimeFilter(ts, false);
}});

loopToggle.addEventListener("click", () => {{
  loopMode = !loopMode;
  loopToggle.classList.toggle("active", loopMode);
}});

speedButtons.forEach(btn => {{
  btn.addEventListener("click", () => {{
    playbackSpeed = parseFloat(btn.dataset.speed);
    speedButtons.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
  }});
}});

jumpBack10.addEventListener("click", () => {{
  const v = parseInt(timeSlider.value) - 10;
  timeSlider.value = clamp(v, timeDomain.minTs, timeDomain.maxTs);
  updateTimeFilter(parseInt(timeSlider.value));
}});
jumpFwd10.addEventListener("click", () => {{
  const v = parseInt(timeSlider.value) + 10;
  timeSlider.value = clamp(v, timeDomain.minTs, timeDomain.maxTs);
  updateTimeFilter(parseInt(timeSlider.value));
}});
resetBtn.addEventListener("click", () => {{
  timeSlider.value = timeDomain.minTs;
  updateTimeFilter(timeDomain.minTs, true);
}});

tileOSM.addEventListener("click", () => {{
  map.removeLayer(esriSat); if (!map.hasLayer(osm)) osm.addTo(map);
  tileOSM.classList.add("active"); tileSAT.classList.remove("active");
}});
tileSAT.addEventListener("click", () => {{
  map.removeLayer(osm); if (!map.hasLayer(esriSat)) esriSat.addTo(map);
  tileSAT.classList.add("active"); tileOSM.classList.remove("active");
}});

darkModeBtn.addEventListener("click", () => {{
  appRoot.classList.toggle("dark");
  darkModeBtn.classList.toggle("active", appRoot.classList.contains("dark"));
}});

heatToggleBtn.addEventListener("click", () => {{
  if (!heatLayer) {{
    heatLayer = L.heatLayer([], {{ radius: 25, blur: 15, maxZoom: 17 }});
  }}

  // Toggle on/off
  const isActive = map.hasLayer(heatLayer);
  if (isActive) {{
    map.removeLayer(heatLayer);
    heatToggleBtn.classList.remove("active");
    // Restore normal display
    updateTimeFilter(parseInt(timeSlider.value), false);
  }} else {{
    heatLayer.addTo(map);
    heatToggleBtn.classList.add("active");

    // Hide markers & polylines while heatmap active
    markerLayer.clearLayers();
    polylineLayer.clearLayers();

    const fromTs = parseDatetimeLocal(fromTime.value) ?? timeDomain.minTs;
    const toTs = parseDatetimeLocal(toTime.value) ?? timeDomain.maxTs;
    const timeWindow = filteredByTag.filter(p => p.timestamp >= fromTs && p.timestamp <= toTs);

    const heatData = timeWindow.map(p => [p.lat, p.lon, Math.max(0.2, Math.min(1.0, p.conf / 10))]);
    heatLayer.setLatLngs(heatData);
  }}
}});


// Time window filter
[fromTime, toTime].forEach(el => el.addEventListener("change", () => {{
  const fromTs = parseDatetimeLocal(fromTime.value) ?? timeDomain.minTs;
  const toTs = parseDatetimeLocal(toTime.value) ?? timeDomain.maxTs;
  // clamp slider into new window if needed
  timeSlider.value = clamp(parseInt(timeSlider.value), fromTs, toTs);
  updateTimeFilter(parseInt(timeSlider.value), true);
}}));

// Jump to time
jumpToTime.addEventListener("change", () => {{
  if (!jumpToTime.value) return;
  const ts = parseDatetimeLocal(jumpToTime.value);
  if (ts == null) return;
  const clamped = clamp(ts, timeDomain.minTs, timeDomain.maxTs);
  timeSlider.value = clamped;
  updateTimeFilter(clamped, true);
}});

// Keyboard hotkeys
document.addEventListener("keydown", (e) => {{
  if (e.code === "Space") {{ e.preventDefault(); playPauseBtn.click(); }}
  if (e.code === "ArrowLeft") {{ e.preventDefault(); prevBtn.click(); }}
  if (e.code === "ArrowRight") {{ e.preventDefault(); nextBtn.click(); }}
}});

// Export GPX (visible window)
exportGPXBtn.addEventListener("click", () => {{
  if (!currentVisible.length) return;
  const name = (tagSelect.value === "__ALL__" ? "All" : tagSelect.value) + " visible";
  const trkpts = currentVisible.map(p => `      <trkpt lat="${{p.lat}}" lon="${{p.lon}}"><time>${{new Date(p.timestamp*1000).toISOString()}}</time></trkpt>`).join("\\n");
  const gpx = `<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="FindMy Forensic v3" xmlns="http://www.topografix.com/GPX/1/1">
  <trk>
    <name>${{name}}</name>
    <trkseg>
${{trkpts}}
    </trkseg>
  </trk>
</gpx>`;
  const blob = new Blob([gpx], {{type:"application/gpx+xml"}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "track_visible.gpx"; a.click();
  URL.revokeObjectURL(url);
}});

// Export JSON (choose visible or all)
exportJSONBtn.addEventListener("click", () => {{
  const useVisible = confirm("Export only VISIBLE points? Click Cancel to export ALL points.");
  const data = useVisible ? currentVisible : (tagSelect.value === "__ALL__" ? allPoints : allPoints.filter(p => p.key === tagSelect.value));
  const blob = new Blob([JSON.stringify(data, null, 2)], {{type:"application/json"}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = useVisible ? "points_visible.json" : "points_all.json"; a.click();
  URL.revokeObjectURL(url);
}});

// Init
applyFiltersForKey("{'__ALL__'}");
</script>
</body>
</html>
"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] HTML map written to", output_file)

# ========= CLI =========

def main():
    parser = argparse.ArgumentParser(
        description="Generate a single-file interactive HTML map (FindMy Forensic Tracker v3).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  # All tags, last 24h
  python findmy_forensic_v3.py -H 24

  # Only tag aACohBi, last 48h
  python findmy_forensic_v3.py -H 48 -k aACohBi

  # Custom DB path, only last positions per tag, auto-open
  python findmy_forensic_v3.py --db /path/to/reports.db --last-only --open
        """
    )
    parser.add_argument("-H", "--hours", type=int, default=24, help="Only use reports newer than this many hours")
    parser.add_argument("-p", "--prefix", default="", help="Prefix for .keys files")
    parser.add_argument("-k", "--tag", default=None, help="Filter by tag short name (id_short)")
    parser.add_argument("-d", "--db", default=None, help="Path to reports.db (default: ./reports.db)")
    parser.add_argument("-o", "--output", default="map.html", help="Output HTML file (default: map.html)")
    parser.add_argument("--last-only", action="store_true", help="Keep only last known location per tag")
    parser.add_argument("--open", dest="open_browser", action="store_true", help="Open generated HTML in default browser")
    args = parser.parse_args()

    tags = decrypt_reports_from_db(args.hours, args.prefix, args.db, args.tag)

    if args.last_only and tags:
        latest_by_key = {}
        for t in tags:
            k = t["key"]
            if k not in latest_by_key or t["timestamp"] > latest_by_key[k]["timestamp"]:
                latest_by_key[k] = t
        tags = sorted(latest_by_key.values(), key=lambda t: t["timestamp"])

    print(f"[INFO] Decrypted {len(tags)} positions.")
    if tags:
        print(f"[INFO] First:  {tags[0]['isodatetime']} -> {tags[0]['lat']}, {tags[0]['lon']}")
        print(f"[INFO] Last:   {tags[-1]['isodatetime']} -> {tags[-1]['lat']}, {tags[-1]['lon']}")

    generate_html_map(tags, args.output)

    if args.open_browser and tags:
        html_path = os.path.abspath(args.output)
        url = "file://" + html_path
        print(f"[INFO] Opening {url}")
        webbrowser.open(url)

if __name__ == "__main__":
    main()
