#!/usr/bin/env python3
"""
Pygle - offline wardriving map generator (Wigle-like, no upload).

Reads a WigleWifi CSV (as exported by Evil-M5Project / Wigle) and builds a single
self-contained HTML file: clusters + WebGL points + heatmap, live filters,
stats, per-AP details. All JS libraries are vendored and inlined, so the output
opens without any internet (map tiles aside).

Usage:
    python Pygle.py                      # reads data.csv -> wifi_map.html
    python Pygle.py my_scan.csv
    python Pygle.py my_scan.csv -o map.html --title "Caen - nov 2026"
    python Pygle.py --no-dedup           # keep every observation (1 point/row)
"""
import argparse
import csv
import datetime as dt
import json
import math
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(HERE, "vendor")
TEMPLATE = os.path.join(HERE, "template.html")

VENDOR = {
    "leaflet.css": "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css",
    "MarkerCluster.css": "https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/MarkerCluster.css",
    "MarkerCluster.Default.css": "https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/MarkerCluster.Default.css",
    "leaflet.js": "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js",
    "leaflet.markercluster.js": "https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/leaflet.markercluster.js",
    "leaflet-heat.js": "https://cdnjs.cloudflare.com/ajax/libs/leaflet.heat/0.2.0/leaflet-heat.js",
    "glify-browser.js": "https://cdn.jsdelivr.net/npm/leaflet.glify@3.2.0/dist/glify-browser.js",
}

COLS = ["mac", "ssid", "auth", "enc", "band", "chan", "rssi", "lat", "lon",
        "first", "type", "count", "elat", "elon", "npos", "acc"]


def log(*a):
    print(*a, file=sys.stderr)


def fetch_vendor():
    """Download the JS/CSS libs once into vendor/, return {name: text}."""
    os.makedirs(VENDOR_DIR, exist_ok=True)
    out = {}
    for name, url in VENDOR.items():
        path = os.path.join(VENDOR_DIR, name)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            log(f"  fetch {name} ...")
            req = urllib.request.Request(url, headers={"User-Agent": "Pygle-build/2.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            with open(path, "wb") as f:
                f.write(data)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out[name] = f.read()
    return out


def detect_encoding(path):
    try:
        import chardet
        with open(path, "rb") as f:
            return chardet.detect(f.read(200000)).get("encoding") or "utf-8"
    except Exception:
        return "utf-8"


def classify_enc(auth, typ):
    s = (auth or "").upper()
    if typ != "WIFI":
        return "unknown"
    if "WPA3" in s:
        return "wpa3"
    if "WPA2" in s:
        return "wpa2"
    if "WPA" in s:
        return "wpa"
    if "WEP" in s:
        return "wep"
    if s == "" or "OPEN" in s or s.replace("[", "").replace("]", "") in ("ESS", "IBSS", ""):
        return "open"
    return "unknown"


def classify_band(chan):
    if chan is None:
        return "other"
    if 1 <= chan <= 14:
        return "2.4"
    if 32 <= chan <= 177:
        return "5"
    if 180 <= chan <= 233:
        return "6"
    return "other"


def to_int(v):
    try:
        return int(float(v))
    except Exception:
        return None


def to_float(v):
    try:
        return float(v)
    except Exception:
        return None


def parse_csv(path):
    enc = detect_encoding(path)
    log(f"  encoding: {enc}")
    recs = []
    skipped = 0
    with open(path, "r", encoding=enc, errors="replace", newline="") as f:
        # skip a leading "WigleWifi-1.x,..." pre-header line if present
        pos = f.tell()
        first = f.readline()
        if not first.lower().startswith("wiglewifi"):
            f.seek(pos)  # no pre-header, rewind
        reader = csv.DictReader(f)
        # normalise header keys
        fieldmap = {}
        for h in (reader.fieldnames or []):
            fieldmap[h.strip().lower()] = h

        def col(row, *names):
            for n in names:
                k = fieldmap.get(n)
                if k is not None:
                    return row.get(k, "")
            return ""

        for row in reader:
            lat = to_float(col(row, "currentlatitude", "latitude", "lat"))
            lon = to_float(col(row, "currentlongitude", "longitude", "lon"))
            rssi = to_int(col(row, "rssi", "signal"))
            if lat is None or lon is None or rssi is None or (lat == 0 and lon == 0):
                skipped += 1
                continue
            typ = (col(row, "type") or "WIFI").strip().upper() or "WIFI"
            chan = to_int(col(row, "channel", "chan"))
            rec = {
                "mac": (col(row, "mac", "bssid") or "").strip().upper(),
                "ssid": (col(row, "ssid") or "").strip(),
                "auth": (col(row, "authmode", "auth", "capabilities") or "").strip(),
                "chan": chan,
                "rssi": rssi,
                "lat": round(lat, 7),
                "lon": round(lon, 7),
                "first": (col(row, "firstseen", "time") or "").strip(),
                "type": typ,
                "count": 1,
            }
            rec["enc"] = classify_enc(rec["auth"], typ)
            rec["band"] = classify_band(chan)
            recs.append(rec)
    return recs, skipped


def haversine(a, b):
    """Great-circle distance in meters between (lat,lon) a and b."""
    R = 6371000.0
    la1, lo1 = math.radians(a[0]), math.radians(a[1])
    la2, lo2 = math.radians(b[0]), math.radians(b[1])
    dla, dlo = la2 - la1, lo2 - lo1
    h = math.sin(dla / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin(dlo / 2) ** 2
    return 2 * R * math.asin(min(1.0, math.sqrt(h)))


def rssi_weight(rssi):
    """Signal-based weight for trilateration. Stronger signal -> closer -> heavier,
    but bounded so a single strong hit does not fully collapse the estimate."""
    return max(1.0, rssi + 100.0) ** 2


def trilaterate(obs):
    """RSSI-weighted centroid over the distinct GPS points an AP was seen from.
    obs: list of (lat, lon, rssi). Returns (elat, elon, npos, acc_meters)."""
    # collapse to distinct positions, keeping the best RSSI at each
    bypos = {}
    for lat, lon, rssi in obs:
        k = (round(lat, 6), round(lon, 6))
        if k not in bypos or rssi > bypos[k]:
            bypos[k] = rssi
    pts = [(k[0], k[1], r) for k, r in bypos.items()]
    npos = len(pts)
    sw = swlat = swlon = 0.0
    for lat, lon, rssi in pts:
        w = rssi_weight(rssi)
        sw += w
        swlat += w * lat
        swlon += w * lon
    elat = swlat / sw if sw else sum(p[0] for p in pts) / npos
    elon = swlon / sw if sw else sum(p[1] for p in pts) / npos
    # accuracy = signal-weighted RMS distance of the points to the estimate
    num = den = 0.0
    for lat, lon, rssi in pts:
        w = rssi_weight(rssi)
        d = haversine((elat, elon), (lat, lon))
        num += w * d * d
        den += w
    acc = math.sqrt(num / den) if den else 0.0
    return round(elat, 7), round(elon, 7), npos, round(acc, 1), pts


def group(recs):
    """One entry per MAC: strongest observation as the representative, plus a
    trilaterated location estimate from every observation. Returns (records, obs_map)
    where obs_map[index] = distinct observation points for APs seen from >=2 spots."""
    agg = {}
    order = []
    for r in recs:
        mac = r["mac"] or f"_{id(r)}"
        e = agg.get(mac)
        if e is None:
            e = {"rep": r, "obs": [(r["lat"], r["lon"], r["rssi"])]}
            agg[mac] = e
            order.append(mac)
        else:
            e["obs"].append((r["lat"], r["lon"], r["rssi"]))
            if r["rssi"] > e["rep"]["rssi"]:
                if not r["ssid"] and e["rep"]["ssid"]:
                    r["ssid"] = e["rep"]["ssid"]
                e["rep"] = r
            elif not e["rep"]["ssid"] and r["ssid"]:
                e["rep"]["ssid"] = r["ssid"]

    out, obs_map = [], {}
    for i, mac in enumerate(order):
        e = agg[mac]
        rep = e["rep"]
        elat, elon, npos, acc, pts = trilaterate(e["obs"])
        rep["count"] = len(e["obs"])
        rep["elat"], rep["elon"], rep["npos"], rep["acc"] = elat, elon, npos, acc
        out.append(rep)
        if npos >= 2:
            obs_map[i] = [[p[0], p[1], p[2]] for p in pts]
    return out, obs_map


def as_single(recs):
    """--no-dedup path: keep every observation, fill estimate fields trivially."""
    for r in recs:
        r["elat"], r["elon"], r["npos"], r["acc"] = r["lat"], r["lon"], 1, 0.0
    return recs, {}


def build_payload(recs, obs_map, total_rows, source, title):
    lats = [r["lat"] for r in recs]
    lons = [r["lon"] for r in recs]
    center = [sum(lats) / len(lats), sum(lons) / len(lons)] if recs else [0, 0]
    bounds = [[min(lats), min(lons)], [max(lats), max(lons)]] if recs else None
    rows = [[r[c] for c in COLS] for r in recs]
    types = sorted({r["type"] for r in recs})
    return {
        "meta": {
            "title": title,
            "source": os.path.basename(source),
            "total_rows": total_rows,
            "located": sum(1 for r in recs if r["npos"] >= 2),
            "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        },
        "cols": COLS,
        "rows": rows,
        "obs": {str(k): v for k, v in obs_map.items()},
        "types": types,
        "center": center,
        "bounds": bounds,
    }


def render(payload, libs, title):
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        html = f.read()
    repl = {
        "/*__CSS_LEAFLET__*/": libs["leaflet.css"],
        "/*__CSS_MARKERCLUSTER__*/": libs["MarkerCluster.css"],
        "/*__CSS_MARKERCLUSTER_DEFAULT__*/": libs["MarkerCluster.Default.css"],
        "/*__JS_LEAFLET__*/": libs["leaflet.js"],
        "/*__JS_MARKERCLUSTER__*/": libs["leaflet.markercluster.js"],
        "/*__JS_HEAT__*/": libs["leaflet-heat.js"],
        "/*__JS_GLIFY__*/": libs["glify-browser.js"],
        "/*__DATA__*/": "window.PYGLE = " + json.dumps(payload, ensure_ascii=False) + ";",
        "__TITLE__": title,
    }
    for k, v in repl.items():
        html = html.replace(k, v)
    return html


def main():
    ap = argparse.ArgumentParser(description="Pygle - offline wardriving map generator")
    ap.add_argument("input", nargs="?", default="data.csv", help="WigleWifi CSV (default: data.csv)")
    ap.add_argument("-o", "--output", default="wifi_map.html", help="output HTML (default: wifi_map.html)")
    ap.add_argument("-t", "--title", default=None, help="map title")
    ap.add_argument("--no-dedup", action="store_true", help="keep every observation (no per-MAC dedupe)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        log(f"[!] input not found: {args.input}")
        sys.exit(1)

    title = args.title or f"Pygle - {os.path.basename(args.input)}"

    log(f"[*] parsing {args.input}")
    recs, skipped = parse_csv(args.input)
    total_rows = len(recs)
    log(f"    {total_rows} valid observations, {skipped} skipped (bad/zero coords)")

    if not args.no_dedup:
        recs, obs_map = group(recs)
        located = sum(1 for r in recs if r["npos"] >= 2)
        log(f"    {len(recs)} unique APs after dedupe")
        log(f"    {located} APs trilaterated (seen from >=2 GPS points)")
    else:
        recs, obs_map = as_single(recs)

    if not recs:
        log("[!] nothing to map (no valid coordinates).")
        sys.exit(2)

    log("[*] vendoring libraries")
    libs = fetch_vendor()

    log("[*] rendering")
    payload = build_payload(recs, obs_map, total_rows, args.input, title)
    html = render(payload, libs, title)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)
    size_mb = os.path.getsize(args.output) / 1e6
    log(f"[+] wrote {args.output}  ({size_mb:.1f} MB, {len(recs)} APs)")
    # quick security glance
    opens = sum(1 for r in recs if r["enc"] == "open")
    log(f"    open networks: {opens}  |  hidden SSIDs: {sum(1 for r in recs if not r['ssid'])}")


if __name__ == "__main__":
    main()
