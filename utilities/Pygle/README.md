# Pygle - Offline Wardriving Map

**Pygle** turns a WigleWifi CSV (as exported by Evil-M5Project / Wigle) into a
single self-contained HTML map. No upload, no account, works offline: all the
JavaScript libraries are vendored and inlined into the output file. It is a
local, private alternative to the WiGLE web map.

![views: clusters / points / heatmap](.)

## Features

- **3 render modes, togglable**
  - **Clusters** (Leaflet.markercluster): WiGLE-style grouped counts, scales well.
  - **Points** (WebGL via Leaflet.glify): every AP drawn at once on the GPU,
    stays smooth with tens of thousands of points.
  - **Heatmap**: signal-weighted density.
- **AP location estimate (trilateration).** Each access point is positioned by
  an RSSI-weighted centroid over every distinct GPS point it was seen from, with
  an accuracy radius in meters. Toggle between the estimate and the raw observed
  point; click an AP to reveal its observation points, the accuracy circle and
  the estimated marker.
- **Color by signal (RSSI) or by encryption.**
- **Live filters**: text search (SSID / MAC), encryption (Open / WEP / WPA /
  WPA2 / WPA3), band (2.4 / 5 / 6 GHz), type (WIFI / BLE / BT), minimum-signal
  slider, hidden-SSID toggle (all / hide / only).
- **Live stats** that follow the filters: unique networks, open networks,
  unique SSIDs, hidden count, encryption and band breakdowns, channel histogram,
  top SSIDs.
- **Per-AP detail panel**: MAC, auth string, best RSSI, channel/band,
  observation count and number of GPS points, position type (trilaterated or
  single-point) with accuracy, first seen, coordinates, copy-MAC, show
  observations, open-in-OpenStreetMap.
- **Per-MAC dedupe**: one marker per AP, keeping the strongest observation and
  counting how many times it was seen (`--no-dedup` to keep every row).
- **Export the filtered set** to GeoJSON or CSV.
- **Basemaps**: Esri Dark / Street / Satellite, OpenStreetMap.
- Self-contained output: opens with no internet (map tiles aside).

## Requirements (build side only)

Python 3 with `pandas` is **not** required anymore; the generator only needs the
standard library plus `chardet` (optional, for encoding detection):

```
pip install chardet
```

A one-time internet connection is needed on first run to vendor the JS/CSS
libraries into `vendor/`. After that, builds are fully offline and so is the
generated HTML.

## Usage

```
python Pygle.py                      # reads data.csv -> wifi_map.html
python Pygle.py my_scan.csv
python Pygle.py my_scan.csv -o caen.html --title "Caen - nov 2026"
python Pygle.py --no-dedup           # one point per observation
```

Open the generated `wifi_map.html` in any browser.

## Input format

Standard WigleWifi 1.x CSV. The optional `WigleWifi-1.x,...` pre-header line is
handled automatically; columns are matched by name
(`MAC, SSID, AuthMode, FirstSeen, Channel, RSSI, CurrentLatitude,
CurrentLongitude, AltitudeMeters, AccuracyMeters, Type`). Rows with missing or
zero coordinates are dropped.

## AP location estimate (trilateration)

Instead of plotting an AP where it happened to be heard, Pygle estimates where
the AP actually is. For every MAC it gathers all observations, reduces them to
the distinct GPS points it was seen from (keeping the best RSSI at each), and
computes an **RSSI-weighted centroid**: points with a stronger signal pull the
estimate closer to themselves. The weight is `max(1, rssi + 100)^2`, which
favours strong hits without letting a single one collapse the result.

An **accuracy radius** (meters) is reported as the signal-weighted RMS distance
of the observation points to the estimate: smaller means the points agree, larger
means the AP was only heard loosely.

An AP seen from a single GPS point cannot be trilaterated and is shown at its
observed location (`npos = 1`). In the UI, the **AP position** toggle switches
all markers between the estimate and the raw observation, and **Show
observations** on an AP draws its points, the links to the estimate and the
accuracy circle.

This is a weighted-centroid approach (the robust, calibration-free method, close
to what WiGLE does), not a path-loss least-squares multilateration. It needs the
GPS to have moved between captures to add anything.

## Fully offline map tiles (optional)

The UI is self-contained, but the basemap tiles are fetched online by default.
For a 100% offline map, serve a local tile set (e.g. an MBTiles region via a
local tile server) and point a basemap at it in `template.html` (`BASES`).

## Layout

- `Pygle.py` - generator (parse, dedupe, enrich, vendor, render).
- `template.html` - the UI (CSS + app JS) with `__TOKENS__` replaced at build.
- `vendor/` - cached JS/CSS libraries (created on first run).
- `Pygle_legacy.py` - the original folium-based script, kept for reference.
