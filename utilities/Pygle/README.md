# Pygle - Offline Wi-Fi Visualization Tool

**Pygle** is a Python script designed to visualize Wi-Fi data from wardriving CSV files, similar to WiGLE but in an offline environment. It allows you to map Wi-Fi networks on an interactive map using data like MAC addresses, SSIDs, RSSI, and geographic coordinates.

## Features

- Visualizes Wi-Fi networks on an interactive map using latitude and longitude.
- Displays additional information in pop-ups, including SSID, MAC address, authentication mode, RSSI, and more.
- Color-codes Wi-Fi markers based on signal strength (RSSI).
- Works entirely offline.

## Requirements

Before using Pygle, ensure that you have the following installed on your machine:

- Python 3.x
- [Pandas](https://pandas.pydata.org/)
- [Folium](https://python-visualization.github.io/folium/)

You can install the required libraries with the following command:

pip install pandas folium chardet

## How to Use

Prepare your CSV file:

The CSV file should have data in a similar format to the one provided by WiGLE, containing information such as MAC address, SSID, RSSI, and GPS coordinates (latitude and longitude).
And named `data.csv` in the same folder as the Python script.

Execute the Python script in your terminal:

python Pygle.py

View the output:

After running the script, an HTML file wifi_map.html will be generated in the same directory. You can open this file in any web browser to see the interactive map of Wi-Fi networks.

## Color

Color-Coding Based on RSSI

Wi-Fi markers are color-coded based on signal strength (RSSI):

- Green: Strong signal (RSSI ≥ -70 dBm)
- Orange: Moderate signal (-85 dBm ≤ RSSI < -70 dBm)
- Red: Weak signal (RSSI < -85 dBm)

You can modify these thresholds in the script by editing the get_color() function.

## Data Popups

Each Wi-Fi marker displays additional information such as:

- SSID: The name of the network
- MAC: The MAC address of the access point
- Auth Mode: The type of encryption (e.g., WPA, WPA2)
- RSSI: Signal strength in dBm
- First Seen: Timestamp of when the network was first detected
- Altitude: Altitude in meters
- Accuracy: Accuracy of the GPS coordinates
