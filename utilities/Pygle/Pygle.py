import pandas as pd
import folium
import chardet
import html

# Define relevant columns
colonnes = ['MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'RSSI', 'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'Type']
text_cols = ['MAC', 'SSID', 'AuthMode', 'Type']


# Detect the encoding of the file
with open('data.csv', 'rb') as f:
    result = chardet.detect(f.read())
encoding = result['encoding']
print(f"Detected encoding: {encoding}")

# Load the cleaned data
df = pd.read_csv('data.csv', skiprows=3, names=colonnes, on_bad_lines='skip', encoding=encoding)
df[text_cols] = df[text_cols].fillna("").astype(str)
# Convert latitude, longitude, and RSSI to numeric values (handling errors)
df['CurrentLatitude'] = pd.to_numeric(df['CurrentLatitude'], errors='coerce')
df['CurrentLongitude'] = pd.to_numeric(df['CurrentLongitude'], errors='coerce')
df['RSSI'] = pd.to_numeric(df['RSSI'], errors='coerce')

# Remove rows with invalid coordinates, RSSI, or coordinates equal to zero
df = df.dropna(subset=['CurrentLatitude', 'CurrentLongitude', 'RSSI'])
df = df[(df['CurrentLatitude'] != 0) & (df['CurrentLongitude'] != 0)]

# Create a map centered on the average location
if not df.empty:
    avg_lat = df['CurrentLatitude'].mean()
    avg_lon = df['CurrentLongitude'].mean()
    ma_carte = folium.Map(location=[avg_lat, avg_lon], zoom_start=15)

    # Function to get color based on RSSI
    def get_color(rssi):
        if rssi >= -70:
            return 'green'
        elif rssi >= -85:
            return 'orange'
        else:
            return 'red'

    # Add points to the map with popups
    for index, row in df.iterrows():
        latitude = row['CurrentLatitude']
        longitude = row['CurrentLongitude']
        ssid = row['SSID']
        mac = row['MAC']
        auth_mode = row['AuthMode']
        rssi = row['RSSI']
        altitude = row['AltitudeMeters']
        accuracy = row['AccuracyMeters']
        wifi_type = row['Type']

        popup_content = f"""
        <b>SSID:</b> {html.escape(ssid)}<br>
        <b>MAC:</b> {html.escape(mac)}<br>
        <b>Auth Mode:</b> {html.escape(auth_mode)}<br>
        <b>RSSI:</b> {rssi} dBm<br>
        <b>Altitude:</b> {altitude} m<br>
        <b>Accuracy:</b> {accuracy} m<br>
        <b>Type:</b> {html.escape(wifi_type)}
        """

        color = get_color(int(rssi))

        folium.CircleMarker(
            location=[latitude, longitude],
            radius=5,
            popup=folium.Popup(popup_content, max_width=300),
            color=color,
            fill=True,
            fill_color=color
        ).add_to(ma_carte)

    # Save the map to an HTML file
    ma_carte.save('wifi_map.html')
else:
    print("Aucune donnée valide disponible pour générer la carte.")
