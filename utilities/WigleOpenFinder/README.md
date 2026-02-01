# WigleOpenFinder

## Description

This Python script uses the Nominatim API (OpenStreetMap) to retrieve the coordinates of a given city and the Wigle API to search for open Wi-Fi networks in that area. The SSIDs of the found networks are sorted, displayed in the console, and saved to a text file.

---

## Features

- Retrieve geographic coordinates of a city using the Nominatim API.
- Search for unsecured Wi-Fi networks within a 0.5-degree radius around the provided coordinates.
- Extract and sort SSIDs of open networks.
- Save the SSIDs to a text file.

---

## Requirements

- Python 3.x installed on your system.
- The `requests` library installed in your Python environment.
- A Wigle account with a valid API token.

---

## Installation

1. Clone the repository to your local machine.
2. Add your Wigle API token to the `api_token` variable in the script.
3. Ensure all required libraries are installed in your Python environment.

---

## Usage

1. Execute the script using Python.
2. Enter a city name when prompted.
3. Review the SSIDs displayed in the console.
4. Check the text file generated in the script directory for the saved SSIDs.

---

## Example

### Input
The script will prompt you to enter the name of a city, for example: `Paris`.

### Console output
The script will display the open networks it finds:
Open networks for Paris:
FreeWiFi McDonalds_Open Starbucks

SSIDs saved in Open-SSID-Paris.txt


### Generated Text File
The script will save the open SSIDs in a text file named after the city, such as `Open-SSID-Paris.txt`.

---

## Notes

- The Wigle API enforces usage limits. Ensure compliance with their terms of service.
- The accuracy of results depends on the data available in Wigle's database.

---

## Contribution

Contributions are welcome. If you encounter a bug or have ideas for improvement, feel free to report them or submit updates.

---

## License

This project is licensed under the MIT License.

---

## Disclaimer

This script is intended for ethical and legal use only. Always respect privacy and adhere to local network regulations.
