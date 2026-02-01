# Reverse TCP Control Server

This project sets up a proxy server that allows an **ESP32** device to communicate with a **client** (such as a web browser or other HTTP client) via a **Python asyncio server**. 

The server accepts connections from both the ESP32 and client, forwarding requests and responses between them.

## Features

- Manages connections between an ESP32 and client.
- Forwards client requests to the ESP32 and streams ESP32 responses back to the client.
- Utilizes asyncio for asynchronous handling of connections.
- Allows multiple clients to connect to the ESP32 through a single proxy server.

## Prerequisites

- Python 3.7 or higher
- ESP32 device (configured to connect to this server)
- Basic knowledge of networking, as NAT configuration is required for external access.

## Setup

### 1. Install Python Dependencies

Make sure you have Python 3.7+ installed. This script uses only the Python standard library, so no extra packages are required.

### 2. Configure Network Address Translation (NAT) for External Access

To allow the ESP32 to connect to this server from outside your local network, configure NAT (Port Forwarding) on your router for the C2 server.

- **Find your server's local IP address**: Check your computer's IP address (e.g., `192.168.x.x`).
- **Access your router settings**: Open a web browser and enter your router’s IP address (usually something like `192.168.1.1`).
- **Set up port forwarding**:
  - **NAT**: Forward **port 4444** (or your chosen `tcp_port`) to your server's local IP address.

> **Important**: Port forwarding exposes your server to the internet, which may present security risks. Ensure that your server is secure and accessible only to trusted devices.
