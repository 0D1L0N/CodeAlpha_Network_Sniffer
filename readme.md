# Network Sniffer

A simple network packet sniffer built in Python. This project captures and analyzes network traffic, helping you understand how data flows over a network and the structure of network packets.

## Features

- Captures Ethernet frames and decodes the headers.
- Analyzes IP packets, including TTL, protocol type, source, and destination IP addresses.
- Displays packet information in a user-friendly format.
- Supports filtering by network interface.

## Usage

To use the packet sniffer tool, follow these steps:

1. **Install Required Packages**: Make sure you have the necessary Python packages installed. You can do this by running:

    ```bash
    pip install -r requirements.txt
    ```

2. **Run the Sniffer**: You can run the packet sniffer by using the following command:

    ```bash
    python3 sniffer.py -i <interface>
    ```

   Replace `<interface>` with the network interface you want to monitor (e.g., `eth0`, `wlan0`). If you don't specify an interface, it will capture packets from all available interfaces.

3. **Display Packet Data**: If you want to see the raw packet data while sniffing, add the `-d` flag:

    ```bash
    python3 sniffer.py -i <interface> -d
    ```

4. **Stop the Sniffer**: To stop the packet capture, simply press `Ctrl+C` in the terminal.

### Example

Here’s a complete example of how to run the packet sniffer on the `wlan0` interface:

```bash
python3 sniffer.py -i wlan0 -d



