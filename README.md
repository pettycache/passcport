# Network Assistant Tool

A utility for network configuration and troubleshooting on Linux and macOS systems. This tool helps in analyzing network environments, identifying active hosts, and configuring network interfaces with specific IP and MAC addresses.

## Features

-   **Network Scanning:** Discover active hosts within a specified network range.
-   **Network Configuration:** Configure network interfaces with custom IP and MAC addresses.
-   **OS Compatibility:** Supports both Linux and macOS.
-   **Logging:** Detailed logging for troubleshooting and debugging.

## Prerequisites

This script requires the following tools to be installed on your system:

-   `sipcalc`: A command-line IP subnet calculator.
-   `nmap`: A network scanner.
-   `macchanger`: (Linux only) A utility for viewing/modifying MAC addresses.

### Installation of Prerequisites

#### Debian/Ubuntu (Linux)

```bash
sudo apt update
sudo apt install sipcalc nmap macchanger
```

#### Fedora/RHEL (Linux)

```bash
sudo dnf install sipcalc nmap macchanger
```

#### Arch Linux (Linux)

```bash
sudo pacman -S sipcalc nmap macchanger
```

#### macOS

```bash
brew install sipcalc nmap
# macchanger is not available for macOS via Homebrew. MAC address changes on macOS are typically done via ifconfig or network settings.
```

## Usage

The `net_assist.sh` script can be run with various parameters to customize its behavior.

```bash
sudo ./net_assist.sh [parameters]
```

### Parameters

-   `-h`, `--help`: Show the help menu.
-   `-d`, `--debug`: Enable debug logging.
-   `-s <name>`, `--ssid=<name>`: WiFi SSID.
-   `-i <name>`, `--iface=<name>`: Network Interface.
-   `-g <ip>`, `--gateway=<ip>`: Network Gateway.
-   `-p <ip>`, `--localip=<ip>`: Local IP address.
-   `-b <ip>`, `--broadcast=<ip>`: Broadcast IP.
-   `-n <cidr>`, `--netmask=<cidr>`: Network Mask (CIDR, e.g., 24).
-   `-m <ip/cidr>`, `--ipmask=<ip/cidr>`: IP with Mask (e.g., 192.168.1.10/24).
-   `-w <net/cidr>`, `--network=<net/cidr>`: Network (e.g., 192.168.1.0/24).
-   `-a <mac>`, `--macaddress=<mac>`: Your original MAC Address.
-   `-S <ip>`, `--netaddress=<ip>`: Network Address (e.g., 192.168.1.0).

### Examples

1.  **Run with debug mode enabled:**
    ```bash
    sudo ./net_assist.sh --debug
    ```

2.  **Specify network interface and SSID:**
    ```bash
    sudo ./net_assist.sh -i wlan0 -s "MyWiFiNetwork"
    ```

3.  **Specify a custom IP and MAC address:**
    ```bash
    sudo ./net_assist.sh -i eth0 -p 192.168.1.100 -a 00:11:22:33:44:55
    ```

## License

This project is licensed under the [LICENSE](LICENSE) file.