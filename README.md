# PassCPort

A utility for network configuration and troubleshooting on Linux, macOS, and Windows systems. This tool helps in analyzing network environments, identifying active hosts, and configuring network interfaces with specific IP and MAC addresses, primarily for bypassing captive portals or similar network challenges. But its main use case is to bypass captive portals for public internet in hotels, airports, businesses, etc. 

## Features

-   **Network Scanning:** Discover active hosts within a specified network range.
-   **Network Configuration:** Configure network interfaces with custom IP and MAC addresses.
-   **OS Compatibility:** Supports Linux, macOS (via `net_assist.sh`), and Windows (via `net_assist.ps1`).
-   **Logging:** Detailed logging for troubleshooting and debugging.

## Prerequisites

### For Linux and macOS (`net_assist.sh`)

This script requires the following tools to be installed on your system:

-   `sipcalc`: A command-line IP subnet calculator.
-   `nmap`: A network scanner.
-   `macchanger`: (Linux only) A utility for viewing/modifying MAC addresses.

#### Installation of Prerequisites (Linux/macOS)

##### Debian/Ubuntu (Linux)

```bash
sudo apt update
sudo apt install sipcalc nmap macchanger
```

##### Fedora/RHEL (Linux)

```bash
sudo dnf install sipcalc nmap macchanger
```

##### Arch Linux (Linux)

```bash
sudo pacman -S sipcalc nmap macchanger
```

##### macOS

```bash
brew install sipcalc nmap
# macchanger is not available for macOS via Homebrew. MAC address changes on macOS are typically done via ifconfig or network settings.
```

### For Windows (`net_assist.ps1`)

This script requires the following:

-   **PowerShell 5.1 or newer:** Included by default in modern Windows versions.
-   **Nmap:** A network scanner.

#### Installation of Prerequisites (Windows)

1.  **Nmap:**
    *   Download the Nmap installer from the official website: [https://nmap.org/download.html](https://nmap.org/download.html)
    *   Run the installer and follow the prompts. Ensure Nmap is added to your system's PATH during installation.

## Usage

### For Linux and macOS (`net_assist.sh`)

The `net_assist.sh` script can be run with various parameters to customize its behavior.

```bash
sudo ./net_assist.sh [parameters]
```

### For Windows (`net_assist.ps1`)

The `net_assist.ps1` script can be run from PowerShell with administrator privileges.

**First-time setup (if needed):** You might need to adjust PowerShell's execution policy to allow scripts to run. Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Confirm with 'Y' when prompted.

**Running the script:**

Open PowerShell as Administrator, navigate to the script's directory, and run:

```powershell
.\net_assist.ps1 [parameters]
```

### Parameters (Common to both scripts)

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

#### Linux/macOS Examples

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

#### Windows Examples

1.  **Run with debug mode enabled:**
    ```powershell
    .
et_assist.ps1 -Debug
    ```

2.  **Specify network interface and SSID:**
    ```powershell
    .
et_assist.ps1 -Iface "Wi-Fi" -SSID "MyWiFiNetwork"
    ```

3.  **Specify a custom IP and MAC address:**
    ```powershell
    .
et_assist.ps1 -Iface "Ethernet" -LocalIP "192.168.1.100" -MACAddress "00:11:22:33:44:55"
    ```


## Disclaimer & License

### Disclaimer

PassCPort is an open-source project designed to assist cybersecurity professionals in conducting authorized wireless network assessments. This software is intended for legitimate use only, such as authorized penetration testing and/or nonprofit educational purposes. It should only be used on networks that you own or have explicit written permission from the owner to test.

Misuse of this software for illegal activities, including unauthorized network intrusion, hacking, or any activity that violates applicable laws, is strictly prohibited. The author(s), contributors, and any affiliated party assume no responsibility or liability for any damage, misuse, or legal consequences arising from the use of this software. By using airgeddon, you agree to indemnify and hold harmless the project contributors from any claims or legal action.

It is the user's sole responsibility to ensure compliance with all applicable local, state, national, and international laws. If you are unsure about your legal rights to use this software, you should consult with an attorney before proceeding.

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

Use this software at your own risk.

### License

This project is licensed under the [LICENSE](LICENSE) file.
