# Arppy - An Advanced ARP Spoofing Tool

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)

Arppy is a powerful and user-friendly ARP spoofing tool written in Python 3. It is designed for network analysis and educational purposes, demonstrating the principles of a Man-in-the-Middle (MITM) attack via ARP cache poisoning.

It leverages the `scapy` library for packet manipulation and the `rich` library to provide a clean, informative, and visually appealing command-line interface. It supports both targeted spoofing between two specific devices and a "Nuke Mode" to spoof all devices on the local network simultaneously.

The script is built with a focus on robust error handling, cross-platform compatibility, and graceful cleanup to restore the network to its original state.

## 🎯 Targeted Mode

![Targeted mode](https://github.com/Maaroof-Khan10/Arppy/blob/ccafc37b4e8c8c75068fd7459fddb4347c8aa401/Screenshot%202025-07-21%20230138.png)

## ☢️ Nuke Mode

![Nuke Mode](https://github.com/Maaroof-Khan10/Arppy/blob/ccafc37b4e8c8c75068fd7459fddb4347c8aa401/Screenshot%202025-07-21%20230057.png)
 

## ✨ Features

-   **🎯 Targeted Spoofing**: Intercept traffic between a specific target device and the gateway.
-   **☢️ Nuke Mode**: Automatically discovers all active devices on the network and spoofs them all, redirecting their traffic through the attacker's machine.
-   **💻 Rich CLI Output**: Utilizes the `rich` library for beautiful and informative output, including tables, status spinners, and colored text.
-   **🌐 Automatic Discovery**: Automatically detects the gateway IP and network range (CIDR), simplifying the setup process.
-   **🖥️ Cross-Platform**: Designed to work on both **Linux** and **Windows** systems.
-   **🧹 Graceful Exit**: On interruption (Ctrl+C), the script automatically restores the ARP tables of all targeted devices, preventing lasting network disruption.
-   **⚙️ Robust Argument Parsing**: Clear and easy-to-use command-line arguments with helpful examples.

## ⚠️ Ethical Disclaimer

This tool is intended for **educational and authorized security testing purposes ONLY**. Using this tool on a network without explicit permission from the administrator is illegal and unethical. The author is not responsible for any misuse or damage caused by this script. **Always act responsibly.**

## 🔧 Installation

### Prerequisites

-   Python 3.11+
-   `pip` (Python package installer)

### 1. System-Specific Dependencies

Scapy has different underlying requirements for capturing and sending packets on Linux and Windows.

#### On Linux (Debian/Ubuntu)
You need to install the `libpcap` development library.
```bash
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev
```

#### On Linux (Fedora/CentOS)
```bash
sudo dnf install python3-devel libpcap-devel
```

#### On Windows
You need to install **Npcap**.
1.  Download the latest Npcap installer from the [official Npcap website](https://npcap.com/#download).
2.  Run the installer.
3.  **Important**: During installation, make sure to check the box for **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Clone and Install Python Packages

Now, clone the repository and install the required Python packages.

```bash
# Clone the repository
git clone https://github.com/Maaroof-Khan10/Arppy.git
cd Arppy

# Install Python dependencies
pip install -r requirements.txt
```

## 🚀 Usage

This script must be run with administrative or root privileges to access raw sockets for packet manipulation.

-   On **Linux**, use `sudo`.
-   On **Windows**, open `Command Prompt` or `PowerShell` as an Administrator.

---

### Basic Command Structure

```
# For Linux
sudo python3 arppy.py [MODE] [OPTIONS]

# For Windows (in an Administrator terminal)
python arppy.py [MODE] [OPTIONS]
```

### Modes of Operation

#### 🎯 Targeted Spoofing

This mode intercepts traffic between a single target and the gateway. You must provide the IP address for both.

```bash
# Example:
sudo python3 arppy.py --target 192.168.1.10 --gateway 192.168.1.1
```
Arppy will first resolve the MAC addresses for the target and gateway, then begin sending spoofed ARP packets to both, positioning itself as the man-in-the-middle.
Note: If Arppy could not resolve the MAC addresses it could be due to a slower network or traffic, just rerun the script till it resolves them (This process is automated in the Nuke mode)

---

#### ☢️ Nuke Mode

This mode automatically discovers all devices on your local network and ARP spoofs every one of them (except the gateway). This effectively redirects all network traffic through your machine.

```bash
# Activate Nuke Mode with default settings
sudo python3 arppy.py --nuke
```

You can control the number of discovery scans to find more devices, especially on busy or slow networks.

```bash
# Nuke Mode with 5 scan rounds for better device discovery
sudo python3 arppy.py --nuke --scan-rounds 5
```

### Stopping the Attack

To stop the attack and restore the network, press `Ctrl+C`. Arppy will catch the interruption and send corrective ARP packets to all targets, cleaning up their ARP caches.

### View Help Menu
For a full list of commands and options, use the `-h` or `--help` flag.

```bash
python3 arppy.py --help
```

## 🧠 How It Works

1.  **ARP (Address Resolution Protocol)**: ARP is used by devices on a network to associate an IP address with a MAC (hardware) address. When a device needs to send a packet to an IP address on the local network, it sends an ARP request asking, "Who has this IP address?" The owner of that IP replies with its MAC address.
2.  **ARP Cache Poisoning**: Arppy exploits this by sending unsolicited, forged ARP replies.
    -   It tells the **target machine** that the **gateway's IP address** belongs to the **attacker's MAC address**.
    -   It tells the **gateway** that the **target's IP address** belongs to the **attacker's MAC address**.
3.  **Man-in-the-Middle**: As a result, both the target and the gateway update their ARP caches with the attacker's MAC address. All traffic between them is now sent to the attacker's machine first, allowing for interception or analysis before (optionally) forwarding it to the legitimate destination.
4.  **IP Forwarding**: To maintain the victim's internet connection and remain undetected, the attacker must enable IP forwarding on their own machine. This allows packets to flow through them to the intended destination. *Note: This script does not handle IP forwarding automatically. You must enable it manually if you wish for the targets to maintain connectivity.*

    -   **On Linux**: `echo 1 > /proc/sys/net/ipv4/ip_forward`
    -   **On Windows**: This is more complex and involves registry edits or PowerShell commands (e.g., `Set-NetIPInterface -Forwarding Enabled`).

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
