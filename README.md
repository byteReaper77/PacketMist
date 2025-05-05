# PacketMist

**A Simple ARP Spoofing Tool (Free Version)**
*Author: Byte Reaper*

---

## Overview

PacketMist is a free and open-source ARP spoofing (ARP spoofing) tool for local networks, written in C++ using libpcap. It allows you to intercept, reroute, or manipulate traffic between a router and a target device by injecting crafted ARP packets.

> **Note:** This free version is intended for small-scale testing and educational use only. A commercial "Pro" version with advanced features and performance improvements will be available soon.

---

## Key Features

- **Basic ARP Spoofing**
- **Packet Fragmentation**: Splits ARP packets into smaller fragments to better simulate real traffic.
- **Random MAC Address Changer**: Automatically assigns a locally administered MAC address for cloaking.
- **TTL Detection**: Reads the time-to-live to determine the target operating system (Linux/Windows/Mac OS).
- **CPU Monitoring**: Displays CPU usage and issues a warning if it exceeds 80%.
- **Event Logging**: Records errors and warnings in the `arp.log` file.
- **Safe Cleanup**: Restores the original ARP tables by pressing Ctrl+C (SIGINT).
- **Lightweight Command Line Interface**: Does not rely on heavy dependencies—only **libpcap** and the C++ standard libraries.
You can add a ping feature. The library has been added, as well as a device verification function, if you wish.
---

## Requirements

- **Linux** (root access required)
- **libpcap** development headers
sudo apt update && sudo apt install libpcap-dev

# Installation:
Cloop the repository:
git clone https://github.com/byteReaper77/PacketMist/blob/main/PacketMist.cpp
Compile the code:

g++ PacketMist.cpp -o PacketMist -lpcap -pthread
or
g++ PacketMist.cpp -o PacketMist -lpcap
Make it executable:

sudo chmod +x PacketMist

## Usage:
Run as root:

sudo ./PacketMist

Specify a network interface (e.g., eth0).

Enter the IP address and MAC address of the router.

Enter the target IP and MAC address.

PacketMist will start sending fragmented ARP requests, monitor the CPU, and display TTL information.

Press Ctrl+C to stop it. The original ARP tables will be restored automatically.

# Licensing
PacketMist is licensed under the MIT License. See the license for details.

# Contribution
Open an issue to suggest features or report bugs.

Fork the repository and submit a pull request.

Help us improve PacketMist!

My Telegram account: https://t.me/ByteReaper0

# Legal and Ethical Notice
Please use this only with explicit permission. Unauthorized network attacks are illegal.

The author is not responsible for misuse of this tool.

Always work within legal and ethical boundaries.

Stay tuned for the upcoming pro version with enhanced functionality and commercial support!