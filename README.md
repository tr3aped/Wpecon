# Wpecon Suite

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge&logo=python&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>Advanced WordPress Reconnaissance Tool</b><br>
  A fast and lightweight Python-based CLI tool designed to gather critical information about WordPress installations.
</p>

---

## Features

Wpecon Suite provides a comprehensive overview of a target WordPress site with a beautifully formatted terminal output.

- **Version Detection**: Accurately identifies the WordPress core version using multiple vectors (`/feed/`, `readme.html`, and meta generator tags).
- **Vulnerability Scanning**: Fetches known CVEs directly from the WPVulnerability API and displays them in a color-coded table based on CVSS severity scores.
- **Domain Intelligence**: Retrieves the target's IP address, site language, and domain creation date via WHOIS.
- **Plugin Enumeration**: Extracts active plugins directly from the page source code.
- **User Enumeration**: Attempts to list registered users through the WordPress REST API (`/wp-json/wp/v2/users`).
- **Dynamic Interface**: Features an animated ASCII banner, real-time loading spinners, and structured output boxes.

---

## Installation & Download Guide

Follow these steps carefully to download and set up Wpecon Suite on your system (Termux, Linux, or macOS).

**Step 1: Update your package manager (Optional but recommended)**
```bash
pkg update && pkg upgrade -y    # For Termux
sudo apt update && sudo apt upgrade -y  # For Debian/Ubuntu
```

Step 2: Install Python and Git
If you don't have them installed yet, run:

```bash
pkg install python git -y       # For Termux
sudo apt install python3 git -y # For Debian/Ubuntu
```

Step 3: Clone the repository
Download the tool by cloning this repository to your local machine:

```bash
git clone https://github.com/tr3aped/wpecon.git
```

Step 4: Navigate into the directory

```bash
cd wpecon
```

Step 5: Install the required Python dependencies

```bash
pip install -r requirements.txt
```

(Note: If requirements.txt is missing, install manually using: pip install requests python-whois pyfiglet)

Step 6: Run the tool

```bash
python3 wpecon.py
```

---

Usage

Run the tool using python3. You can choose between check for a full scan or info for version and vulnerability details only.

```bash
# Display help menu
python3 wpecon.py

# Perform a full scan (Version, Vulns, Plugins, Users)
python3 wpecon.py check https://example.com

# Fetch version and vulnerabilities only
python3 wpecon.py info https://example.com/wp-admin
```

---

Author & Community

Created and maintained by @Tr3Ped.

Stay updated with the latest tools, exploits, and updates by joining our Telegram channel:

<p align="left">
  <a href="https://t.me/Tr3aped_Archive">
    <img src="https://img.shields.io/badge/Telegram-@Tr3aped__Archive-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram Archive">
  </a>
</p>---
