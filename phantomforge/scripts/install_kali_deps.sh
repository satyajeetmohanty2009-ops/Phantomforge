#!/usr/bin/env bash
set -euo pipefail

echo "[PhantomForge] Installing Kali tool dependencies with apt..."
sudo apt update
sudo apt install -y nmap tshark sqlmap john beef-xss python3.11 python3.11-venv nodejs npm

cat <<'NOTE'

Installed core tools:
  - nmap: recon and NSE scanning
  - tshark: capture and pcap analysis
  - sqlmap: SQL injection testing
  - john: password/hash cracking
  - beef-xss: browser hook workflow

Privilege notes:
  - Live capture usually requires root, dumpcap capabilities, or membership in the wireshark group.
  - Nmap OS detection may require root for best results.
  - sqlmap, john, report viewing, and mock mode do not require root.

Review config.yaml and override paths if your packages install elsewhere.
NOTE
