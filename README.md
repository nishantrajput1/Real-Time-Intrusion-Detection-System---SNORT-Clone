# 🔐 Simple IDS - Snort Clone (Cybersecurity Project)

This is a lightweight Intrusion Detection System (IDS) built using Python, Scapy, and Flask. It detects real-time network-based attacks and alerts the user visually using desktop notifications on Ubuntu.

---

## 🚨 Features

- ✅ Detects common attacks:
  - ICMP Flood
  - TCP SYN Port Scan
  - HTTP GET Flood
  - SSH Brute Force
- ✅ Alerts:
  - Real-time `notify-send` tray notifications
  - Visual `zenity` popup dialog (attention grabber)
- ✅ Logs all alerts to `alerts.log`
- ✅ Web dashboard to view the last 20 alerts

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- Flask (for web UI)
- notify-send (Ubuntu notifications)
- zenity (GUI warning dialog)
- Git + GitHub for version control

---

## 🐧 Setup Instructions (Ubuntu)

Clone this repo and install dependencies:

```bash
sudo apt update
sudo apt install python3-scapy libnotify-bin zenity python3-flask git

git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
