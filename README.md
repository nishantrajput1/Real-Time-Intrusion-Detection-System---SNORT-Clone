# 🔐 Simple IDS - Snort Clone (Cybersecurity Project)

A lightweight Intrusion Detection System (IDS) built using **Python**, **Scapy**, and **Flask**, designed to detect real-time network-based attacks. It triggers desktop alerts via Ubuntu notification systems and offers a minimal web UI for tracking threats.

---

## 🚨 Features

- ✅ Detects common network attacks:
  - ICMP Flood
  - TCP SYN Port Scan
  - HTTP GET Flood
  - SSH Brute Force Attempt
- ✅ Real-time alerting via:
  - `notify-send` tray notifications (Ubuntu)
  - `zenity` pop-up dialog (attention grabber)
- ✅ Logs all incidents to `alerts.log`
- ✅ Web dashboard to view the last 20 alerts

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- Flask (for dashboard)
- `notify-send` (desktop notifications)
- `zenity` (GUI warning dialog)
- Git + GitHub for version control

---
⚔️ Attack Simulation Details
To validate the effectiveness of the IDS, a series of simulated attacks were executed from a Windows machine targeting the Ubuntu VM (192.168.113.162) where the IDS was running. Each attack mimics a real-world intrusion technique, and detection logic was built accordingly.

🟡 ICMP Flood (Ping Attack)
Tool Used: Windows Command Prompt

Command:

bash
Copy
Edit
ping -t 192.168.113.162
Description: Sends continuous ICMP Echo Requests, which can flood the target system's network stack.

Detection Logic: The IDS counts the number of ICMP packets per second from the same IP. If it exceeds a predefined threshold (e.g., >10 packets/sec), an alert is triggered.

🔵 TCP SYN Port Scan
Tool Used: Nmap

Command:

bash
Copy
Edit
nmap -Pn -sS -T4 192.168.113.162
Description: Performs a stealth scan by sending TCP SYN packets to multiple ports to identify open ones.

Detection Logic: If numerous SYN packets from the same IP target different ports in a short time, the IDS flags it as a port scanning attempt.

🔴 HTTP GET Flood
Target Setup:
Ubuntu VM runs a basic HTTP server:

bash
Copy
Edit
sudo python3 -m http.server 80
Tool Used: Python script on Windows

Script:

python
Copy
Edit
import requests
url = "http://192.168.113.162"
for _ in range(30):
    try:
        requests.get(url)
    except:
        pass
Description: Sends a rapid sequence of HTTP GET requests to overwhelm the web server.

Detection Logic: The IDS monitors HTTP GET requests to port 80 and flags a flood when a threshold is crossed (e.g., >25 requests/sec from same IP).

🟣 SSH Brute Force Attempt
Tool Used: Windows Command Prompt

Command:

bash
Copy
Edit
for /L %i in (1,1,15) do ssh testuser@192.168.113.162
Description: Simulates repeated SSH login attempts within a short timeframe, mimicking brute-force behavior.

Detection Logic: The IDS tracks TCP connection attempts to port 22. If multiple SSH login attempts are detected from a single IP in quick succession, an alert is triggered.

✅ Detection Summary Table
Attack Type	Tool Used	Detection Criteria	Response
ICMP Flood	ping	>10 ICMP packets/sec	Zenity alert + Log + Dashboard
TCP SYN Port Scan	nmap	Multiple SYNs to different ports	Zenity alert + Log + Dashboard
HTTP GET Flood	requests	>25 GET requests/sec to port 80	Zenity alert + Log + Dashboard
SSH Brute Force	ssh loop	15+ rapid login attempts to port 22	Zenity alert + Log + Dashboard

These controlled attack simulations helped ensure the IDS reacts in real-time, offering both on-screen alerts and persistent logs to aid in post-attack analysis.
## 🐧 Setup Instructions (Ubuntu)

```bash
# Install dependencies
sudo apt update
sudo apt install python3-scapy libnotify-bin zenity python3-flask git

# Clone the repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
