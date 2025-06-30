from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw
from datetime import datetime
from collections import defaultdict
import threading
import os

# Packet counters per IP
icmp_counter = defaultdict(int)
tcp_scan_tracker = defaultdict(set)
http_counter = defaultdict(int)
ssh_attempts = defaultdict(int)
alert_log = []

# Detection thresholds
ICMP_THRESHOLD = 4
PORT_SCAN_THRESHOLD = 10
HTTP_THRESHOLD = 10
SSH_THRESHOLD = 10

WHITELIST_FILE = "whitelist.txt"

# Load and add to whitelist
def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def add_to_whitelist(ip):
    with open(WHITELIST_FILE, "a") as f:
        f.write(ip + "\n")

# Color print helper (for terminal aesthetics)
def color(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

# Logging alerts + Interactive Zenity Popup
def log_alert(alert_type, src_ip):
    whitelist = load_whitelist()
    if src_ip in whitelist:
        return  # Don't alert for whitelisted IPs

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert = f"[{timestamp}] 🛡️ ALERT: {alert_type} from {src_ip}"
    print(color(alert, '91'))  # Bright Red

    alert_log.append({'time': timestamp, 'type': alert_type, 'ip': src_ip})
    with open("alerts.log", "a") as f:
        f.write(alert + "\n")

    # Zenity popup to ask user for trust
    response = os.system(
        f'zenity --question --title="🚨 Intrusion Alert" '
        f'--text="❗ {alert_type} from {src_ip}\n\n👉 Do you trust this IP?" '
        f'--ok-label="✅ Trust" --cancel-label="🚫 Ignore" --timeout=10'
    )

    if response == 0:
        add_to_whitelist(src_ip)
        print(color(f"[INFO] {src_ip} added to whitelist.", '92'))  # Bright Green

# Reset counters periodically
def reset_counters():
    while True:
        icmp_counter.clear()
        tcp_scan_tracker.clear()
        http_counter.clear()
        ssh_attempts.clear()
        threading.Event().wait(5)

# Main detection logic
def detect_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src

        if ICMP in pkt:
            icmp_counter[src_ip] += 1
            if icmp_counter[src_ip] > ICMP_THRESHOLD:
                log_alert("💥 ICMP Flood Detected", src_ip)

        if TCP in pkt and pkt[TCP].flags == "S":
            dport = pkt[TCP].dport
            tcp_scan_tracker[src_ip].add(dport)
            if len(tcp_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                log_alert("🛠️ TCP Port Scan Detected", src_ip)

        if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
            if b"GET" in pkt[Raw].load:
                http_counter[src_ip] += 1
                if http_counter[src_ip] > HTTP_THRESHOLD:
                    log_alert("🌐 HTTP GET Flood Detected", src_ip)

        if TCP in pkt and pkt[TCP].dport == 22 and pkt[TCP].flags == "S":
            ssh_attempts[src_ip] += 1
            if ssh_attempts[src_ip] > SSH_THRESHOLD:
                log_alert("🔐 SSH Brute Force Attempt", src_ip)

# Start background thread for resetting
threading.Thread(target=reset_counters, daemon=True).start()

# Start the IDS
print(color("[*] IDS is now ACTIVE. Monitoring traffic... 🕵️‍♂️", '94'))
sniff(filter="ip", prn=detect_packet, store=0)

