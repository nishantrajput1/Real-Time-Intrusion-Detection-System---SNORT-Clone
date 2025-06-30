from flask import Flask, render_template
import os

app = Flask(__name__)
LOG_FILE = "alerts.log"

# Track the starting file size (position)
start_offset = 0
if os.path.exists(LOG_FILE):
    start_offset = os.path.getsize(LOG_FILE)

def read_alerts():
    alerts = []
    try:
        with open(LOG_FILE, "r") as f:
            f.seek(start_offset)  # Only read new lines after the app started
            for line in f:
                parts = line.strip().split("ALERT:")
                if len(parts) == 2:
                    timestamp, info = parts
                    alerts.append({'time': timestamp.strip('[] '), 'info': info.strip()})
    except FileNotFoundError:
        pass
    return alerts[-20:]  # Show last 20 alerts

@app.route("/")
def home():
    alerts = read_alerts()
    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)
