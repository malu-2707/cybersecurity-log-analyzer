
from flask import Flask, request, render_template_string
from collections import Counter
import re
import ipaddress

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberShield | Log Analyzer</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0; font-family: Arial, sans-serif;
  background: #0b1120; color: #e5edf9;
}
header {
  padding: 24px; text-align: center;
  background: #111c32; border-bottom: 1px solid #263650;
}
header h1 { color: #38bdf8; margin-bottom: 8px; }
main { max-width: 850px; margin: 30px auto; padding: 0 18px; }
.card {
  background: #142039; border: 1px solid #2b3c58;
  padding: 24px; border-radius: 14px; margin-bottom: 22px;
}
label { display: block; margin: 14px 0 8px; }
textarea, input {
  width: 100%; padding: 12px; border-radius: 7px;
  border: 1px solid #405270; background: #0b1120;
  color: white;
}
textarea { min-height: 180px; resize: vertical; }
button {
  margin-top: 16px; padding: 12px 20px;
  background: #38bdf8; border: 0; border-radius: 7px;
  color: #07111f; font-weight: bold; cursor: pointer;
}
.stat { font-size: 26px; color: #38bdf8; font-weight: bold; }
.alert { color: #fbbf24; }
li { margin: 10px 0; overflow-wrap: anywhere; }
footer { text-align: center; color: #94a3b8; padding: 24px; }
</style>
</head>
<body>
<header>
  <h1>🛡️ CyberShield</h1>
  <p>Cybersecurity Log Analyzer</p>
</header>
<main>
  <section class="card">
    <h2>Analyze Authentication Logs</h2>
    <p>Paste synthetic or authorized log entries to detect repeated failed logins.</p>
    <form method="post">
      <label for="threshold">Alert threshold</label>
      <input id="threshold" type="number" name="threshold"
             min="1" max="1000" value="{{ threshold }}" required>
      <label for="logs">Log entries</label>
      <textarea id="logs" name="logs" maxlength="100000"
        required placeholder="Paste log entries here">{{ logs }}</textarea>
      <button type="submit">Analyze Logs</button>
    </form>
  </section>

  {% if results is not none %}
  <section class="card">
    <h2>Analysis Report</h2>
    <p>Matching failed-login events</p>
    <div class="stat">{{ total }}</div>
    <p>Unique valid source IPs: {{ unique_ips }}</p>
    <h3>Attempts by IP</h3>
    {% if counts %}
    <ul>
      {% for ip, count in counts %}
      <li>{{ ip }} — {{ count }} failed attempts</li>
      {% endfor %}
    </ul>
    {% else %}
    <p>No matching failed-login entries found.</p>
    {% endif %}
    <h3 class="alert">IPs flagged for review</h3>
    {% if results %}
    <ul>
      {% for ip, count in results %}
      <li class="alert">{{ ip }} — {{ count }} attempts</li>
      {% endfor %}
    </ul>
    {% else %}
    <p>No IPs reached the selected threshold.</p>
    {% endif %}
    <p>Alerts are investigation leads, not proof of malicious activity.</p>
  </section>
  {% endif %}
</main>
<footer>Educational project • Use only authorized data</footer>
</body>
</html>
"""

PATTERN = re.compile(
    r"Failed password for .*? from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)

@app.route("/", methods=["GET", "POST"])
def home():
    logs = ""
    threshold = 3
    results = None
    counts = []
    total = 0
    unique_ips = 0

    if request.method == "POST":
        logs = request.form.get("logs", "")[:100000]

        try:
            threshold = int(request.form.get("threshold", "3"))
        except ValueError:
            threshold = 3

        threshold = max(1, min(threshold, 1000))
        attempts = Counter()

        for line in logs.splitlines():
            match = PATTERN.search(line)
            if not match:
                continue

            total += 1
            ip = match.group("ip")

            try:
                validated_ip = str(ipaddress.ip_address(ip))
                attempts[validated_ip] += 1
            except ValueError:
                continue

        unique_ips = len(attempts)
        counts = sorted(attempts.items())
        results = [
            (ip, count) for ip, count in counts
            if count >= threshold
        ]

    return render_template_string(
        HTML,
        logs=logs,
        threshold=threshold,
        results=results,
        counts=counts,
        total=total,
        unique_ips=unique_ips
    )

@app.errorhandler(413)
def file_too_large(error):
    return "Input too large. Please use a smaller log sample.", 413

if __name__ == "__main__":
    app.run(debug=False)
