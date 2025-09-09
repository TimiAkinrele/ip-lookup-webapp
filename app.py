from flask import Flask, render_template, request
from dotenv import load_dotenv
import os
import requests
import ipaddress
from datetime import datetime

app = Flask(__name__)
load_dotenv()

# === API Keys ===
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# === Endpoints ===
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_REPORTS_URL = "https://api.abuseipdb.com/api/v2/reports"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
SHODAN_URL = "https://api.shodan.io/shodan/host/"

# === Helpers ===
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def fmt_ts(ts):
    # VirusTotal returns UNIX epoch; AbuseIPDB returns ISO 8601 string
    if ts is None:
        return "N/A"
    if isinstance(ts, (int, float)):
        try:
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts)
    return ts

def http_get(url, **kwargs):
    # sensible defaults
    kwargs.setdefault("timeout", 8)
    return requests.get(url, **kwargs)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip_address = request.form.get("ip_address", "").strip()

        if not ip_address or not is_valid_ip(ip_address):
            return render_template("index.html", error="Please enter a valid IPv4/IPv6 address.")

        ip_data = {"input_ip": ip_address, "errors": []}

        # ---------- AbuseIPDB: CHECK (for confidence score, domain, usage type, etc.) ----------
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}
            r = http_get(ABUSEIPDB_CHECK_URL, headers=headers, params=params)
            if r.status_code == 200:
                data = r.json().get("data", {})
                ip_data["abuseipdb_check"] = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", "N/A"),
                    "country_code": data.get("countryCode", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "usage_type": data.get("usageType", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt", "N/A"),
                }
            else:
                ip_data["abuseipdb_check"] = None
                ip_data["errors"].append(f"AbuseIPDB Check error: {r.status_code}")
        except Exception as e:
            ip_data["abuseipdb_check"] = None
            ip_data["errors"].append(f"AbuseIPDB Check exception: {e}")

        # ---------- AbuseIPDB: REPORTS (list of recent reports) ----------
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 30, "perPage": 10, "page": 1}
            r = http_get(ABUSEIPDB_REPORTS_URL, headers=headers, params=params)
            if r.status_code == 200:
                data = r.json().get("data", {})
                ip_data["abuseipdb_reports"] = {
                    "total": data.get("total", 0),
                    "count": data.get("count", 0),
                    "results": data.get("results", []),
                }
            else:
                ip_data["abuseipdb_reports"] = None
                ip_data["errors"].append(f"AbuseIPDB Reports error: {r.status_code}")
        except Exception as e:
            ip_data["abuseipdb_reports"] = None
            ip_data["errors"].append(f"AbuseIPDB Reports exception: {e}")

        # ---------- VirusTotal ----------
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            r = http_get(VIRUSTOTAL_URL + ip_address, headers=headers)
            if r.status_code == 200:
                data = r.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                ip_data["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "last_analysis_date": fmt_ts(attrs.get("last_analysis_date")),
                }
            else:
                ip_data["virustotal"] = None
                ip_data["errors"].append(f"VirusTotal error: {r.status_code}")
        except Exception as e:
            ip_data["virustotal"] = None
            ip_data["errors"].append(f"VirusTotal exception: {e}")

        # ---------- Shodan ----------
        try:
            r = http_get(SHODAN_URL + ip_address, params={"key": SHODAN_API_KEY})
            if r.status_code == 200:
                data = r.json()
                loc = data.get("location", {}) if isinstance(data.get("location"), dict) else {}
                ip_data["shodan"] = {
                    "os": data.get("os", "N/A"),
                    "hostnames": ", ".join(data.get("hostnames", []) or []) or "—",
                    "city": loc.get("city", "N/A"),
                    "country": loc.get("country_name", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "org": data.get("org", "N/A"),
                    "ports": ", ".join([str(p) for p in data.get("ports", [])]) if data.get("ports") else "—",
                }
            else:
                ip_data["shodan"] = None
                ip_data["errors"].append(f"Shodan error: {r.status_code}")
        except Exception as e:
            ip_data["shodan"] = None
            ip_data["errors"].append(f"Shodan exception: {e}")

        return render_template("results.html", ip_data=ip_data)

    return render_template("index.html")
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
