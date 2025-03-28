from flask import Flask, render_template, request
from dotenv import load_dotenv
import os
import requests
import json

app = Flask(__name__)

load_dotenv()
# API Keys (replace with your actual API keys)
ABUSE_IP_DB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
VIRUS_TOTAL_API_KEY = os.getenv('VIRUS_TOTAL_API_KEY')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

ABUSE_IP_DB_URL = 'https://api.abuseipdb.com/api/v2/reports'
VIRUS_TOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
SHODAN_URL = 'https://api.shodan.io/shodan/host/'

# Home page route
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip_address = request.form.get("ip_address")

        # Check if ip_address is None or empty
        if not ip_address:
            return render_template('index.html', error="Please enter a valid IP address.")

        ip_data = {}

        # **AbuseIPDB Reports API call**
        abuse_ip_db_params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 30,  # Optional: fetch reports within the last 30 days
            'perPage': 10,       # Optional: limit to 10 reports per page
            'page': 1            # Optional: set the page number for pagination
        }
        abuse_ip_db_headers = {
            'Key': ABUSE_IP_DB_API_KEY,
            'Accept': 'application/json'
        }
        abuse_ip_db_response = requests.get(ABUSE_IP_DB_URL, params=abuse_ip_db_params, headers=abuse_ip_db_headers)

        if abuse_ip_db_response.status_code == 200:
            abuse_ip_db_data = abuse_ip_db_response.json().get('data', {})
            ip_data['abuse_score'] = abuse_ip_db_data.get('abuseConfidenceScore', 'N/A')
            ip_data['total_reports'] = abuse_ip_db_data.get('total', 0)
            ip_data['reports'] = abuse_ip_db_data.get('results', [])
        else:
            ip_data['abuse_score'] = 'Error'
            ip_data['total_reports'] = 'Error'
            ip_data['reports'] = []

        # **VirusTotal API call**
        virus_total_headers = {
            'x-apikey': VIRUS_TOTAL_API_KEY
        }
        virus_total_response = requests.get(VIRUS_TOTAL_URL + ip_address, headers=virus_total_headers)

        if virus_total_response.status_code == 200:
            virus_total_data = virus_total_response.json().get('data', {})
            ip_data['virustotal'] = {
                'total_reports': virus_total_data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                'last_analysis_date': virus_total_data.get('attributes', {}).get('last_analysis_date', 'N/A')
            }
        else:
            ip_data['virustotal'] = {
                'total_reports': 'Error',
                'last_analysis_date': 'Error'
            }

        # **Shodan API call**
        shodan_response = requests.get(SHODAN_URL + ip_address, params={'key': SHODAN_API_KEY})

        if shodan_response.status_code == 200:
            shodan_data = shodan_response.json()
            ip_data['shodan'] = {
                'os': shodan_data.get('os', 'N/A'),
                'hostnames': shodan_data.get('hostnames', []),
                'city': shodan_data.get('location', {}).get('city', 'N/A'),
                'country': shodan_data.get('location', {}).get('country_name', 'N/A'),
                'isp': shodan_data.get('isp', 'N/A'),
                'org': shodan_data.get('org', 'N/A')
            }
        else:
            ip_data['shodan'] = {
                'os': 'Error',
                'hostnames': [],
                'city': 'Error',
                'country': 'Error',
                'isp': 'Error',
                'org': 'Error'
            }

        # Render the results template with ip_data passed as context
        return render_template('results.html', ip_data=ip_data)

    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
