# IP Lookup Web Application

## Overview
This project is a Flask-based web application that performs IP address lookups using three different services: AbuseIPDB, VirusTotal, and Shodan. The app allows users to input an IP address and receive information such as:
- AbuseIPDB Reports: Shows the abuse score and detailed reports on the given IP address.
- VirusTotal Analysis: Displays the number of malicious reports and the last analysis date for the IP address.
- Shodan Information: Provides information about the IP address's operating system, hostnames, location, ISP, and organization.

## Requirements
To run this project, you’ll need the following:
- Python 3.x
- Flask
- Requests (for API calls)
- API Keys for AbuseIPDB, VirusTotal, and Shodan

## Installing Dependencies
1. Clone the repository or download the project folder.
2. Create a virtual environment (optional but recommended):

  ```
  python3 -m venv venv
  ```

Activate the virtual environment:
### Windows:
  ```
  venv\Scripts\activate
  ```
### macOS/Linux:
  ```
  source venv/bin/activate
  ```

### Install the necessary Python packages:
  ```
  pip install -r requirements.txt
  ```

### If you don't have a requirements.txt file yet, you can manually install the required packages:
  ```
  pip install flask requests
  ```

### You may have to install the required python-dotenv package aswell via:
  ```
  pip install python-dotenv
  ```

## Configuration
Before running the application, you need to set up the following API keys for the services:
- AbuseIPDB: Sign up and get the API Key
- VirusTotal: Sign up and get the API Key
- Shodan: Sign up and get the API Key

  Once you've acquired your API Keys update the following variables in ```app.py```
  ```
  ABUSEIPDB_API_KEY = 'YOUR_ABUSE_IP_DB_API_KEY'
  VIRUS_TOTAL_API_KEY = 'YOUR_VIRUS_TOTAL_API_KEY'
  SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
  ```
  
## Running the Application
1. Make sure all dependencies are installed.
2. Run the Flask application:
```
  python app.py
```
The application will be available at ```http://127.0.0.1:5000/``` by default. Open this URL in your web browser.

## How to Use the Application
- Visit the web application on your browser.
- On the home page, enter an IP address in the provided input field.
- Click Submit to see the results. The application will fetch information from AbuseIPDB, VirusTotal, and Shodan and display it in a tabular format.

You can see:
- The AbuseIPDB reports and abuse confidence score.
- VirusTotal analysis, including the last analysis date and malicious reports.
- Shodan information like the operating system, hostnames, location, and ISP.
