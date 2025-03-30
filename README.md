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
## Configuration
Before running the application, you need to set up the following API keys for the services:
- AbuseIPDB: Sign up and get the API Key
- VirusTotal: Sign up and get the API Key
- Shodan: Sign up and get the API Key
