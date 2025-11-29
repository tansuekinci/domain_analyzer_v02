# 🛡️ Domain Security & Intelligence Analyzer

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Domain Security & Intelligence Analyzer** is a Python-based automation tool designed to gather comprehensive intelligence, audit security vulnerabilities, and analyze the performance of a domain name.

This tool analyzes **DNS records**, discovers subdomains using **Sublist3r**, validates **Email Security Protocols** (SPF/DMARC/DKIM), performs **Blacklist/Reputation checks**, and measures web performance using **Google Lighthouse**. The results are presented in a stylish console output and exported as a detailed Excel report.

---

## 🚀 Features

### 🔍 Basic Intelligence
* Whois information lookup.
* IP location, ISP, and ASN detection.

### 🌐 DNS & Subdomain Discovery
* **Root Domain Records:** Extracts A, MX, NS, TXT, and other standard records.
* **Integrated Sublist3r:** Performs deep subdomain discovery by scraping passive sources.

### 📧 Email Security
* **Protocol Validation:** Checks for the presence and validity of SPF, DMARC, and DKIM records.
* **SMTP Health Check:** Tests server response via MXToolbox simulation.
* **Reputation Management:** Real-time IP reputation checks using DNSBL (Spamhaus, Spamcop) and AbuseIPDB API.

### ⚡ Web Performance
* Performance, SEO, and accessibility analysis using the **Google PageSpeed Insights (Lighthouse) API**.

### 🔌 Port Scanning
* Status checks for critical ports (80, 443, 21, 22, 3389, etc.) on discovered IP addresses.

### 📊 Reporting
* Generates a color-coded, multi-tabbed `.xlsx` (Excel) report containing all gathered data.

---

## 🛠️ Installation

### Prerequisites
* Python 3.x
* Git

### 1. Clone the Repository
Since the necessary modules (including Sublist3r) are bundled within the project, simply clone the repository:

    git clone https://github.com/tansuekinci/domain_analyzer_v02.git
    cd domain_analyzer_v02

### 2. Install Required Libraries
Install the necessary Python libraries using the `requirements.txt` file:

    pip3 install -r requirements.txt

> **Manual Installation:** If you run into issues, you can install them manually:
>
>     pip3 install requests python-whois pandas dnspython tabulate beautifulsoup4 openpyxl argparse

### ℹ️ Note on Sublist3r
The Sublist3r tool is already included in the `Sublist3r/` directory within this project. You do not need to install it separately.

**Troubleshooting:** If you encounter issues with the bundled version or need to update it to the latest version, you can replace the folder contents from the official repository:
* **Official Repository:** [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r)

---

## ⚙️ Configuration (API Keys)

To fully utilize the **Reputation Checks** and **Web Performance** features, you need to provide your own API keys in the `domain_check.py` file.

Open `domain_check.py` and locate the following lines at the top:

    PSI_API_KEY = "YOUR_GOOGLE_API_KEY"
    ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"

### 🔑 How to Get a Google PageSpeed Insights API Key
*Required for Web Performance, SEO, and Accessibility scores.*

1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Create a new project or select an existing one.
3.  Navigate to **APIs & Services > Library**.
4.  Search for **"PageSpeed Insights API"** and enable it.
5.  Go to **APIs & Services > Credentials**.
6.  Click **Create Credentials** and select **API Key**.
7.  Copy the key and paste it into the `PSI_API_KEY` variable in the script.

### 🔑 How to Get an AbuseIPDB API Key
*Required for checking if an IP address has been reported for malicious activity.*

1.  Register for a free account at [AbuseIPDB](https://www.abuseipdb.com/).
2.  Once logged in, go to the **API** tab in your profile settings.
3.  Click **Create Key**.
4.  Copy the key and paste it into the `ABUSEIPDB_API_KEY` variable in the script.

> **Note:** If you leave the keys empty, the script will skip these specific tests or run in a limited simulation mode.

---

## 🖥️ Usage

Run the script via terminal or command line:

    python3 domain_check.py [target_domain]

**Example:**

    python3 domain_check.py example.com

### Operation Modes
When started, the script checks for existing data files (e.g., `dns.txt`).

* **First Run:** Automatically performs DNS Discovery and Port Scanning.
* **Data Found:** It presents an interactive menu:
    1.  **Update Data:** Re-run Discovery.
    2.  **Run Port Scan & Web Performance:** Uses existing data to save time.
    3.  **Run ALL Tests:** Discovery + Port Scan + Web Perf.
    4.  **Run Mail Tests Only:** SMTP / Reputation / Auth checks.

---

## 📄 Outputs

Upon completion, the following files are generated in the project directory:

* `[domain].xlsx`: A detailed Excel report with multiple tabs for different analyses.
* `[domain]_dns.txt`: Raw DNS and Subdomain records.
* `[domain]_webservers.txt`: List of servers detected with open web ports.

---

## 🤝 Acknowledgments

This project utilizes the open-source tool **Sublist3r** for subdomain enumeration.

---

## ⚠️ Legal Disclaimer

This tool is designed for **educational purposes** and for security analysis of systems **you are authorized to test**. Using this tool on unauthorized systems is illegal. The developer cannot be held responsible for any misuse of this tool.
