# domain_analyzer_v02
Analyze given domain's web and mail systems
🛡️ Domain Security & Intelligence Analyzer
Domain Security & Intelligence Analyzer is a Python-based automation tool designed to gather comprehensive intelligence, audit security vulnerabilities, and analyze the performance of a domain name.

This tool analyzes DNS records, discovers subdomains using Sublist3r, validates Email Security Protocols (SPF/DMARC/DKIM), performs Blacklist/Reputation checks, and measures web performance using Google Lighthouse. The results are presented in a stylish console output and exported as a detailed Excel report.

🚀 Features
🔍 Basic Intelligence: Whois information, IP location, ISP, and ASN detection.

🌐 DNS & Subdomain Discovery:

Root domain DNS records (A, MX, NS, TXT, etc.).

Integrated Sublist3r Support: Deep subdomain discovery by scraping passive sources.

📧 Email Security:

Presence and validation checks for SPF, DMARC, and DKIM records.

SMTP Health Check: Server response testing via MXToolbox simulation.

Reputation Management: Real-time IP reputation checks using DNSBL (Spamhaus, Spamcop) and AbuseIPDB API.

⚡ Web Performance: Performance, SEO, and accessibility analysis using the Google PageSpeed Insights (Lighthouse) API.

🔌 Port Scanning: Status checks for critical ports (80, 443, 21, 22, 3389, etc.) on discovered IP addresses.

📊 Reporting: Generates a color-coded, multi-tabbed .xlsx (Excel) report containing all gathered data.

🛠️ Installation
Prerequisites
Python 3.x

Git

1. Clone the Repository
Since the necessary modules (including Sublist3r) are bundled within the project, simply clone the repository:

Bash

git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
2. Install Required Libraries
Install the necessary Python libraries using the requirements.txt file:

Bash

pip3 install -r requirements.txt
(If you run into issues, you can install them manually: pip3 install requests python-whois pandas dnspython tabulate beautifulsoup4 openpyxl argparse)

ℹ️ Note on Sublist3r
The Sublist3r tool is already included in the Sublist3r/ directory within this project. You do not need to install it separately.

Troubleshooting: If you encounter issues with the bundled version or need to update it to the latest version, you can replace the folder contents from the official repository:

Official Repository: https://github.com/aboul3la/Sublist3r

⚙️ Configuration (API Keys)
To fully utilize the Reputation Checks and Web Performance features, you need to provide your own API keys in the domain_check.py file.

Open domain_check.py and locate the following lines at the top:

Python

PSI_API_KEY = "YOUR_GOOGLE_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"
🔑 How to Get a Google PageSpeed Insights API Key
Required for Web Performance, SEO, and Accessibility scores.

Go to the Google Cloud Console.

Create a new project or select an existing one.

Navigate to APIs & Services > Library.

Search for "PageSpeed Insights API" and enable it.

Go to APIs & Services > Credentials.

Click Create Credentials and select API Key.

Copy the key and paste it into the PSI_API_KEY variable in the script.

🔑 How to Get an AbuseIPDB API Key
Required for checking if an IP address has been reported for malicious activity.

Register for a free account at AbuseIPDB.

Once logged in, go to the API tab in your profile settings.

Click Create Key.

Copy the key and paste it into the ABUSEIPDB_API_KEY variable in the script.

(Note: If you leave the keys empty, the script will skip these specific tests or run in a limited simulation mode.)

🖥️ Usage
Run the script via terminal or command line:

Bash

python3 domain_check.py [target_domain]
Example:

Bash

python3 domain_check.py example.com
Operation Modes
When started, the script checks for existing data files (dns.txt).

First Run: Automatically performs DNS Discovery and Port Scanning.

Data Found: It presents an interactive menu:

1 - Update Data (Re-run Discovery)

2 - Run Port Scan & Web Performance (Using existing data)

3 - Run ALL Tests (Discovery + Port Scan + Web Perf)

4 - Run Mail Tests Only (SMTP/Reputation/Auth)

📄 Outputs
Upon completion, the following files are generated in the project directory:

[domain].xlsx: A detailed Excel report with multiple tabs for different analyses.

[domain]_dns.txt: Raw DNS and Subdomain records.

[domain]_webservers.txt: List of servers detected with open web ports.

🤝 Acknowledgments
This project utilizes the open-source tool Sublist3r for subdomain enumeration.

⚠️ Legal Disclaimer
This tool is designed for educational purposes and for security analysis of systems you are authorized to test. Using this tool on unauthorized systems is illegal. The developer cannot be held responsible for any misuse of this tool.
