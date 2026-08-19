📋 Overview <img width="657" height="512" alt="himarecon" src="https://github.com/user-attachments/assets/3fd32259-ec39-4b42-94a1-311d14ed4c58" />

<img width="1920" height="1080" alt="himarecon 2" src="https://github.com/user-attachments/assets/ddc75143-716f-469f-8c30-14afe627c58f" />

WebRecon is a professional, all-in-one web reconnaissance and intelligence gathering tool designed for security professionals, penetration testers, and bug bounty hunters. It provides comprehensive information gathering capabilities through a clean, colorful CLI interface with real-time progress tracking.

Built with Python 3.10+, WebRecon automates the entire reconnaissance process, from basic WHOIS lookups to advanced subdomain enumeration and WAF detection.

🎯 Key Features
⚡ Multi-threaded Scanning - Lightning-fast directory and subdomain discovery

🎨 Rich CLI Interface - Beautiful, color-coded output with progress bars

📊 Comprehensive Reports - JSON and TXT report generation

🔧 Auto-Dependency Management - Automatic installation of required modules

🌐 Cross-Platform - Works on Linux, Kali, Ubuntu, and Windows

🛡️ Error Resilient - Proper exception handling and timeout management

🚀 Features Breakdown
1. WHOIS Lookup
Registrar Information

Creation & Expiry Dates

Name Servers

Domain Status

2. NS Lookup
IP Resolution

Reverse DNS Lookup

Nameserver Records

3. DNS Records
A Records

AAAA Records

MX Records

TXT Records

CNAME Records

NS Records

4. Ping Check
Latency Measurement

Packet Loss Analysis

OS Detection (Linux/Windows)

5. Traceroute
Cross-platform support

Hop-by-hop analysis

10-hop limit for speed

6. WAF Detection
Detects major WAF providers:

Cloudflare

Akamai

Imperva

Sucuri

AWS WAF

F5 BIG-IP

Fortinet

Azure Front Door

Fastly

7. HTTP Header Analysis
Status Code Analysis

Server Information

Powered-By Detection

Security Headers Audit

Cookie Analysis

Redirect Detection

Robots.txt Check

Sitemap.xml Check

8. Directory Discovery
50+ Common Directories

Built-in Wordlist

Multi-threaded Scanning

Status Code Classification

9. Subdomain Enumeration
crt.sh Integration

Hackertarget API

DNS Brute-force

Built-in Wordlist

Duplicate Removal

10. All-in-One Recon
Automated comprehensive scanning including:

✅ WHOIS Lookup

✅ DNS Records

✅ IP Resolution

✅ Reverse DNS

✅ HTTP Headers

✅ Security Headers

✅ WAF Detection

✅ Ping Check

✅ Traceroute

✅ Subdomain Enumeration

✅ Directory Discovery

📦 Installation
Prerequisites
Python 3.10 or higher

Git (optional)

Quick Install
bash
# Clone the repository
git clone https://github.com/yourusername/webrecon.git
cd webrecon

# Make it executable (Linux/Mac)
chmod +x webrecon.py

# Run the tool (auto-installs dependencies)
python3 webrecon.py
Manual Dependency Installation
bash
# Using pip
pip install -r requirements.txt

# For Kali/Ubuntu/Debian systems
sudo apt install python3-requests python3-dnspython python3-whois python3-rich python3-colorama python3-tqdm python3-bs4 python3-lxml
🎮 Usage
Basic Usage
bash
python3 webrecon.py
Step-by-Step
Launch the tool

bash
python3 webrecon.py
Enter target

text
Enter target URL or domain: example.com
Select an option from the menu

text
============================================================
MAIN MENU
============================================================
1. WHOIS Lookup
2. NS Lookup
3. DNS Records (A, AAAA, MX, TXT, CNAME)
4. Ping Check
5. Traceroute
6. WAF Detection
7. HTTP Header Analysis
8. Directory Discovery
9. Subdomain Enumeration
10. Basic All-in-One Recon
0. Exit
============================================================
Enter your choice: 
Example Output
https://raw.githubusercontent.com/yourusername/webrecon/main/assets/demo.gif

📊 Report Generation
WebRecon automatically generates comprehensive reports in two formats:

JSON Report
json
{
  "target": "https://example.com",
  "domain": "example.com",
  "timestamp": "2024-01-15T10:30:00",
  "results": {
    "whois": {
      "Registrar": "Example Registrar",
      "Creation Date": "2000-01-01",
      "Expiry Date": "2025-01-01"
    }
  }
}
TXT Report
text
WebRecon Report
============================================================
Target: https://example.com
Domain: example.com
Timestamp: 2024-01-15 10:30:00
============================================================

WHOIS
----------------------------------------
Registrar: Example Registrar
Creation Date: 2000-01-01
...
Reports are automatically saved in the reports/ directory with timestamped filenames.

🛠️ Technical Details
Architecture
Single File Design - Portable and easy to deploy

Object-Oriented - Clean, maintainable code structure

Thread Pool Executor - Efficient multi-threading

Session Management - Optimized HTTP connections

Dependencies
Module	Purpose	Version
requests	HTTP Requests	2.28+
dnspython	DNS Resolution	2.2+
python-whois	WHOIS Queries	0.7+
rich	CLI UI Enhancement	13.0+
colorama	Cross-platform Colors	0.4+
tqdm	Progress Bars	4.64+
beautifulsoup4	HTML Parsing	4.11+
lxml	XML Processing	4.9+
🔒 Security & Privacy
No Data Storage - Reports are stored locally only

No Tracking - No external data collection

HTTPS Support - Secure connections where possible

Timeout Limits - Prevents hanging requests

Error Handling - Graceful failure recovery

🤝 Contributing
Contributions are welcome! Here's how you can help:

Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

Development Guidelines
Follow PEP 8 style guide

Add comments for complex logic

Update documentation as needed

Test on multiple platforms

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Built with Python and open-source libraries

Inspired by various recon tools and techniques

Special thanks to the security community

📞 Contact & Support
Developer: Hima Cyber Expert

Issues: GitHub Issues

Discussions: GitHub Discussions

⚠️ Disclaimer
WebRecon is designed for educational and authorized security testing purposes only.

Always obtain proper authorization before scanning any system

Use responsibly and in compliance with applicable laws

The developer is not responsible for any misuse of this tool

Ensure you have permission to test the target systems

<p align="center"> Made with ❤️ by Hima Cyber Expert </p><p align="center"> ⭐ Star us on GitHub — it motivates us! </p><img width="657" height="512" alt="himarecon" src="https://github.com/user-attachments/assets/da9976f6-aa63-4e05-8430-2ede83fff30a" />
<img width="657" height="512" alt="himarecon" src="https://github.com/user-attachments/assets/f6bac741-c564-4d52-a661-c286565b438b" />
<img width="657" height="512" alt="himarecon" src="https://github.com/user-attachments/assets/72bb5f15-8216-4633-b682-5b43c4b0479d" />
