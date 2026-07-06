# 🛡️ Web Application Vulnerability Scanner

A Python-based Web Application Vulnerability Scanner that performs automated security assessments on web applications. The scanner crawls target websites, analyzes forms and URLs, checks for common web security issues, and generates detailed vulnerability reports through an easy-to-use Flask web interface.

---

## 🌐 Live Demo

🔗 **Try the Web Application Vulnerability Scanner here:**

👉 **https://vuln-scanner-olnk.arcada.app**

> Enter a target URL to perform an authorized security assessment and view the generated vulnerability report through the web interface.

---

## 🌐 Features

- 🔍 Website Crawling
- 📝 HTML Form Discovery
- 🛡️ OWASP Top 10 Inspired Security Checks
- 🚨 Detection of Common Web Vulnerabilities
  - Cross-Site Scripting (XSS) Indicators
  - SQL Injection Error Detection
  - Missing Security Headers
  - Cookie Security Analysis
  - Information Disclosure
- 📊 Severity Classification (Low, Medium, High)
- 📄 HTML Scan Report Generation
- 🖥️ User-Friendly  Web Interface
- 📋 Detailed Scan Logs with Evidence


## 🛠️ Technologies Used

- Python 3
- Flask
- Requests
- BeautifulSoup4
- Regular Expressions (Regex)
- HTML/CSS
- Jinja2





## 🔎 Security Checks Performed

- Website Crawling
- Internal Link Discovery
- HTML Form Detection
- Security Header Analysis
- Cookie Security Checks
- Reflected Input Detection
- SQL Error Detection
- Information Disclosure
- HTTP Response Analysis

---

## 📊 Sample Report

| URL | Vulnerability | Severity | Evidence |
|-----|--------------|----------|----------|
| /login | Missing Content-Security-Policy | Medium | CSP Header Not Found |
| /search | Reflected Input Detected | Medium | User Input Reflected in Response |
| / | Missing X-Frame-Options | Low | Header Missing |

---

## 📌 Future Improvements

- PDF Report Export
- Authentication Support
- Login Session Scanning
- Directory Enumeration
- SSL/TLS Configuration Analysis
- JavaScript Security Checks
- Multi-threaded Scanning
- Scan History Dashboard

---



## 🎯 Learning Outcomes

This project demonstrates practical implementation of:

- Web Security Assessment
- Python Automation
- Web Crawling
- HTTP Request Analysis
- Secure Coding Practices
- Flask Web Development
- Vulnerability Reporting

---

## ⚠️ Disclaimer

This software is developed solely for educational purposes and authorized penetration testing. The developer is not responsible for any misuse of this tool. Always ensure you have explicit permission before scanning or testing any web application

## Usage

```bash
python3 main.py
```
