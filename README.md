# 🛡️ PHPShield v4 — Security Analysis Suite

**Developed by Abdul Samad**  
**Aror University of Art, Architecture, Design & Heritage, Sukkur**

PHPShield is a Python-based defensive security analysis tool designed to review PHP source code, PHP configuration files, and web-server access logs for suspicious patterns and potentially insecure settings.

It provides a desktop GUI with security findings, severity filters, analytics, persistent scan history, and PDF, CSV, and JSON report exports.

> **Important:** PHPShield is an educational security analysis tool. Its findings are heuristic indicators, not proof of a vulnerability or confirmed attack.

---

## 🚀 Key Features

### 🔍 1. PHP Source Code Scanner
- Scans PHP project folders for selected suspicious code patterns.
- Flags indicators involving `eval()`, operating-system command execution functions, and `unserialize()`.
- Identifies selected weak password-hashing patterns and potential SQL string concatenation.
- Displays finding severity, file, line number, and remediation recommendations.

### ⚙️ 2. PHP Configuration Auditor
- Reviews selected settings in `php.ini`.
- Checks configurations such as `display_errors`, `expose_php`, `allow_url_include`, and session cookie security settings.
- Flags settings that differ from the tool's recommended values.

### 📑 3. Web-Server Access Log Analyzer
- Reviews local access logs for selected suspicious request patterns.
- Flags indicators associated with possible SQL injection, path traversal, cross-site scripting, and command injection.
- Provides recommendations for further investigation.

**Note:** Suspicious log patterns do not independently confirm that an attack occurred.

### 📊 4. Security Dashboard and Analytics
- Displays scan statistics and severity counts.
- Provides a heuristic risk indicator from 0 to 100.
- Includes severity-distribution visualization.
- Supports finding search and severity filtering.

The risk indicator is a simple heuristic score. It is not a CVSS rating, a probability of compromise, or a guarantee of security.

### 🗂️ 5. Persistent Scan History
- Saves scan results locally using SQLite.
- Allows users to review previous scans.
- Supports loading saved results and deleting selected history entries.

### 📄 6. Security Report Generation
Export scan results in the following formats:

- **PDF:** Security assessment report with findings and recommendations.
- **CSV:** Tabular data for spreadsheets and further analysis.
- **JSON:** Structured report data for programmatic review.

### 🖥️ 7. Desktop GUI
- Built with Python and Tkinter.
- Dark black, red, and white cybersecurity-inspired interface.
- Includes Dashboard, Findings, Analytics, Scan History, Activity, and About tabs.

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic and scanning |
| Tkinter | Desktop graphical interface |
| Regular Expressions | Pattern-based security checks |
| SQLite | Persistent local scan history |
| Matplotlib | Security analytics and charts |
| ReportLab | PDF report generation |
| CSV and JSON | Report export formats |

---

## 📋 Requirements

- Python 3
- Tkinter support
- Dependencies listed in `requirements.txt`

The project uses Python's standard library for core scanning, file handling, and SQLite storage. Matplotlib and ReportLab are required for analytics and PDF reporting.

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/sami0x-pk/PHPShield-Security-Analysis-Suite.git
```

### 2. Open the Project Directory

```bash
cd PHPShield-Security-Analysis-Suite
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Launch PHPShield

```bash
python app.py
```

The PHPShield desktop application should open.

**Alternative:** Open `PHPShield_v4.ipynb` in Jupyter Notebook and run the setup cell followed by the GUI-launch cell. Keep `app.py` in the same project directory as the notebook.

---

## 🧪 Running the Scanner

### PHP Source Scan
1. Open PHPShield.
2. Select **FOLDER**.
3. Choose a local PHP project directory.
4. Click **SCAN PHP**.
5. Review the findings and remediation recommendations.

### PHP Configuration Audit
1. Click **PHP CONFIG**.
2. Select a local `php.ini` file.
3. Review the flagged settings.

### Access Log Analysis
1. Click **ANALYZE LOG**.
2. Select a local access log.
3. Review suspicious indicators and investigate relevant entries.

### Export a Report
After running a scan, select **PDF REPORT**, **CSV**, or **JSON** and choose where to save the report.

### Review Previous Scans
Open **SCAN HISTORY** to review saved sessions, load previous results, or delete an individual history entry.

---

## 🛡️ Web Shell Detection — Future Roadmap

A dedicated Web Shell Detection Module is a planned enhancement. These capabilities are **not claimed as fully implemented in the current v4 release**.

### Planned Improvements

- **Advanced Pattern Detection:** Expand static checks for suspicious and obfuscated PHP code patterns.
- **Unexpected PHP File Detection:** Help identify newly created or unexpected executable PHP files, including files located in upload directories.
- **File Integrity Checks:** Calculate file hashes and support comparisons to help identify changes between scans.
- **Severity Classification:** Assign suitable severity levels and actionable remediation guidance to web-shell-related findings.
- **Scan History Integration:** Store web-shell scan results for later review and comparison.
- **Report Integration:** Include relevant findings, file details, hashes, severity, and recommendations in security reports.

These improvements aim to make PHPShield more useful for defensive PHP application review and suspicious-file investigation.

### Important Limitation

PHPShield cannot guarantee detection of every web shell. Malicious code may use obfuscation, unfamiliar functions, indirect execution, or techniques that its pattern-based checks do not recognize. A dedicated detection module would also require careful testing and validation.

For better defensive coverage, combine static analysis with file-integrity monitoring, secure upload handling, server logs, access controls, and manual investigation.

---

## ⚠️ Security Limitations

PHPShield uses selected rules and heuristic checks. It is not a complete antivirus, endpoint detection system, web application firewall, or professional penetration-testing platform.

- False positives may occur.
- Vulnerabilities and malicious files may be missed.
- A clean scan does not prove that an application is secure.
- Configuration recommendations should be reviewed against the application's deployment requirements.
- Access-log findings are suspicious indicators, not confirmation of successful exploitation.
- The risk indicator is not a standardized security score.
- Scanning is performed on selected local files and logs; the application does not perform live attacks against websites.

All findings should be manually reviewed before remediation decisions are made.

---

## 🔐 Ethical Use

PHPShield is intended for educational purposes, defensive security analysis, and authorized auditing.

Use it only on PHP projects, configuration files, and logs that you own or are authorized to review. Do not use scan results as the sole basis for declaring a system secure or compromised.

---

## 📁 Project Structure

```text
PHPShield-Security-Analysis-Suite/
│
├── app.py
├── PHPShield_v4.ipynb
├── README.md
├── requirements.txt
├── Run_PHPShield.bat
│
├── tests/
│   ├── test_scanners.py
│   └── test_v4.py
│
└── sample_data/
    ├── sample.php
    ├── php_test.ini
    ├── access.log
    └── example_report.pdf
```

The exact files may vary by release or repository update.

---

## 🧪 Tests

Run the included automated tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests cover selected scanner and application logic. Passing tests do not establish complete vulnerability-detection coverage.

---

## 📚 References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) — Defensive guidance for handling uploaded files.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Web application security testing guidance.
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/) — Security research and threat-analysis articles.

These resources provide additional defensive context; they do not imply that PHPShield implements every technique discussed in them.

---

## 👨‍💻 Developer

**Abdul Samad**  
Aror University of Art, Architecture, Design & Heritage, Sukkur, Pakistan

**Project:** PHPShield v4 — Security Analysis Suite  
**Focus:** Defensive PHP security analysis, configuration auditing, suspicious log review, and security reporting.

---

## ⭐ Acknowledgment

PHPShield is an educational cybersecurity project intended to support security awareness and defensive analysis of PHP applications.

If you find the project useful, consider starring the repository and sharing feedback or suggestions for future improvements.
