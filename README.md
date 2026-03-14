<div align="center">

# 🛡️ XSS Scanner

**A modular, automated Cross-Site Scripting (XSS) vulnerability scanner built in Python.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/rohit-1006/XSS_Scanner?style=flat-square&color=facc15)](https://github.com/rohit-1006/XSS_Scanner/stargazers)
[![Issues](https://img.shields.io/github/issues/rohit-1006/XSS_Scanner?style=flat-square)](https://github.com/rohit-1006/XSS_Scanner/issues)
[![Last Commit](https://img.shields.io/github/last-commit/rohit-1006/XSS_Scanner?style=flat-square)](https://github.com/rohit-1006/XSS_Scanner/commits/main)

<br/>

[Features](#-features) • [Project Structure](#-project-structure) • [Installation](#-installation) • [Usage](#-usage) • [How It Works](#-how-it-works) • [Contributing](#-contributing) • [Disclaimer](#️-legal-disclaimer)

</div>

---

## 📖 Overview

**XSS Scanner** is a fully modular, Python-based tool for detecting **Cross-Site Scripting (XSS)** vulnerabilities in web applications. It combines an intelligent web crawler, multiple detection engines, advanced payload encoding, false-positive filtering, and HTML report generation into a clean, extensible architecture.

Designed for **security researchers**, **penetration testers**, and **developers** who want to audit their applications for XSS vulnerabilities before attackers do.

> ⚠️ **For authorized testing only.** See the [Legal Disclaimer](#️-legal-disclaimer) at the bottom.

---

## ✨ Features

- 🕷️ **Web Crawler** — Automatically spiders target websites to discover all endpoints and injectable parameters
- 🔍 **Reflected XSS Detection** — Tests URL parameters for content reflected in server responses
- 🧠 **DOM-Based XSS Detection** — Analyzes client-side JavaScript sinks for DOM manipulation vulnerabilities
- 📝 **Form Detection** — Discovers and tests all HTML form inputs for injection points
- 💉 **Advanced Payload Engine** — Ships with a curated payload library plus encoding techniques (HTML, URL, Unicode) to bypass filters
- 🎯 **Custom Payloads** — Supports user-supplied payload lists via `payloads/custom_payloads.txt`
- 🚫 **False Positive Filtering** — Intelligent analysis to reduce noise and improve result accuracy
- 📊 **HTML Report Generation** — Produces detailed, styled HTML vulnerability reports
- ⚙️ **Configurable** — Centralized `config.py` for easy tuning of scan behaviour

---

## 📁 Project Structure

```
XSS_Scanner/
│
├── analyzer/
│   ├── false_positive.py      # Filters false positives from scan results
│   └── reflection.py          # Checks if payloads are reflected in responses
│
├── crawler/
│   └── spider.py              # Web spider to discover URLs and parameters
│
├── detector/
│   ├── dom_analyzer.py        # DOM-based XSS detection logic
│   └── form_detector.py       # Detects and extracts HTML form fields
│
├── engine/
│   ├── payloads.py            # Core XSS payload library
│   ├── advanced_payloads.py   # Advanced & filter-bypass payloads
│   ├── encoders.py            # Payload encoding (URL, HTML, Unicode, etc.)
│   └── injector.py            # Injects payloads into discovered parameters
│
├── payloads/
│   └── custom_payloads.txt    # User-defined custom payload list
│
├── reporter/
│   └── html_report.py         # Generates detailed HTML vulnerability reports
│
├── config.py                  # Global configuration settings
├── main.py                    # Entry point — orchestrates the full scan
├── requirements.txt           # Python dependencies
└── LICENSE
```

---

## 📦 Installation

### Prerequisites

- Python **3.8** or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/rohit-1006/XSS_Scanner.git

# 2. Navigate into the directory
cd XSS_Scanner

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python main.py -u <target_url> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--url` | **Required.** Target URL to scan |
| `-c`, `--crawl` | Enable web crawler to discover all endpoints |
| `--forms` | Scan HTML forms for injection points |
| `--dom` | Enable DOM-based XSS analysis |
| `--payloads` | Path to a custom payloads file |
| `--encode` | Apply encoding to payloads to bypass filters |
| `--report` | Generate an HTML report of findings |
| `--threads` | Number of concurrent threads (default: 5) |
| `-v`, `--verbose` | Enable verbose output |

> **Note:** Update this table to reflect your exact CLI flags from `main.py`.

---

## 💡 Examples

**Basic scan on a single URL:**
```bash
python main.py -u https://example.com
```

**Full crawl + form detection + HTML report:**
```bash
python main.py -u https://example.com --crawl --forms --report
```

**Scan with a custom payload list and encoding:**
```bash
python main.py -u https://example.com --payloads payloads/custom_payloads.txt --encode
```

**DOM-based XSS scan with verbose output:**
```bash
python main.py -u https://example.com --dom -v
```

---

## ⚙️ Configuration

Edit `config.py` to customize scan behaviour:

```python
# config.py (example settings)
THREADS          = 10            # Concurrent scanning threads
TIMEOUT          = 10            # Request timeout in seconds
MAX_DEPTH        = 3             # Crawler depth limit
USER_AGENT       = "XSSScanner/1.0"
FOLLOW_REDIRECTS = True
REPORT_OUTPUT    = "report.html"
```

---

## 🔬 How It Works

```
Target URL
    │
    ▼
[spider.py] ─────────── Crawls the target, discovers URLs, params & forms
    │
    ▼
[form_detector.py] ───── Extracts input fields from discovered HTML forms
    │
    ▼
[injector.py] ─────────── Injects payloads from payloads.py / advanced_payloads.py
[encoders.py] ─────────── Optionally encodes payloads to evade filters
    │
    ▼
[reflection.py] ──────── Checks if payloads appear in HTTP responses
[dom_analyzer.py] ────── Checks for DOM sinks executing injected scripts
    │
    ▼
[false_positive.py] ───── Filters noise and confirms true positives
    │
    ▼
[html_report.py] ─────── Generates a detailed HTML vulnerability report
```

---

## 📋 Requirements

All dependencies are listed in `requirements.txt`. Install them with:

```bash
pip install -r requirements.txt
```

Common dependencies include:

```
requests
beautifulsoup4
colorama
```

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. **Fork** the repository
2. **Create** a feature branch — `git checkout -b feature/your-feature`
3. **Commit** your changes — `git commit -m "Add your feature"`
4. **Push** to the branch — `git push origin feature/your-feature`
5. **Open** a Pull Request

Please keep your code clean, documented, and tested before submitting.

---

## 🐛 Reporting Issues

Found a bug or have a suggestion? [Open an issue](https://github.com/rohit-1006/XSS_Scanner/issues) and include:

- Your Python version (`python --version`)
- The command you ran
- Steps to reproduce the issue
- Any error messages or stack traces

---

## ⚖️ Legal Disclaimer

> **This tool is intended strictly for authorized security testing and educational purposes.**
>
> Using XSS Scanner against web applications **without explicit written permission** from the owner is **illegal** and unethical. The author assumes **no liability** for any misuse or damage caused by this tool.
>
> Always obtain proper authorization before security testing. Practice responsible disclosure.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with ❤️ by [rohit-1006](https://github.com/rohit-1006)

⭐ **Star this repo if you find it useful!**

</div>
