# 🛡️ BugHunter Toolkit

An advanced, modular, and high-performance automated reconnaissance utility written in Go, designed specifically for Bug Bounty hunters and penetration testers.

## 🎯 Features

- **🚀 High Performance:** Built with Go's native concurrency (Goroutines) for lightning-fast, parallel scanning.
- **🔗 Smart Chaining Pipeline:** Automatically extracts endpoints from JS files and intelligently feeds them into the Fuzzer, filtering out static assets (`.png`, `.svg`, etc.) and tracking parameters to avoid WAF bans and false positives.
- **🛡️ Resilient Core:** Uses a custom `retryablehttp` client with automatic retries, smart timeouts, and robust error handling.
- **🔍 Module 1: JS Analyzer**
  - Automatically extracts external JavaScript files and scans page content.
  - Uses advanced Regex patterns to detect **Secrets** (AWS Keys, API Keys, Tokens, DB Credentials).
  - Discovers hidden **Endpoints**, API routes, and internal domains.
- **🎯 Module 2: Smart API Fuzzer**
  - Intelligently analyzes URL structures to identify parameter types (Numeric, String, UUID).
  - Injects context-aware payloads (IDOR, SQLi, XSS, LFI) based on the detected parameter type.
  - Includes built-in Rate Limiting to avoid WAF bans during scanning.
- **🌐 Module 3: Subdomain Takeover**
  - Reads bulk subdomain lists and resolves DNS records at high speed using `fastdialer` with caching.
  - Matches CNAME records against an expanded database of 12+ vulnerable cloud services (GitHub Pages, Heroku, AWS S3, Azure, etc.).
  - Automatically verifies vulnerabilities via HTTP/HTTPS fallback.
- **📊 Beautiful HTML Reporting:** Generates a professional, color-coded, single-page HTML report summarizing all findings for easy review.

## 📦 Installation

### Prerequisites
- Go 1.21 or higher installed on your system.

### Build from Source
```bash
# Clone the repository
git clone https://github.com/mmahyar639-del/bughunter-toolkit.git
cd bughunter-toolkit

# Download dependencies
go mod tidy

# Build the binary (Windows)
go build -o bughunter.exe

# Build the binary (Linux / Kali)
GOOS=linux GOARCH=amd64 go build -o bughunter
```

## 🚀 Usage

### 1. Full Automated Recon Pipeline (Recommended)
Runs JS Analyzer, chains valid endpoints to the Smart Fuzzer, checks Subdomain Takeover, and generates an HTML report.
```bash
# Basic usage
./bughunter full-recon -d target.com

# With custom subdomain list and output file
./bughunter full-recon -d target.com -s subs.txt -o report.html
```

### 2. Individual Modules
```bash
# JS Analyzer only
./bughunter js-analyze -u https://target.com

# Smart API Fuzzer only
./bughunter fuzz -u "https://api.target.com/v1/users?id=123"

# Subdomain Takeover only
./bughunter takeover -l subdomains.txt
```

## 🏗️ Architecture
The project follows a clean, modular architecture:
- `cmd/`: CLI commands and flag parsing powered by `spf13/cobra`.
- `internal/core/`: Reusable, robust components (HTTP Client, HTML Reporter).
- `internal/modules/`: Independent, highly optimized scanning modules (`js_analyzer`, `api_fuzzer`, `takeover`).

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

---
*Created by [@mmahyar639-del](https://github.com/mmahyar639-del)*
```
