# VULSCAN SOURCE CODE SCANNER WITH AES DECRYPTION

VULSCAN is a specialized security tool designed to analyze client-side web application code for hardcoded secrets, cryptographic weaknesses, and logic flaws. It combines static analysis (crawling and regex matching) with dynamic analysis (browser interception and hooking) to uncover vulnerabilities in modern Single Page Applications (SPAs).

## Features

- **Authenticated Crawling**: Handles session cookies and custom headers.
- **Static Analysis**: 
    - Scans HTML, JavaScript, JSON, and markdown files.
    - Detects hardcoded API keys (AWS, Google, etc.), PII, and custom secret patterns.
    - Identifies dangerous JS sinks (`eval`, `innerHTML`, etc.).
- **Dynamic Analysis (Live Exploit)**:
    - Injects a JavaScript interceptor (`aes_live.js`) into the browser context.
    - Hooks `CryptoJS`, `WebCrypto API`, `atob`, and other sensitive functions.
    - Captures encryption keys, IVs, and decrypted payloads in real-time.
- **Unlinked Asset Discovery**: Fuzzes for common unlinked JS files (e.g., `main.js`, `common.js`).
- **AES Decryption Strategies**: Includes logic to handle specific obfuscation patterns and automated key extraction.
- **Reporting**: Generates comprehensive JSON reports.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/vulscan.git
    cd vulscan
    ```

2.  Install Python dependencies:
    ```bash
    pip3 install -r requirements.txt
    ```

3.  Ensure you have `chromedriver` installed and in your PATH (for dynamic analysis).

## Usage

### Basic Static Scan
```bash
python3 vulscan.py -u https://target.com/
```

### Authenticated Scan
```bash
python3 vulscan.py -u https://target.com/dashboard -c "sessionid=xyz; token=abc"
```

### Comprehensive Scan (Static + Dynamic)
This mode runs the crawler, analyzes source code, and launches a headless browser to intercept cryptographic operations.
```bash
python3 vulscan.py -u https://target.com/ --scan-all
```

### Live Exploit Mode (Manual Control)
Launches the browser with the interceptor and keeps it open for manual navigation.
```bash
python3 vulscan.py -u https://target.com/ --live-exploit
```

## Flags

*   `-u, --url`: Target URL.
*   `-c, --cookies`: Session cookies string.
*   `-H, --headers`: Custom headers (can be used multiple times).
*   `-d, --depth`: Crawl depth (default: 3).
*   `-t, --threads`: Number of threads (default: 10).
*   `-o, --output`: Output file path.
*   `-k, --insecure`: Disable SSL verification.
*   `--scan-all`: Run all analysis strategies.
*   `--live-exploit`: Inject interceptor and monitor.
*   `--save-content`: Save crawled file content locally.

## Directory Structure

*   `core/`: Core logic modules (Mapper, Engine, Behavior, etc.).
*   `payloads/`: JavaScript payloads for dynamic interception.
*   `utils/`: Helper utilities (Login, Component Checker, Decryption).
*   `vulscan.py`: Main entry point.

## Disclaimer

This tool is for educational and authorized testing purposes only. Usage against targets without prior mutual consent is illegal.