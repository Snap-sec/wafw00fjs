# WAF Detector - Node.js Edition

<div align="center">

**A Node.js implementation of WAF detection and fingerprinting**

[![Node.js](https://img.shields.io/badge/Node.js-v12+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-BSD%203%20Clause-orange.svg)](LICENSE)
[![WAF Detection](https://img.shields.io/badge/WAFs%20Detected-168-blue.svg)](waf_rules.json)

</div>

## 📖 About

**WAF Detector** is a Node.js equivalent of the popular [wafw00f](https://github.com/EnableSecurity/wafw00f) tool - a Web Application Firewall (WAF) fingerprinting and detection tool. This implementation brings the power of WAF detection to the Node.js ecosystem, allowing you to identify and fingerprint WAF products protecting web applications.

This tool analyzes HTTP responses (headers, content, cookies, status codes) and matches them against a comprehensive database of 168 WAF detection rules extracted from the wafw00f project.

## ✨ Features

- 🔍 **Detects 168+ WAF products** - Comprehensive detection rules from wafw00f
- 🚀 **Zero Dependencies** - Uses only built-in Node.js modules
- 🌐 **HTTP/HTTPS Support** - Automatically handles both protocols
- 🎯 **Multiple Detection Methods**:
  - HTTP header analysis
  - Response content pattern matching
  - Cookie-based detection
  - Status code and reason code analysis
  - Complex helper function rules
- ⚡ **Attack Request Support** - Optionally sends malicious payloads to trigger WAF responses
- 📦 **Easy to Use** - Simple command-line interface and programmatic API
- 🔒 **Case-Insensitive Matching** - Robust header and content matching

## 🚀 Quick Start

### Requirements

- **Node.js** v12 or higher
- No external dependencies required!

### Installation

Simply clone or download this repository:

```bash
git clone <repository-url>
cd wafw00f
```

Or download the files directly:
- `waf-detector.js` - Main detection module
- `run.js` - Command-line interface
- `waf_rules.json` - WAF detection rules database

## 📚 Usage

### Command Line Interface

The easiest way to use WAF Detector is through the command-line interface:

```bash
# Basic usage - detect WAF on a domain
node run.js example.com

# Detect WAF on an IP address
node run.js 192.168.1.1

# Use full URL
node run.js https://example.com

# Find all WAFs (don't stop at first match)
node run.js example.com --find-all

# Skip attack requests (faster, but may miss some WAFs)
node run.js example.com --no-attack

# Set custom timeout (milliseconds)
node run.js example.com --timeout 15000
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--find-all` | Continue checking all WAFs even after finding a match |
| `--no-attack` | Skip making attack requests (faster but less thorough) |
| `--timeout N` | Set request timeout in milliseconds (default: 10000) |

### Programmatic API

You can also use WAF Detector as a Node.js module in your own projects:

```javascript
const WAFDetector = require('./waf-detector');

async function detectWAF() {
    // Initialize detector with path to rules file
    const detector = new WAFDetector('./waf_rules.json');
    
    try {
        // Detect WAFs on a target
        const detectedWAFs = await detector.detectWAFs('example.com', {
            findAll: false,        // Stop at first match (default: false)
            checkAttacks: true,    // Make attack requests if needed (default: true)
            timeout: 10000         // Request timeout in ms (default: 10000)
        });
        
        if (detectedWAFs.length > 0) {
            console.log('✅ Detected WAFs:', detectedWAFs);
        } else {
            console.log('❌ No WAF detected');
        }
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

detectWAF();
```

### Advanced Usage

```javascript
const WAFDetector = require('./waf-detector');

const detector = new WAFDetector('./waf_rules.json');

// Detect with custom options
detector.detectWAFs('https://example.com', {
    findAll: true,           // Find all matching WAFs
    checkAttacks: true,     // Use attack requests
    timeout: 20000          // 20 second timeout
}).then(wafs => {
    if (wafs.length > 0) {
        wafs.forEach(waf => console.log(`Found: ${waf}`));
    }
}).catch(err => {
    console.error('Detection failed:', err);
});
```

## 📋 Example Output

```
[*] Making request to https://example.com...
[+] WAF Detected!
    Cloudflare (Cloudflare Inc.)

[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
```

Or when multiple WAFs are detected:

```
[*] Making request to https://example.com...
[+] WAF Detected!
    Cloudflare (Cloudflare Inc.)
    ModSecurity (SpiderLabs)

[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) and/or ModSecurity (SpiderLabs) WAF.
```

## 🔧 How It Works

WAF Detector follows a similar methodology to wafw00f:

1. **Normal Request**: Sends a standard HTTP/HTTPS GET request to the target
2. **Response Analysis**: Analyzes the response for WAF indicators:
   - HTTP headers (Server, custom WAF headers)
   - Response body content (error messages, WAF-specific patterns)
   - Cookies (WAF-specific cookies like `__cfduid`)
   - HTTP status codes and reason messages
3. **Rule Matching**: Compares response against all 168 WAF detection rules
4. **Attack Request** (optional): If no WAF detected, sends a request with XSS payload to trigger WAF responses
5. **Detection**: Returns list of detected WAF products

### Detection Methods

The tool uses multiple detection techniques:

- **Header-based**: Identifies WAFs by unique HTTP headers (e.g., `cf-ray` for Cloudflare)
- **Content-based**: Matches WAF-specific error messages and content patterns
- **Cookie-based**: Detects WAF-specific cookies set by the firewall
- **Status-based**: Identifies WAFs by specific HTTP status codes
- **Combined Rules**: Complex patterns requiring multiple conditions (helper functions)

## 📁 Project Structure

```
wafw00f/
├── waf-detector.js      # Main WAF detection module
├── run.js               # Command-line interface
├── waf_rules.json       # WAF detection rules database (168 WAFs)
├── extract_rules.py     # Script to extract rules from wafw00f plugins
└── README.md            # This file
```

## 🎯 Supported WAFs

This tool can detect **168 different WAF products**, including:

- **Cloud Providers**: AWS WAF, Cloudflare, Azure Application Gateway, Google Cloud Armor
- **Enterprise WAFs**: F5 BIG-IP, Citrix NetScaler, Imperva, Akamai Kona
- **Open Source**: ModSecurity, NAXSI, Shadow Daemon
- **CDN WAFs**: Cloudflare, Fastly, StackPath, KeyCDN
- **WordPress**: Wordfence, Sucuri, NinjaFirewall
- And many more...

For a complete list, check the `waf_rules.json` file or run:

```bash
node -e "const rules = require('./waf_rules.json'); console.log(rules.wafs.map(w => w.name).join('\n'));"
```

## 🤝 Contributing

Contributions are welcome! If you'd like to improve this tool:

1. Add new WAF detection rules
2. Improve detection accuracy
3. Add new features
4. Fix bugs
5. Improve documentation

## 📝 License

This project is licensed under the same license as wafw00f. Please refer to the [LICENSE](LICENSE) file for details.

## 🙏 Credits & Acknowledgments

### Special Thanks to the wafw00f Team

This Node.js implementation would not be possible without the incredible work of the **wafw00f** project and its developers. All detection rules and methodologies are based on the original wafw00f tool.

**Original wafw00f Project:**
- **Repository**: [https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f)
- **Website**: [https://enablesecurity.com](https://enablesecurity.com)

**wafw00f Maintainers:**
- **Sandro Gauci** <sandro [at] enablesecurity [dot] com>
- **Pinaki Mondal** <0xinfection [at] gmail [dot] com>

**Original Code Authors:**
- **Sandro Gauci** <sandro [at] enablesecurity [dot] com>
- **Wendel G. Henrique** <whenrique [at] trustwave [dot] com>

**wafw00f Contributors:**
- Sebastien Gioria
- W3AF (Andres Riancho)
- Charlie Campbell
- @j0eMcCray
- Mathieu Dessus
- David S. Langlands
- Nmap's http-waf-fingerprint.nse / Hani Benhabiles
- Denis Kolegov
- kun a
- Louis-Philippe Huberdeau
- Brendan Coles
- Matt Foster
- g0tmi1k
- MyKings
- And many more contributors to the wafw00f project

### Thank You! 🙇‍♂️

**A huge thank you to the entire wafw00f team and community** for creating and maintaining such an excellent tool. This Node.js implementation is a tribute to your hard work and dedication to the security community.

All WAF detection rules, methodologies, and detection patterns in this project are derived from the wafw00f Python tool. This Node.js version simply provides an alternative implementation for those who prefer or need to work in the Node.js ecosystem.

## ⚠️ Disclaimer

This tool is for **authorized security testing and research purposes only**. Only use this tool on systems you own or have explicit permission to test. Unauthorized use of this tool may be illegal in your jurisdiction.

## 📞 Support

For issues, questions, or contributions related to this Node.js implementation, please open an issue in this repository.

For questions about the original wafw00f tool, please refer to the [official wafw00f repository](https://github.com/EnableSecurity/wafw00f).

---

<div align="center">

**Made with ❤️ for the security community**

*Node.js equivalent of the amazing [wafw00f](https://github.com/EnableSecurity/wafw00f) tool*

</div>
