# 🕵️ Ultimate Reconnaissance Tool v3.0

**The Most Comprehensive Reconnaissance Framework Ever Created**

A modular, extensible reconnaissance framework that integrates every possible reconnaissance technique, tool, and methodology into a single, intelligent system.

## 🔒 **SAFETY AND LEGAL DISCLAIMER**

⚠️ **CRITICAL: This tool is for authorized security testing only!**

### **Legal Requirements:**
- **MUST** have explicit written permission before scanning
- **MUST** stay within authorized scope boundaries  
- **MUST** follow responsible disclosure practices
- **MUST** comply with local and international laws
- **NEVER** scan targets without permission

### **Ethical Requirements:**
- Respect rate limits and system resources
- Do not cause disruption or damage
- Report findings responsibly
- Protect sensitive information
- Use stealth mode for sensitive targets

### **Safety Features:**
- ✅ Authorization validation
- ✅ Scope checking
- ✅ Rate limiting
- ✅ Stealth mode options
- ✅ Safety warnings
- ✅ Interactive confirmations

**By using this tool, you acknowledge and accept full responsibility for compliance with all applicable laws and ethical guidelines.**

## 🌟 Features

### 🔍 **Comprehensive Reconnaissance**
- **Passive Reconnaissance**: WHOIS, DNS, subdomains, certificates, tech stack detection
- **Certificate Analysis**: Comprehensive crt.sh integration for certificate transparency logs
- **Active Reconnaissance**: Port scanning, directory bruteforcing, web crawling
- **Service Enumeration**: Deep enumeration for SMB, FTP, SSH, databases, web services
- **Advanced OSINT Gathering**: Email leaks, social profiles, breach data, historical artifacts
- **Breach Intelligence**: Multi-source breach database integration (HIBP, DeHashed, Intelligence X)
- **OSINT Dashboard**: Real-time web-based dashboard for results visualization
- **Vulnerability Assessment**: Automated scanning with multiple tools
- **AI/ML Integration**: Intelligent prioritization and analysis

### 🛠️ **Advanced Capabilities**
- **Multi-Tool Integration**: Nmap, Gobuster, FFUF, Subfinder, Amass, Nuclei, and more
- **Intelligent Evasion**: WAF/CDN detection, proxy rotation, rate limit adaptation
- **Dynamic Wordlists**: Custom wordlist management and generation
- **Distributed Scanning**: Cloud and cluster support
- **Real-time Dashboard**: Live progress tracking and results visualization
- **Comprehensive Reporting**: HTML, Markdown, JSON, and CSV exports

### 🔧 **Modular Architecture**
- **Plugin System**: Extensible module architecture
- **Configuration Management**: YAML-based configuration
- **API Integration**: Shodan, Censys, VirusTotal, and more
- **Self-Updating**: Automatic dependency and tool updates

## 💻 System Requirements

### Minimum System Specifications
- **CPU**: Intel Core i3 / AMD Ryzen 3 or equivalent (2 cores, 2.0 GHz)
- **RAM**: 2 GB DDR3/DDR4
- **Storage**: 5 GB available space
- **Network**: 1 Mbps download / 512 Kbps upload
- **OS**: Windows 7+, macOS 10.12+, or Ubuntu 16.04+
- **Python**: 3.7 or higher

### Recommended System Specifications
- **CPU**: Intel Core i5 / AMD Ryzen 5 or equivalent (4 cores, 2.5 GHz)
- **RAM**: 4 GB DDR4
- **Storage**: 10 GB available space
- **Network**: 10 Mbps download / 2 Mbps upload
- **OS**: Windows 10+, macOS 10.14+, or Ubuntu 18.04+
- **Python**: 3.8 or higher

### High-Performance System Specifications
- **CPU**: Intel Core i7 / AMD Ryzen 7 or equivalent (6+ cores, 3.0 GHz)
- **RAM**: 8 GB DDR4
- **Storage**: 20 GB available space (SSD recommended)
- **Network**: 25+ Mbps download / 5+ Mbps upload
- **OS**: Latest stable versions
- **Python**: 3.9 or higher

## ⚡ Power Consumption & Network Requirements

### Power Consumption Analysis

#### Light Reconnaissance (Basic Scan)
- **Duration**: 5-15 minutes
- **CPU Usage**: 10-20% (2 cores)
- **RAM Usage**: 500 MB - 1 GB
- **Network**: 10-50 MB total
- **Power**: ~15-25W (laptop) / ~30-50W (desktop)

#### Standard Reconnaissance (Comprehensive Scan)
- **Duration**: 30-60 minutes
- **CPU Usage**: 20-40% (4 cores)
- **RAM Usage**: 1-2 GB
- **Network**: 100-300 MB total
- **Power**: ~20-35W (laptop) / ~40-70W (desktop)

#### Aggressive Reconnaissance (Full Enumeration)
- **Duration**: 1-3 hours
- **CPU Usage**: 40-60% (4-6 cores)
- **RAM Usage**: 2-4 GB
- **Network**: 500 MB - 1 GB total
- **Power**: ~30-45W (laptop) / ~60-90W (desktop)

#### Enterprise Reconnaissance (Multi-Target)
- **Duration**: 3-8 hours
- **CPU Usage**: 60-80% (6+ cores)
- **RAM Usage**: 4-8 GB
- **Network**: 2-5 GB total
- **Power**: ~40-60W (laptop) / ~80-120W (desktop)

### Network Speed Requirements

#### Minimum Network Speeds
- **Download**: 1 Mbps (for basic API calls and data retrieval)
- **Upload**: 512 Kbps (for result reporting)
- **Latency**: <200ms (for basic operations)
- **Data Cap**: 100 MB (for basic scans)

#### Recommended Network Speeds
- **Download**: 10 Mbps (for efficient API operations)
- **Upload**: 2 Mbps (for result reporting)
- **Latency**: <100ms (for optimal performance)
- **Data Cap**: 1 GB (for comprehensive scans)

#### High-Performance Network Speeds
- **Download**: 25+ Mbps (for parallel operations)
- **Upload**: 5+ Mbps (for real-time reporting)
- **Latency**: <50ms (for maximum efficiency)
- **Data Cap**: 5+ GB (for enterprise scans)

### Test Case Analysis

#### Test Case 1: Single Domain Basic Scan
```
Target: example.com
Duration: 10 minutes
CPU: 2 cores @ 15%
RAM: 800 MB
Network: 25 MB
Power: 20W (laptop)
Internet: 1 Mbps required
```

#### Test Case 2: Single Domain Comprehensive Scan
```
Target: example.com (all modules)
Duration: 45 minutes
CPU: 4 cores @ 30%
RAM: 1.5 GB
Network: 150 MB
Power: 30W (laptop)
Internet: 5 Mbps required
```

#### Test Case 3: Single Domain Aggressive Scan
```
Target: example.com (full enumeration)
Duration: 2 hours
CPU: 4 cores @ 50%
RAM: 3 GB
Network: 500 MB
Power: 40W (laptop)
Internet: 10 Mbps required
```

#### Test Case 4: Multi-Domain Enterprise Scan
```
Targets: 10 domains
Duration: 6 hours
CPU: 6 cores @ 60%
RAM: 6 GB
Network: 2 GB
Power: 50W (laptop)
Internet: 15 Mbps required
```

### Resource Optimization Tips

#### For Low-End Systems (2-4 GB RAM, 2 cores)
- Use `--stealth` mode for slower, less resource-intensive scanning
- Limit concurrent threads: `-t 5-10`
- Disable heavy modules in config.yaml (vuln_scan, bruteforce)
- Use basic wordlists only
- Close unnecessary applications during scanning
- Run scans during low-usage periods

#### For Medium Systems (4-8 GB RAM, 4 cores)
- Use default mode for balanced performance
- Use moderate thread count: `-t 20-30`
- Enable most modules but limit concurrent operations
- Use standard wordlists
- Monitor system resources during scanning

#### For High-End Systems (8+ GB RAM, 6+ cores)
- Use `--aggressive` mode for maximum coverage
- Increase thread count: `-t 50-100`
- Enable all modules for comprehensive results
- Use large wordlists for thorough enumeration
- Consider parallel scanning for multiple targets

#### Network Optimization
- Use wired connection when possible
- Ensure stable internet connection
- Monitor data usage for capped connections
- Use VPN if required (may impact speed)
- Schedule scans during off-peak hours
- Use rate limiting for API-heavy operations

## 📊 Performance Monitoring

### Built-in Performance Monitor
The tool includes a comprehensive performance monitoring system:

```bash
# Monitor performance during reconnaissance
python performance_monitor.py

# Monitor for specific duration (e.g., 1 hour)
python performance_monitor.py --duration 3600

# Custom output file
python performance_monitor.py --output my_performance.json
```

### Performance Metrics Tracked
- **CPU Usage**: Per-core and overall CPU utilization
- **Memory Usage**: RAM and swap usage patterns
- **Network Usage**: Data sent/received, bandwidth analysis
- **Disk I/O**: Read/write operations and storage usage
- **System Information**: Platform details and Python version

### Performance Reports
The monitor generates:
- **JSON Reports**: Detailed performance data for analysis
- **Visual Charts**: CPU, memory, and network usage graphs
- **Recommendations**: System optimization suggestions
- **Resource Analysis**: Peak usage and average consumption

### Real-time Monitoring
```bash
# Start monitoring before running reconnaissance
python performance_monitor.py &
python core_manager.py example.com

# Stop monitoring when done
# Press Ctrl+C in the monitor terminal
```

### Performance Optimization Examples

#### Low-End System Optimization
```bash
# Use stealth mode for lower resource usage
python core_manager.py example.com --stealth -t 10

# Monitor performance
python performance_monitor.py --duration 1800  # 30 minutes
```

#### High-End System Optimization
```bash
# Use aggressive mode for maximum performance
python core_manager.py example.com --aggressive -t 100

# Monitor with custom output
python performance_monitor.py --output aggressive_scan.json
```

### Performance Analysis Tools
- **Resource Usage Charts**: Visual representation of system performance
- **Bandwidth Analysis**: Network efficiency and data transfer rates
- **CPU/Memory Correlation**: Resource usage patterns
- **Optimization Recommendations**: System-specific improvement suggestions

## 🔒 Safety Setup

### **MANDATORY: Authorization Setup**

Before using this tool, you MUST set up proper authorization:

1. **Create Authorization File:**
   ```bash
   # Edit the authorization template
   cp authorized_targets.json my_authorization.json
   # Edit my_authorization.json with your authorized targets
   ```

2. **Run Safety Check:**
   ```bash
   # Test safety check for your target
   python safety_check.py example.com
   ```

3. **Configure Safety Settings:**
   ```bash
   # Edit safety configuration
   nano safety_config.yaml
   ```

### **Authorization Template Structure:**
```json
{
  "authorized_targets": {
    "domains": ["example.com", "*.example.com"],
    "ips": ["192.168.1.0/24"],
    "excluded_targets": ["api.example.com"]
  },
  "scope_limitations": {
    "allowed_techniques": ["passive_reconnaissance", "port_scanning"],
    "rate_limits": {"requests_per_second": 10}
  }
}
```

### **Safety Configuration Options:**
```yaml
# safety_config.yaml
require_authorization: true
stealth_mode_default: true
block_critical_infrastructure: true
rate_limiting: true
```

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- Git
- Required system tools (see below)

### System Tools Installation

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install required tools
sudo apt install -y nmap gobuster ffuf subfinder amass whatweb nikto nuclei

# Install SecLists
sudo apt install -y seclists

# Install additional tools
sudo apt install -y dirb dirbuster hydra sqlmap
```

#### macOS
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install nmap gobuster ffuf subfinder amass whatweb

# Install SecLists
git clone https://github.com/danielmiessler/SecLists.git /usr/local/share/seclists
```

#### Windows
```bash
# Install Chocolatey if not installed
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install required tools
choco install nmap gobuster ffuf
```

### Python Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ultimate-recon.git
cd ultimate-recon

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install additional tools (optional)
pip install --upgrade pip
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ultimate-recon.git
cd ultimate-recon

# Run automated installation
python install.py

# Or install manually
pip install -r requirements.txt
sudo apt-get install nmap gobuster ffuf subfinder amass whatweb
```

### System Check and Setup

```bash
# Check system specifications and requirements
python system_check.py

# Run interactive setup and configuration
python setup.py

# Check system status anytime
python system_check.py --quick
```

### Basic Usage

```bash
# Run against a domain
python ultimate_recon.py example.com

# Run against an IP address
python ultimate_recon.py 192.168.1.1

# Run against a URL
python ultimate_recon.py https://example.com

# Run with custom output directory
python ultimate_recon.py example.com -o results

# Run with custom configuration
python ultimate_recon.py example.com -c my_config.yaml
```

### Advanced Usage

```bash
# Stealth mode (slower, less detectable)
python ultimate_recon.py example.com --stealth

# Aggressive mode (faster, more comprehensive)
python ultimate_recon.py example.com --aggressive

# Custom thread count
python ultimate_recon.py example.com -t 100

# Run specific modules only
python ultimate_recon.py example.com --modules passive_recon,active_recon

# Enable OSINT dashboard
python ultimate_recon.py example.com --dashboard
```

## ⚙️ Configuration and Setup

### Automatic Setup and System Analysis

The tool includes comprehensive setup and configuration management:

#### **System Check (`system_check.py`)**
- **Hardware Analysis**: CPU, memory, disk, and network capabilities
- **Performance Assessment**: Automatic categorization (low/medium/high/enterprise)
- **Dependency Verification**: Python packages and external tools
- **Wordlist Detection**: Automatic wordlist location and validation
- **API Key Status**: Check configured API keys and missing services
- **Recommendations**: Actionable suggestions based on system capabilities

#### **Interactive Setup (`setup.py`)**
- **System Analysis**: Automatic hardware and software detection
- **Performance-Based Configuration**: Auto-configure based on system capabilities
- **Wordlist Management**: Interactive wordlist setup and download
- **API Key Configuration**: Secure API key input with fallback options
- **Fallback Setup**: Configure alternative methods for missing services

#### **Fallback Manager (`modules/fallback_manager.py`)**
- **API Key Alternatives**: Free methods when paid APIs are unavailable
- **Service Substitution**: DNS resolution, search engines, pattern guessing
- **Graceful Degradation**: Maintain functionality without API keys
- **Multiple Fallback Types**: Public APIs, DNS queries, content analysis

### Configuration File (config.yaml)

```yaml
# General settings
threads: 50
timeout: 30
retries: 3
rate_limit: 1

# Modes
stealth_mode: false
aggressive_mode: false

# Features
enable_apis: true
enable_bruteforce: true
enable_vuln_scan: true
enable_osint: true
enable_evasion: true

# Proxy settings
proxy_enabled: false
proxy_list: []
tor_enabled: false

# Wordlist paths
wordlist_paths:
  subdomains:
    - /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
    - /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
  directories:
    - /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
    - /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
  files:
    - /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
  usernames:
    - /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
  passwords:
    - /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# Module settings
modules:
  passive_recon: true
  active_recon: true
  service_enum: true
  osint: true
  vuln_scan: true
  ai_assist: false
  distributed: false
```

### API Keys (api_keys.json)

```json
{
  "shodan_api_key": "your_shodan_key",
  "censys_api_id": "your_censys_id",
  "censys_api_secret": "your_censys_secret",
  "virustotal_api_key": "your_virustotal_key",
  "securitytrails_api_key": "your_securitytrails_key",
  "hunter_api_key": "your_hunter_key",
  "wappalyzer_api_key": "your_wappalyzer_key",
  "haveibeenpwned_api_key": "your_haveibeenpwned_key",
  "dehashed_api_key": "your_dehashed_key"
}
```

## 📋 Modules

### 1. Passive Reconnaissance (`modules/passive_recon.py`)
- WHOIS information gathering
- DNS record enumeration
- DNSDumpster integration
- Certificate transparency logs (crt.sh)
- Subdomain enumeration
- Technology stack detection
- OSINT gathering

### 2. Certificate Analysis (`modules/certificate_analysis.py`)
- **Comprehensive crt.sh Integration**: Query certificate transparency logs with multiple patterns
- **Subdomain Discovery**: Extract subdomains from certificates and SAN fields
- **Certificate Security Analysis**: Detect weak certificates, expiry issues, and security problems
- **Wildcard Certificate Detection**: Identify and analyze wildcard certificates
- **Certificate Chain Analysis**: Analyze certificate hierarchies and trust relationships
- **Duplicate Certificate Detection**: Find duplicate or conflicting certificates
- **Certificate Metrics**: Generate comprehensive statistics and analysis
- **Export Capabilities**: Export results in JSON, CSV, and text formats

### 3. Active Reconnaissance (`modules/active_recon.py`)
- Port scanning (TCP/UDP)
- Directory and file bruteforcing
- Web crawling
- API endpoint discovery
- Service enumeration

### 4. Service Enumeration (`modules/service_enum.py`)
- SMB enumeration (shares, users, groups)
- FTP enumeration (anonymous access, file listing)
- SSH enumeration (banner grabbing, key exchange)
- Database enumeration (MySQL, PostgreSQL, MongoDB)
- Web service enumeration (HTTP, HTTPS, APIs)

### 5. OSINT Gathering (`modules/osint.py`)
- **Email Leak Detection**: HaveIBeenPwned, DeHashed, LeakCheck integration
- **Social Media Intelligence**: LinkedIn, Twitter, GitHub, Reddit analysis
- **Breach Data Analysis**: Multi-source breach database correlation
- **Historical Data**: Wayback Machine, CommonCrawl, Pastebin, Gist search
- **Job Postings**: Company job listing analysis
- **Forum Mentions**: Reddit, Stack Overflow, and other forum searches
- **Employee Information**: LinkedIn employee data gathering

### 6. Subdomain Takeover Detection (`modules/subdomain_takeover.py`)
- **Takeover Pattern Detection**: AWS S3, Azure Blob, GCP Storage, GitHub Pages
- **CNAME Analysis**: Dangling CNAME detection and validation
- **HTTP Response Analysis**: Service-specific takeover indicators
- **Platform Enumeration**: Heroku, Vercel, Netlify, Cloudflare Pages
- **Exploitation Guides**: Step-by-step takeover instructions
- **Severity Assessment**: Risk-based prioritization of findings

### 7. Cloud Bucket Enumeration (`modules/cloud_bucket_enum.py`)
- **Multi-Cloud Support**: AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces
- **Bucket Name Generation**: Intelligent bucket name pattern matching
- **Misconfiguration Detection**: Public access, directory listings, CORS issues
- **Sensitive File Discovery**: Configuration files, backups, logs
- **Bucket Policy Analysis**: Access control and security settings
- **Comprehensive Coverage**: Cloudflare R2, Backblaze B2, Wasabi, MinIO

### 8. OSINT Dashboard (`modules/osint_dashboard.py`)
- **Real-time Dashboard**: Web-based interface for OSINT results
- **Live Data Updates**: Socket.IO-powered real-time updates
- **Data Visualization**: Charts and graphs for breach analysis
- **Interactive Interface**: Clickable links and detailed information
- **Multi-format Export**: Export results in various formats

### 9. Vulnerability Assessment (`modules/vuln_scan.py`)
- Nuclei vulnerability scanning
- Nikto web vulnerability scanning
- Custom vulnerability checks
- Exploit suggestion
- Risk assessment

### 10. AI Assistant (`modules/ai_assist.py`)
- Vulnerability prioritization
- Reconnaissance suggestions
- Report generation
- Pattern recognition

## 🖥️ OSINT Dashboard

### Dashboard Features
The OSINT Dashboard provides a real-time web interface for viewing and analyzing OSINT results:

- **Live Updates**: Real-time data updates as reconnaissance progresses
- **Interactive Charts**: Visual representation of breach data and statistics
- **Detailed Views**: Clickable items with detailed information
- **Export Options**: Download results in various formats
- **Responsive Design**: Works on desktop and mobile devices

### Starting the Dashboard

```bash
# Enable dashboard with OSINT module
python core_manager.py example.com --dashboard

# Dashboard will automatically open in your browser
# Access manually at: http://localhost:5000
```

### Dashboard Sections
- **Email Leaks & Breaches**: HaveIBeenPwned, DeHashed, and other breach data
- **Social Profiles**: LinkedIn, Twitter, GitHub, and other social media findings
- **Job Postings**: Company job listings and career information
- **Forum Mentions**: Reddit, Stack Overflow, and forum discussions
- **Paste Dumps**: Pastebin and other paste site findings
- **GitHub Intelligence**: Repository and code analysis
- **Data Visualization**: Charts showing breach sources and statistics

## 🔍 Subdomain Takeover & Cloud Bucket Detection

### Subdomain Takeover Detection
The tool includes comprehensive subdomain takeover detection capabilities:

```bash
# Run with subdomain takeover detection
python core_manager.py example.com

# The tool will automatically detect:
# - CNAME records pointing to cloud services
# - Dangling CNAME records
# - HTTP response takeover indicators
# - Platform-specific takeover patterns
```

### Supported Takeover Targets
- **AWS S3**: Bucket name registration and takeover
- **Azure Blob Storage**: Container name registration
- **GCP Storage**: Bucket name registration
- **GitHub Pages**: Repository name registration
- **Heroku**: App name registration
- **Vercel**: Deployment name registration
- **Netlify**: Site name registration
- **Cloudflare Pages**: Site name registration
- **Firebase Hosting**: Site name registration
- **Shopify**: Store name registration
- **WordPress.com**: Site name registration
- **Squarespace**: Site name registration
- **Wix**: Site name registration

### Cloud Bucket Enumeration
Comprehensive cloud bucket misconfiguration detection:

```bash
# The tool automatically tests for:
# - Public bucket access
# - Directory listing vulnerabilities
# - Sensitive file exposure
# - CORS misconfigurations
# - Bucket policy issues
```

### Supported Cloud Providers
- **AWS S3**: Multiple region endpoints and configurations
- **Azure Blob Storage**: Container and account-level testing
- **GCP Storage**: Bucket and project-level testing
- **DigitalOcean Spaces**: Regional endpoint testing
- **Cloudflare R2**: R2 storage testing
- **Backblaze B2**: B2 storage testing
- **Wasabi**: Wasabi storage testing
- **MinIO**: Self-hosted MinIO testing
- **OpenStack**: Swift container testing

## 📊 Output and Reporting

### Report Formats
- **JSON**: Machine-readable format for automation
- **HTML**: Interactive web report with visualizations
- **Markdown**: Clean, readable format for documentation
- **CSV**: Spreadsheet-compatible format

### Report Structure
```
results/
├── target_20231201_143022.json
├── target_20231201_143022.html
├── target_20231201_143022.md
└── target_20231201_143022.csv
```

### Sample Report Content
- Target information and analysis
- Passive reconnaissance results
- Active reconnaissance findings
- Service enumeration data
- OSINT intelligence
- Vulnerability assessment
- Recommendations and next steps

## 🔧 Customization

### Adding Custom Modules

1. Create a new Python file in the `modules/` directory
2. Follow the module template:

```python
class YourModule:
    def __init__(self, target, config, wordlists, api_keys):
        self.target = target
        self.config = config
        self.wordlists = wordlists
        self.api_keys = api_keys
        
    def run(self):
        # Your reconnaissance logic here
        results = {}
        # ... perform reconnaissance ...
        return results
```

3. The module will be automatically loaded by the core manager

### Custom Wordlists

```bash
# Add custom wordlists to config.yaml
wordlist_paths:
  custom:
    - /path/to/your/custom/wordlist.txt
```

### Custom Tools

```bash
# Add custom tools to tools_config in core_manager.py
'tools_config': {
    'your_tool': {
        'path': 'your_tool',
        'args': 'your_tool_args {target}',
        'stealth_args': 'your_tool_stealth_args {target}'
    }
}
```

## 🛡️ Legal and Ethical Considerations

### Important Disclaimers
- **This tool is for educational and authorized security testing purposes only**
- **Always ensure you have proper authorization before testing any systems**
- **Respect rate limits and avoid overwhelming target systems**
- **Follow responsible disclosure practices**

### Best Practices
- Obtain written permission before testing
- Stay within the defined scope
- Document all activities
- Report findings through proper channels
- Respect privacy and data protection laws

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

### Getting Help
- **Documentation**: Check this README and module documentation
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join our community discussions
- **Wiki**: Check our wiki for advanced usage

### Community
- **Discord**: Join our Discord server
- **Telegram**: Join our Telegram group
- **Twitter**: Follow us for updates

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **SecLists**: For comprehensive wordlists
- **OWASP**: For security testing methodologies
- **Bug Bounty Community**: For continuous feedback and improvements
- **Open Source Tools**: For the amazing tools that make this possible

---

**Happy Hunting! 🎯**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.* 