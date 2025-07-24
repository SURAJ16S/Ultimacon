# 🕵️‍♂️ Ultimate Reconnaissance & Enumeration Checklist

## A. Pre-Engagement
- [ ] Confirm written authorization and scope
- [ ] Validate targets in `authorized_targets.json`
- [ ] Run `safety_check.py <target>` for pre-scan safety
- [ ] Ensure all required tools are installed (`tool_manager.py`)
- [ ] Configure wordlists, API keys, and fallback options

---

## B. Passive Reconnaissance
- [ ] WHOIS lookup (domain registration, contacts, dates)
- [ ] DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME)
- [ ] Subdomain enumeration (Subfinder, Amass, crt.sh, DNSDumpster)
- [ ] Certificate Transparency logs (crt.sh, certificate_analysis)
- [ ] Reverse DNS and PTR records
- [ ] ASN and IP range discovery
- [ ] Publicly exposed services (Shodan, Censys, SecurityTrails)
- [ ] Historical DNS and web data (Wayback Machine, Common Crawl)
- [ ] Email address and employee discovery (Hunter, OSINT)
- [ ] Social media and public profile OSINT
- [ ] Breach and leak checks (HaveIBeenPwned, DeHashed, IntelligenceX)
- [ ] Pastebin, GitHub, and code artifact search
- [ ] Job postings, forum mentions, and news

---

## C. Active Reconnaissance & Enumeration
- [ ] Port scanning (Nmap, service/version detection)
- [ ] Banner grabbing and service fingerprinting
- [ ] Web server and application fingerprinting (WhatWeb, Wappalyzer)
- [ ] Directory and file brute-forcing (Gobuster, FFUF)
- [ ] Web crawling and spidering
- [ ] API endpoint discovery
- [ ] Virtual host and vhost enumeration
- [ ] SSL/TLS configuration and certificate analysis
- [ ] Technology stack detection (headers, favicon, scripts)
- [ ] Screenshot and content preview (optional)
- [ ] Cloud asset enumeration (S3, Azure, GCP, DigitalOcean, etc.)
- [ ] Cloud bucket misconfiguration checks
- [ ] Subdomain takeover detection
- [ ] CORS and HTTP security header checks

---

## D. Vulnerability Assessment
- [ ] Automated vulnerability scanning (Nuclei, Nikto, custom scripts)
- [ ] Default credentials and weak password checks
- [ ] Outdated software and CVE checks
- [ ] Exposed admin panels and sensitive files
- [ ] Open directory and file listing checks

---

## E. OSINT & Intelligence Gathering
- [ ] Email and credential leaks
- [ ] Social media and public profile mapping
- [ ] Breach intelligence aggregation
- [ ] Historical artifact and archive search
- [ ] Data visualization and dashboard review

---

## F. Reporting & Documentation
- [ ] Save all results in multiple formats (JSON, HTML, Markdown, CSV)
- [ ] Document findings, evidence, and screenshots
- [ ] Maintain activity logs and timeline
- [ ] Prepare responsible disclosure report

---

## G. Post-Engagement
- [ ] Clean up temporary files and sensitive data
- [ ] Review and update authorization and scope for next engagement
- [ ] Lessons learned and tool improvement notes 