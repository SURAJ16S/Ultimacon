#!/usr/bin/env python3
"""
Safety Check Module for Ultimate Reconnaissance Tool
Validates authorization, scope, and provides safety warnings
"""

import os
import sys
import json
import yaml
from datetime import datetime
from colorama import init, Fore, Style
import ipaddress
import socket
import requests

# Initialize colorama
init(autoreset=True)

class SafetyChecker:
    """Safety validation and authorization checking"""
    
    def __init__(self):
        self.safety_config = self.load_safety_config()
        self.authorized_targets = self.load_authorized_targets()
        
    def load_safety_config(self):
        """Load safety configuration"""
        default_config = {
            'require_authorization': True,
            'max_targets_per_scan': 10,
            'rate_limiting': True,
            'stealth_mode_default': True,
            'warn_external_targets': True,
            'block_private_ips': False,
            'require_scope_file': True,
            'safety_checks': True
        }
        
        config_file = 'safety_config.yaml'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    default_config.update(config)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading safety config: {e}{Style.RESET_ALL}")
        
        return default_config
    
    def load_authorized_targets(self):
        """Load authorized targets from file"""
        authorized_file = 'authorized_targets.json'
        if os.path.exists(authorized_file):
            try:
                with open(authorized_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading authorized targets: {e}{Style.RESET_ALL}")
        
        return {
            'domains': [],
            'ips': [],
            'networks': [],
            'scope_files': []
        }
    
    def check_authorization(self, target):
        """Check if target is authorized for scanning"""
        print(f"{Fore.CYAN}[*] Checking authorization for: {target}{Style.RESET_ALL}")
        
        if not self.safety_config['require_authorization']:
            print(f"{Fore.YELLOW}[!] Authorization checks disabled{Style.RESET_ALL}")
            return True
        
        # Check if target is in authorized list
        if self.is_target_authorized(target):
            print(f"{Fore.GREEN}[+] Target authorized{Style.RESET_ALL}")
            return True
        
        # Check scope files
        if self.check_scope_files(target):
            print(f"{Fore.GREEN}[+] Target found in scope file{Style.RESET_ALL}")
            return True
        
        # Interactive authorization
        return self.interactive_authorization(target)
    
    def is_target_authorized(self, target):
        """Check if target is in authorized list"""
        # Check domains
        if target in self.authorized_targets.get('domains', []):
            return True
        
        # Check IPs
        if target in self.authorized_targets.get('ips', []):
            return True
        
        # Check networks
        for network in self.authorized_targets.get('networks', []):
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(network):
                    return True
            except:
                continue
        
        return False
    
    def check_scope_files(self, target):
        """Check scope files for target authorization"""
        scope_files = self.authorized_targets.get('scope_files', [])
        
        for scope_file in scope_files:
            if os.path.exists(scope_file):
                try:
                    with open(scope_file, 'r') as f:
                        scope_content = f.read()
                        if target in scope_content:
                            return True
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error reading scope file {scope_file}: {e}{Style.RESET_ALL}")
        
        return False
    
    def interactive_authorization(self, target):
        """Interactive authorization prompt"""
        print(f"\n{Fore.RED}⚠️  SAFETY WARNING ⚠️{Style.RESET_ALL}")
        print(f"{Fore.RED}Target '{target}' is not in authorized list{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Before proceeding, confirm:{Style.RESET_ALL}")
        print(f"1. You have explicit permission to scan this target")
        print(f"2. This is within your authorized scope")
        print(f"3. You understand the legal implications")
        print(f"4. You will follow responsible disclosure practices")
        
        print(f"\n{Fore.RED}Type 'AUTHORIZED' to proceed or 'CANCEL' to abort: {Style.RESET_ALL}", end="")
        response = input().strip()
        
        if response.upper() == 'AUTHORIZED':
            print(f"{Fore.YELLOW}[!] Proceeding with user authorization{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!] Scan cancelled for safety{Style.RESET_ALL}")
            return False
    
    def validate_target_safety(self, target):
        """Validate target for safety concerns"""
        print(f"{Fore.CYAN}[*] Validating target safety...{Style.RESET_ALL}")
        
        safety_issues = []
        
        # Check for private IP addresses
        if self.is_private_ip(target):
            if self.safety_config['block_private_ips']:
                safety_issues.append("Private IP address detected")
            else:
                print(f"{Fore.YELLOW}[!] Private IP detected - ensure you have permission{Style.RESET_ALL}")
        
        # Check for localhost
        if target.lower() in ['localhost', '127.0.0.1', '::1']:
            safety_issues.append("Localhost detected - ensure this is intentional")
        
        # Check for critical infrastructure
        if self.is_critical_infrastructure(target):
            safety_issues.append("Critical infrastructure detected - extreme caution required")
        
        # Check for government domains
        if self.is_government_domain(target):
            safety_issues.append("Government domain detected - ensure proper authorization")
        
        # Check for financial institutions
        if self.is_financial_domain(target):
            safety_issues.append("Financial institution detected - ensure proper authorization")
        
        return safety_issues
    
    def is_private_ip(self, target):
        """Check if target is a private IP address"""
        try:
            ip = ipaddress.ip_address(target)
            return ip.is_private
        except:
            return False
    
    def is_critical_infrastructure(self, target):
        """Check if target might be critical infrastructure"""
        critical_keywords = [
            'power', 'energy', 'grid', 'nuclear', 'water', 'gas', 'oil',
            'hospital', 'medical', 'emergency', 'fire', 'police', 'gov',
            'military', 'defense', 'airport', 'railway', 'transport'
        ]
        
        target_lower = target.lower()
        return any(keyword in target_lower for keyword in critical_keywords)
    
    def is_government_domain(self, target):
        """Check if target is a government domain"""
        gov_domains = ['.gov', '.mil', '.gov.uk', '.gouv.fr', '.gov.au']
        return any(domain in target.lower() for domain in gov_domains)
    
    def is_financial_domain(self, target):
        """Check if target is a financial institution"""
        financial_keywords = [
            'bank', 'credit', 'finance', 'insurance', 'investment',
            'paypal', 'stripe', 'square', 'venmo', 'zelle'
        ]
        
        target_lower = target.lower()
        return any(keyword in target_lower for keyword in financial_keywords)
    
    def display_safety_warnings(self):
        """Display comprehensive safety warnings"""
        print(f"\n{Fore.RED}🔒 SAFETY AND LEGAL DISCLAIMER 🔒{Style.RESET_ALL}")
        print("=" * 60)
        print(f"{Fore.YELLOW}⚠️  IMPORTANT: This tool is for authorized security testing only{Style.RESET_ALL}")
        print()
        print(f"{Fore.RED}LEGAL REQUIREMENTS:{Style.RESET_ALL}")
        print("• You MUST have explicit written permission before scanning")
        print("• You MUST stay within authorized scope boundaries")
        print("• You MUST follow responsible disclosure practices")
        print("• You MUST comply with local and international laws")
        print()
        print(f"{Fore.RED}ETHICAL REQUIREMENTS:{Style.RESET_ALL}")
        print("• Respect rate limits and system resources")
        print("• Do not cause disruption or damage")
        print("• Report findings responsibly")
        print("• Protect sensitive information")
        print()
        print(f"{Fore.RED}TECHNICAL SAFETY:{Style.RESET_ALL}")
        print("• Use stealth mode for sensitive targets")
        print("• Monitor system resources")
        print("• Respect network policies")
        print("• Use appropriate wordlists")
        print()
        print(f"{Fore.YELLOW}By using this tool, you acknowledge and accept these responsibilities.{Style.RESET_ALL}")
        print("=" * 60)
    
    def create_authorization_template(self):
        """Create authorization template file"""
        template = {
            "authorization_info": {
                "client_name": "",
                "project_name": "",
                "authorization_date": "",
                "authorized_by": "",
                "scope_description": ""
            },
            "authorized_targets": {
                "domains": [
                    "example.com",
                    "*.example.com"
                ],
                "ips": [
                    "192.168.1.0/24"
                ],
                "networks": [
                    "10.0.0.0/8"
                ],
                "excluded_targets": [
                    "api.example.com",
                    "admin.example.com"
                ]
            },
            "scope_limitations": {
                "allowed_techniques": [
                    "passive_reconnaissance",
                    "port_scanning",
                    "vulnerability_assessment"
                ],
                "restricted_techniques": [
                    "exploitation",
                    "data_exfiltration",
                    "denial_of_service"
                ],
                "rate_limits": {
                    "requests_per_second": 10,
                    "concurrent_connections": 5
                }
            },
            "reporting_requirements": {
                "responsible_disclosure": True,
                "report_deadline": "30 days",
                "contact_information": ""
            }
        }
        
        with open('authorization_template.json', 'w') as f:
            json.dump(template, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Authorization template created: authorization_template.json{Style.RESET_ALL}")
    
    def run_safety_check(self, target):
        """Run complete safety check for target"""
        print(f"{Fore.CYAN}🔒 Running Safety Check{Style.RESET_ALL}")
        print("=" * 40)
        
        # Display safety warnings
        self.display_safety_warnings()
        
        # Check authorization
        if not self.check_authorization(target):
            return False
        
        # Validate target safety
        safety_issues = self.validate_target_safety(target)
        
        if safety_issues:
            print(f"\n{Fore.RED}⚠️  SAFETY ISSUES DETECTED:{Style.RESET_ALL}")
            for issue in safety_issues:
                print(f"  • {issue}")
            
            print(f"\n{Fore.YELLOW}Do you want to proceed despite these issues? (yes/no): {Style.RESET_ALL}", end="")
            response = input().strip().lower()
            
            if response != 'yes':
                print(f"{Fore.RED}[!] Scan cancelled due to safety concerns{Style.RESET_ALL}")
                return False
        
        print(f"{Fore.GREEN}[+] Safety check passed{Style.RESET_ALL}")
        return True

def main():
    """Main safety check function"""
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python safety_check.py <target>{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python safety_check.py example.com{Style.RESET_ALL}")
        sys.exit(1)
    
    target = sys.argv[1]
    checker = SafetyChecker()
    
    if checker.run_safety_check(target):
        print(f"\n{Fore.GREEN}✅ Target '{target}' is safe to scan{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}❌ Target '{target}' failed safety check{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 