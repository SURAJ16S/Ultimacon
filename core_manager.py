#!/usr/bin/env python3
"""
ULTIMATE RECONNAISSANCE TOOL - Core Manager
Orchestrates all modules, handles configuration, and manages results
"""

import os
import sys
import json
import time
import signal
import threading
import asyncio
import importlib.util
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse
from colorama import init, Fore, Back, Style
import yaml
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
init(autoreset=True)

class CoreManager:
    def __init__(self, target: str, output_dir: str = "results", config_file: str = "config.yaml"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.config_file = config_file
        self.modules = {}
        self.results = {}
        self.config = self.load_config()
        self.wordlists = self.load_wordlists()
        self.api_keys = self.load_api_keys()
        self.target_type = self.analyze_target_type()
        self.start_time = None
        self.total_tasks = 0
        self.completed_tasks = 0
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize modules
        self.load_modules()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        default_config = {
            'threads': 50,
            'timeout': 30,
            'retries': 3,
            'rate_limit': 1,
            'stealth_mode': False,
            'aggressive_mode': False,
            'enable_apis': True,
            'enable_bruteforce': True,
            'enable_vuln_scan': True,
            'enable_osint': True,
            'enable_evasion': True,
            'proxy_enabled': False,
            'proxy_list': [],
            'tor_enabled': False,
            'wordlist_paths': {
                'subdomains': [],
                'directories': [],
                'files': [],
                'usernames': [],
                'passwords': []
            },
            'modules': {
                'passive_recon': True,
                'active_recon': True,
                'service_enum': True,
                'osint': True,
                'vuln_scan': True,
                'ai_assist': False,
                'distributed': False
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
                    default_config.update(file_config)
            except Exception as e:
                print(f"{Fore.RED}[-] Error loading config: {e}{Style.RESET_ALL}")
        
        return default_config
    
    def load_wordlists(self) -> Dict[str, List[str]]:
        """Load wordlist configurations with user prompts"""
        wordlists = self.config.get('wordlist_paths', {})
        
        # Prompt user for wordlist locations if not set
        for category, paths in wordlists.items():
            if not paths:
                print(f"{Fore.YELLOW}[?] Enter path to {category} wordlist (or press Enter to skip):{Style.RESET_ALL}")
                path = input().strip()
                if path and os.path.exists(path):
                    wordlists[category] = [path]
                else:
                    # Use default paths
                    default_paths = self.get_default_wordlists(category)
                    wordlists[category] = [p for p in default_paths if os.path.exists(p)]
        
        return wordlists
    
    def get_default_wordlists(self, category: str) -> List[str]:
        """Get default wordlist paths for each category"""
        defaults = {
            'subdomains': [
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt',
                '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt'
            ],
            'directories': [
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ],
            'files': [
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt'
            ],
            'usernames': [
                '/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt',
                '/usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt'
            ],
            'passwords': [
                '/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                '/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt'
            ]
        }
        return defaults.get(category, [])
    
    def load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment and config"""
        api_keys = {}
        
        # Environment variables
        env_keys = [
            'SHODAN_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET',
            'VIRUSTOTAL_API_KEY', 'SECURITYTRAILS_API_KEY', 'HUNTER_API_KEY',
            'WAPPALYZER_API_KEY', 'HAVEIBEENPWNED_API_KEY', 'DEHASHED_API_KEY'
        ]
        
        for key in env_keys:
            value = os.getenv(key, '')
            if value:
                api_keys[key.lower()] = value
        
        # Config file
        config_file = 'api_keys.json'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_keys = json.load(f)
                    api_keys.update(file_keys)
            except Exception as e:
                print(f"{Fore.RED}[-] Error loading API keys: {e}{Style.RESET_ALL}")
        
        return api_keys
    
    def analyze_target_type(self) -> str:
        """Analyze target type"""
        target = self.target.lower()
        
        if target.startswith(('http://', 'https://')):
            return 'url'
        
        try:
            import ipaddress
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        try:
            import ipaddress
            ipaddress.ip_network(target, strict=False)
            return 'network'
        except ValueError:
            pass
        
        if '.' in target and not target.startswith('.') and not target.endswith('.'):
            return 'domain'
        
        return 'unknown'
    
    def load_modules(self):
        """Load all available modules"""
        modules_dir = Path("modules")
        if not modules_dir.exists():
            modules_dir.mkdir()
            print(f"{Fore.YELLOW}[!] Created modules directory. Please add your modules.{Style.RESET_ALL}")
            return
        
        for module_file in modules_dir.glob("*.py"):
            if module_file.name.startswith("__"):
                continue
            
            try:
                module_name = module_file.stem
                if self.config['modules'].get(module_name, True):
                    # Import module dynamically
                    spec = importlib.util.spec_from_file_location(module_name, module_file)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Get module class (assuming class name is ModuleName)
                    class_name = ''.join(word.capitalize() for word in module_name.split('_'))
                    if hasattr(module, class_name):
                        module_class = getattr(module, class_name)
                        self.modules[module_name] = module_class
                        print(f"{Fore.GREEN}[+] Loaded module: {module_name}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error loading module {module_file.name}: {e}{Style.RESET_ALL}")
    
    def print_banner(self):
        """Print the tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    ULTIMATE RECONNAISSANCE TOOL v3.0                              ║
║                        Modular Reconnaissance Framework                          ║
║                              All-in-One Information Gathering                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[*] Target: {self.target}
[*] Type: {self.target_type.upper()}
[*] Output Directory: {self.output_dir}
[*] Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[*] Configuration: {self.config['threads']} threads, {self.config['timeout']}s timeout
[*] Loaded Modules: {len(self.modules)}
{Style.RESET_ALL}
"""
        print(banner)
    
    def run_module(self, module_name: str, module_class) -> Dict[str, Any]:
        """Run a specific module"""
        try:
            print(f"{Fore.CYAN}[*] Running module: {module_name}{Style.RESET_ALL}")
            module_instance = module_class(self.target, self.config, self.wordlists, self.api_keys)
            results = module_instance.run()
            return results
        except Exception as e:
            print(f"{Fore.RED}[-] Error in module {module_name}: {e}{Style.RESET_ALL}")
            return {}
    
    def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate and deduplicate results from all modules"""
        aggregated = {
            'target_info': {
                'target': self.target,
                'type': self.target_type,
                'scan_time': datetime.now().isoformat()
            },
            'modules': {},
            'summary': {
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0
            }
        }
        
        for module_name, results in self.results.items():
            aggregated['modules'][module_name] = results
            
            # Count findings by severity
            if isinstance(results, dict):
                for key, value in results.items():
                    if isinstance(value, list):
                        aggregated['summary']['total_findings'] += len(value)
        
        return aggregated
    
    def save_results(self, results: Dict[str, Any]):
        """Save results in multiple formats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{self.target}_{timestamp}"
        
        # JSON format
        json_file = self.output_dir / f"{base_filename}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # HTML report
        html_file = self.output_dir / f"{base_filename}.html"
        self.generate_html_report(results, html_file)
        
        # Markdown report
        md_file = self.output_dir / f"{base_filename}.md"
        self.generate_markdown_report(results, md_file)
        
        print(f"{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL}")
        print(f"  - JSON: {json_file}")
        print(f"  - HTML: {html_file}")
        print(f"  - Markdown: {md_file}")
    
    def generate_html_report(self, results: Dict[str, Any], output_file: Path):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .finding {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Reconnaissance Report</h1>
        <p>Target: {self.target}</p>
        <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p>Total Findings: {results['summary']['total_findings']}</p>
        <p>Critical: {results['summary']['critical_findings']}</p>
        <p>High: {results['summary']['high_findings']}</p>
        <p>Medium: {results['summary']['medium_findings']}</p>
        <p>Low: {results['summary']['low_findings']}</p>
    </div>
"""
        
        for module_name, module_results in results['modules'].items():
            html_content += f"""
    <div class="section">
        <h2>{module_name.replace('_', ' ').title()}</h2>
"""
            if isinstance(module_results, dict):
                for key, value in module_results.items():
                    html_content += f"<h3>{key}</h3>"
                    if isinstance(value, list):
                        for item in value:
                            html_content += f'<div class="finding">{item}</div>'
                    else:
                        html_content += f'<div class="finding">{value}</div>'
            
            html_content += "</div>"
        
        html_content += """
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def generate_markdown_report(self, results: Dict[str, Any], output_file: Path):
        """Generate Markdown report"""
        md_content = f"""# Reconnaissance Report - {self.target}

**Target:** {self.target}  
**Type:** {self.target_type}  
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Total Findings:** {results['summary']['total_findings']}
- **Critical:** {results['summary']['critical_findings']}
- **High:** {results['summary']['high_findings']}
- **Medium:** {results['summary']['medium_findings']}
- **Low:** {results['summary']['low_findings']}

"""
        
        for module_name, module_results in results['modules'].items():
            md_content += f"## {module_name.replace('_', ' ').title()}\n\n"
            
            if isinstance(module_results, dict):
                for key, value in module_results.items():
                    md_content += f"### {key}\n\n"
                    if isinstance(value, list):
                        for item in value:
                            md_content += f"- {item}\n"
                    else:
                        md_content += f"{value}\n"
                    md_content += "\n"
        
        with open(output_file, 'w') as f:
            f.write(md_content)
    
    def run(self):
        """Main execution method"""
        self.print_banner()
        self.start_time = time.time()
        
        # Check if OSINT dashboard is requested
        dashboard_enabled = self.config.get('enable_osint_dashboard', False)
        dashboard_instance = None
        
        if dashboard_enabled:
            try:
                from modules.osint_dashboard import OsintDashboard
                dashboard_instance = OsintDashboard(self.target, self.config, self.wordlists, self.api_keys)
                print(f"{Fore.CYAN}[*] OSINT Dashboard enabled - will start after OSINT module{Style.RESET_ALL}")
            except ImportError:
                print(f"{Fore.YELLOW}[!] OSINT Dashboard module not available{Style.RESET_ALL}")
        
        try:
            # Run all loaded modules
            with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
                future_to_module = {
                    executor.submit(self.run_module, name, module_class): name
                    for name, module_class in self.modules.items()
                }
                
                for future in as_completed(future_to_module):
                    module_name = future_to_module[future]
                    try:
                        results = future.result()
                        self.results[module_name] = results
                        print(f"{Fore.GREEN}[+] Module {module_name} completed{Style.RESET_ALL}")
                        
                        # Update dashboard if OSINT module completed
                        if module_name == 'osint' and dashboard_instance:
                            dashboard_instance.update_results(results)
                            print(f"{Fore.CYAN}[*] Updated OSINT Dashboard with results{Style.RESET_ALL}")
                            
                    except Exception as e:
                        print(f"{Fore.RED}[-] Module {module_name} failed: {e}{Style.RESET_ALL}")
            
            # Start OSINT dashboard if enabled
            if dashboard_instance:
                print(f"\n{Fore.CYAN}[*] Starting OSINT Dashboard...{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Dashboard will be available at: http://localhost:5000{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop the dashboard{Style.RESET_ALL}")
                
                # Run dashboard in a separate thread
                dashboard_thread = threading.Thread(target=dashboard_instance.run_dashboard, daemon=True)
                dashboard_thread.start()
                
                # Keep main thread alive
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Stopping OSINT Dashboard...{Style.RESET_ALL}")
            
            # Aggregate results
            print(f"\n{Fore.CYAN}[*] Aggregating results...{Style.RESET_ALL}")
            aggregated_results = self.aggregate_results()
            
            # Save results
            print(f"\n{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
            self.save_results(aggregated_results)
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Reconnaissance interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during reconnaissance: {e}{Style.RESET_ALL}")
        
        # Calculate total time
        total_time = time.time() - self.start_time
        print(f"\n{Fore.GREEN}[+] Reconnaissance completed in {total_time:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate Reconnaissance Tool - Core Manager")
    parser.add_argument("target", help="Target (domain, IP, URL, or network)")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", default="config.yaml", help="Configuration file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive mode")
    parser.add_argument("--dashboard", action="store_true", help="Enable OSINT dashboard")
    
    args = parser.parse_args()
    
    # Create and run core manager
    manager = CoreManager(args.target, args.output, args.config)
    manager.config['threads'] = args.threads
    manager.config['stealth_mode'] = args.stealth
    manager.config['aggressive_mode'] = args.aggressive
    manager.config['enable_osint_dashboard'] = args.dashboard
    
    manager.run() 