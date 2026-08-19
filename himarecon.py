#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
webrecon.py - Professional Web Reconnaissance Tool
Developer: Hima Cyber Expert
Version: 1.0
"""

import os
import sys
import subprocess
import importlib
import time
import socket
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Auto-install missing modules
REQUIRED_MODULES = [
    'requests',
    'dnspython',
    'python-whois',
    'rich',
    'colorama',
    'tqdm',
    'beautifulsoup4',
    'lxml'
]

def install_module(module):
    """Install missing Python module using pip"""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', module, '--quiet'])
        return True
    except Exception:
        return False

def check_and_install_modules():
    """Check and install required modules"""
    missing = []
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module.replace('-', '_'))
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[*] Installing missing modules: {', '.join(missing)}")
        for module in missing:
            if install_module(module):
                print(f"[+] Installed: {module}")
            else:
                print(f"[-] Failed to install: {module}")
        print("[*] Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

# Check and install modules before importing
check_and_install_modules()

# Now import all modules
import requests
import dns.resolver
import whois
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.layout import Layout
from rich import box
from colorama import init, Fore, Style
from tqdm import tqdm
from bs4 import BeautifulSoup
import lxml

# Initialize
init(autoreset=True)
console = Console()

class WebRecon:
    """Main class for web reconnaissance operations"""
    
    def __init__(self, target):
        self.target = self.normalize_target(target)
        self.domain = self.extract_domain(target)
        self.ip = None
        self.report = {
            'target': target,
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 10
        
        # Built-in wordlists
        self.common_dirs = [
            'admin', 'login', 'dashboard', 'api', 'uploads', 'images', 'assets',
            'js', 'css', 'backup', 'config', 'phpinfo.php', '.git', '.env',
            'server-status', 'wp-admin', 'wp-content', 'wp-includes', 'cgi-bin',
            'panel', 'console', 'management', 'system', 'test', 'dev', 'stage',
            'vendor', 'tmp', 'logs', 'cache', 'upload', 'download', 'files',
            'static', 'media', 'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'clientaccesspolicy.xml', '.htaccess', '.htpasswd', 'web.config',
            'backup.zip', 'backup.tar.gz', 'dump.sql', 'dump.sql.gz'
        ]
        
        self.subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
            'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
            'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
            'media', 'email', 'images', 'img', 'video', 'sip', 'dns', 'api',
            'manager', 'remote', 'live', 'portal', 'stage', 'cdn', 'stats'
        ]
    
    def normalize_target(self, target):
        """Normalize target URL"""
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        return target
    
    def extract_domain(self, target):
        """Extract domain from URL"""
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        return domain.split(':')[0]
    
    def resolve_ip(self):
        """Resolve domain to IP"""
        try:
            self.ip = socket.gethostbyname(self.domain)
            return self.ip
        except:
            return None
    
    def print_banner(self):
        """Display ASCII banner"""
        banner = """
[bold cyan]██╗  ██╗██╗███╗   ███╗ █████╗[/bold cyan]
[bold cyan]██║  ██║██║████╗ ████║██╔══██╗[/bold cyan]
[bold cyan]███████║██║██╔████╔██║███████║[/bold cyan]
[bold cyan]██╔══██║██║██║╚██╔╝██║██╔══██║[/bold cyan]
[bold cyan]██║  ██║██║██║ ╚═╝ ██║██║  ██║[/bold cyan]
[bold cyan]╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝[/bold cyan]
[bold yellow]HIMA RECON[/bold yellow]
[bold green]Developer: Hima Cyber Expert[/bold green]
[bold white]Version: 1.0[/bold white]
"""
        console.print(banner)
        console.print(f"[bold blue]Target: {self.target}[/bold blue]")
        console.print("[bold magenta]" + "=" * 60 + "[/bold magenta]")
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        console.print("[yellow]▶ WHOIS Lookup[/yellow]")
        results = {}
        try:
            w = whois.whois(self.domain)
            results = {
                'Registrar': w.registrar or 'N/A',
                'Creation Date': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                'Expiry Date': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                'Updated Date': str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date),
                'Name Servers': ', '.join(w.name_servers) if w.name_servers else 'N/A'
            }
            
            table = Table(title="WHOIS Information", box=box.ROUNDED)
            for key, value in results.items():
                table.add_row(key, value)
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
        
        self.report['results']['whois'] = results
        return results
    
    def ns_lookup(self):
        """Perform NS lookup"""
        console.print("[yellow]▶ NS Lookup[/yellow]")
        results = {'Resolve IP': self.resolve_ip() or 'N/A'}
        
        try:
            # Reverse DNS
            if self.ip:
                try:
                    hostname = socket.gethostbyaddr(self.ip)[0]
                    results['Reverse Lookup'] = hostname
                except:
                    results['Reverse Lookup'] = 'Not found'
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                results['Nameservers'] = ', '.join([str(r) for r in ns_records])
            except:
                results['Nameservers'] = 'No NS records found'
            
            table = Table(title="NS Lookup Results", box=box.ROUNDED)
            for key, value in results.items():
                table.add_row(key, value)
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
        
        self.report['results']['ns_lookup'] = results
        return results
    
    def dns_records(self):
        """Get DNS records"""
        console.print("[yellow]▶ DNS Records[/yellow]")
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']
        results = {}
        
        for record_type in record_types:
            try:
                records = dns.resolver.resolve(self.domain, record_type)
                results[record_type] = [str(r) for r in records]
            except:
                results[record_type] = ['No records found']
        
        table = Table(title="DNS Records", box=box.ROUNDED)
        for record_type, values in results.items():
            table.add_row(record_type, ', '.join(values[:3]) + ('...' if len(values) > 3 else ''))
        console.print(table)
        
        self.report['results']['dns'] = results
        return results
    
    def ping_check(self):
        """Perform ping check"""
        console.print("[yellow]▶ Ping Check[/yellow]")
        results = {}
        
        try:
            import platform
            system = platform.system()
            
            if system == 'Windows':
                cmd = ['ping', '-n', '4', self.domain]
            else:
                cmd = ['ping', '-c', '4', self.domain]
            
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode()
            
            # Parse latency
            latency_match = re.search(r'time[=<](\d+\.?\d*)', output, re.IGNORECASE)
            if latency_match:
                results['Latency'] = f"{latency_match.group(1)} ms"
            
            # Parse packet loss
            loss_match = re.search(r'(\d+)% loss', output, re.IGNORECASE)
            if loss_match:
                results['Packet Loss'] = f"{loss_match.group(1)}%"
            
            # Determine OS from TTL
            ttl_match = re.search(r'TTL=(\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    results['OS'] = 'Linux/Unix'
                elif ttl <= 128:
                    results['OS'] = 'Windows'
                elif ttl <= 255:
                    results['OS'] = 'Cisco/Solaris'
            
            table = Table(title="Ping Results", box=box.ROUNDED)
            for key, value in results.items():
                table.add_row(key, value)
            console.print(table)
            
        except subprocess.TimeoutExpired:
            results['Status'] = 'Timeout'
            console.print("[red]Ping timeout[/red]")
        except Exception as e:
            results['Status'] = f"Error: {str(e)}"
            console.print(f"[red]Error: {str(e)}[/red]")
        
        self.report['results']['ping'] = results
        return results
    
    def traceroute(self):
        """Perform traceroute"""
        console.print("[yellow]▶ Traceroute[/yellow]")
        results = {'Status': 'Not implemented'}
        
        try:
            import platform
            system = platform.system()
            
            if system == 'Windows':
                cmd = ['tracert', '-h', '10', self.domain]
            else:
                cmd = ['traceroute', '-m', '10', self.domain]
            
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30).decode()
            lines = output.split('\n')
            hops = []
            for line in lines:
                if line.strip() and not line.startswith(' '):
                    hops.append(line.strip())
            
            table = Table(title="Traceroute Results", box=box.ROUNDED)
            for i, hop in enumerate(hops[:10]):
                table.add_row(str(i+1), hop[:60])
            console.print(table)
            results['Status'] = 'Completed'
            
        except subprocess.TimeoutExpired:
            console.print("[red]Traceroute timeout[/red]")
            results['Status'] = 'Timeout'
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            results['Status'] = f"Error: {str(e)}"
        
        self.report['results']['traceroute'] = results
        return results
    
    def detect_waf(self):
        """Detect WAF"""
        console.print("[yellow]▶ WAF Detection[/yellow]")
        results = {'WAF': 'Unknown'}
        
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            headers = response.headers
            
            waf_patterns = {
                'Cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
                'Akamai': ['x-akamai-transformed', 'x-akamai-request-id'],
                'Imperva': ['x-cdn', 'x-ip-whitelist'],
                'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
                'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
                'F5 BIG-IP': ['x-f5-served', 'x-f5-ev'],
                'Fortinet': ['x-fortinet-ips'],
                'Azure Front Door': ['x-azure-ref'],
                'Fastly': ['x-fastly-request-id', 'x-served-by']
            }
            
            # Check headers
            for waf_name, patterns in waf_patterns.items():
                for pattern in patterns:
                    if any(pattern in str(h).lower() for h in headers):
                        results['WAF'] = waf_name
                        break
                if results['WAF'] != 'Unknown':
                    break
            
            # Check response
            if results['WAF'] == 'Unknown' and response.status_code in [403, 406]:
                if 'block' in response.text.lower() or 'security' in response.text.lower():
                    results['WAF'] = 'Unknown WAF detected'
            
            console.print(f"[bold green]WAF: {results['WAF']}[/bold green]")
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            results['Error'] = str(e)
        
        self.report['results']['waf'] = results
        return results
    
    def http_analysis(self):
        """Analyze HTTP headers"""
        console.print("[yellow]▶ HTTP Header Analysis[/yellow]")
        results = {}
        
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=False)
            headers = response.headers
            
            results['Status Code'] = response.status_code
            results['Server'] = headers.get('Server', 'Unknown')
            results['Powered By'] = headers.get('X-Powered-By', 'Unknown')
            results['Content Type'] = headers.get('Content-Type', 'Unknown')
            
            # Security Headers
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing')
            }
            
            results['Security Headers'] = security_headers
            results['Cookies'] = [c for c in response.cookies]
            
            # Check redirects
            if response.is_redirect:
                results['Redirects'] = response.headers.get('Location', 'Unknown')
            
            # Check robots.txt
            try:
                robots = self.session.get(f"http://{self.domain}/robots.txt", timeout=5)
                results['Robots.txt'] = 'Available' if robots.status_code == 200 else 'Not available'
            except:
                results['Robots.txt'] = 'Error checking'
            
            # Check sitemap.xml
            try:
                sitemap = self.session.get(f"http://{self.domain}/sitemap.xml", timeout=5)
                results['Sitemap.xml'] = 'Available' if sitemap.status_code == 200 else 'Not available'
            except:
                results['Sitemap.xml'] = 'Error checking'
            
            # Display results
            table = Table(title="HTTP Analysis", box=box.ROUNDED)
            table.add_row("Status Code", str(results['Status Code']))
            table.add_row("Server", results['Server'])
            table.add_row("Powered By", results['Powered By'])
            table.add_row("Content Type", results['Content Type'])
            table.add_row("Robots.txt", results['Robots.txt'])
            table.add_row("Sitemap.xml", results['Sitemap.xml'])
            console.print(table)
            
            # Security Headers table
            sec_table = Table(title="Security Headers", box=box.ROUNDED)
            for key, value in security_headers.items():
                color = "green" if value != "Missing" else "red"
                sec_table.add_row(key, f"[{color}]{value}[/{color}]")
            console.print(sec_table)
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            results['Error'] = str(e)
        
        self.report['results']['http_analysis'] = results
        return results
    
    def directory_discovery(self):
        """Discover common directories"""
        console.print("[yellow]▶ Directory Discovery[/yellow]")
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("[cyan]Scanning directories...", total=len(self.common_dirs))
            
            def check_dir(dir_path):
                try:
                    url = f"{self.target}/{dir_path}"
                    response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 401, 403]:
                        return (dir_path, response.status_code, len(response.content))
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_dir, dir_path) for dir_path in self.common_dirs]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    progress.update(task, advance=1)
            
            progress.update(task, completed=len(self.common_dirs))
        
        # Display results
        if results:
            table = Table(title="Discovered Directories", box=box.ROUNDED)
            table.add_column("Directory", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Size", style="green")
            
            for dir_path, status, size in results:
                color = "green" if status == 200 else "yellow" if status in [301, 302] else "red"
                table.add_row(dir_path, f"[{color}]{status}[/{color}]", f"{size} bytes")
            console.print(table)
        else:
            console.print("[yellow]No directories discovered[/yellow]")
        
        self.report['results']['directories'] = results
        return results
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        console.print("[yellow]▶ Subdomain Enumeration[/yellow]")
        discovered = set()
        
        # Try crt.sh
        try:
            response = requests.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        name = entry['name_value'].lower()
                        if self.domain in name:
                            discovered.add(name)
        except:
            pass
        
        # Try Hackertarget
        try:
            response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0]
                        discovered.add(subdomain)
        except:
            pass
        
        # DNS brute-force
        def check_subdomain(sub):
            try:
                dns.resolver.resolve(f"{sub}.{self.domain}", 'A')
                return f"{sub}.{self.domain}"
            except:
                return None
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Bruteforcing subdomains...", total=len(self.subdomains))
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in self.subdomains]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        discovered.add(result)
                    progress.update(task, advance=1)
        
        # Display results
        discovered = sorted(discovered)
        if discovered:
            table = Table(title=f"Discovered Subdomains ({len(discovered)})", box=box.ROUNDED)
            table.add_column("Subdomain", style="cyan")
            for sub in discovered:
                table.add_row(sub)
            console.print(table)
        else:
            console.print("[yellow]No subdomains discovered[/yellow]")
        
        self.report['results']['subdomains'] = list(discovered)
        return list(discovered)
    
    def all_in_one(self):
        """Run all modules"""
        console.print("[bold cyan]🚀 Running All-in-One Reconnaissance[/bold cyan]")
        
        with Progress() as progress:
            tasks = [
                ("WHOIS Lookup", self.whois_lookup),
                ("DNS Records", self.dns_records),
                ("IP Resolution", self.resolve_ip),
                ("NS Lookup", self.ns_lookup),
                ("HTTP Headers", self.http_analysis),
                ("WAF Detection", self.detect_waf),
                ("Ping Check", self.ping_check),
                ("Traceroute", self.traceroute),
                ("Subdomains", self.subdomain_enumeration),
                ("Directories", self.directory_discovery)
            ]
            
            task = progress.add_task("[cyan]Running all scans...", total=len(tasks))
            for name, func in tasks:
                progress.update(task, description=f"[cyan]Running: {name}")
                try:
                    func()
                except Exception as e:
                    console.print(f"[red]Error in {name}: {str(e)}[/red]")
                progress.update(task, advance=1)
        
        self.generate_summary()
    
    def generate_summary(self):
        """Generate final summary"""
        console.print("\n[bold green]✅ All-in-One Recon Complete![/bold green]")
        
        summary = {
            'Target': self.target,
            'Domain': self.domain,
            'IP': self.ip or 'N/A',
            'WHOIS': self.report['results'].get('whois', {}).get('Registrar', 'N/A'),
            'WAF': self.report['results'].get('waf', {}).get('WAF', 'Unknown'),
            'Server': self.report['results'].get('http_analysis', {}).get('Server', 'Unknown'),
            'Subdomains': len(self.report['results'].get('subdomains', [])),
            'Directories': len(self.report['results'].get('directories', []))
        }
        
        table = Table(title="Recon Summary", box=box.ROUNDED)
        for key, value in summary.items():
            table.add_row(key, str(value))
        console.print(table)
        
        # Save report
        self.save_report()
    
    def save_report(self):
        """Save report to files"""
        try:
            # Create reports directory
            os.makedirs('reports', exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_filename = f"reports/{self.domain}_{timestamp}"
            
            # Save JSON
            with open(f"{base_filename}.json", 'w') as f:
                json.dump(self.report, f, indent=2, default=str)
            
            # Save TXT
            with open(f"{base_filename}.txt", 'w') as f:
                f.write(f"We bRecon Report\n")
                f.write(f"{'='*60}\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Timestamp: {self.report['timestamp']}\n")
                f.write(f"{'='*60}\n\n")
                
                for section, data in self.report['results'].items():
                    f.write(f"{section.upper()}\n")
                    f.write(f"{'-'*40}\n")
                    if isinstance(data, dict):
                        for key, value in data.items():
                            f.write(f"{key}: {value}\n")
                    elif isinstance(data, list):
                        for item in data[:20]:  # Limit to 20 items
                            f.write(f"{item}\n")
                    else:
                        f.write(f"{data}\n")
                    f.write("\n")
            
            console.print(f"[green]✅ Report saved to: {base_filename}.json and {base_filename}.txt[/green]")
            
        except Exception as e:
            console.print(f"[red]Error saving report: {str(e)}[/red]")
    
    def run(self):
        """Main menu"""
        self.print_banner()
        
        while True:
            try:
                console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
                console.print("[bold green]MAIN MENU[/bold green]")
                console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
                console.print("1. WHOIS Lookup")
                console.print("2. NS Lookup")
                console.print("3. DNS Records (A, AAAA, MX, TXT, CNAME)")
                console.print("4. Ping Check")
                console.print("5. Traceroute")
                console.print("6. WAF Detection")
                console.print("7. HTTP Header Analysis")
                console.print("8. Directory Discovery")
                console.print("9. Subdomain Enumeration")
                console.print("10. Basic All-in-One Recon")
                console.print("0. Exit")
                console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
                
                choice = input("[bold yellow]Enter your choice: [/bold yellow]").strip()
                
                if choice == '0':
                    console.print("[bold red]Goodbye![/bold red]")
                    break
                
                options = {
                    '1': self.whois_lookup,
                    '2': self.ns_lookup,
                    '3': self.dns_records,
                    '4': self.ping_check,
                    '5': self.traceroute,
                    '6': self.detect_waf,
                    '7': self.http_analysis,
                    '8': self.directory_discovery,
                    '9': self.subdomain_enumeration,
                    '10': self.all_in_one
                }
                
                if choice in options:
                    options[choice]()
                else:
                    console.print("[red]Invalid choice![/red]")
                
            except KeyboardInterrupt:
                console.print("\n[red]Scan interrupted by user[/red]")
                break
            except Exception as e:
                console.print(f"[red]Unexpected error: {str(e)}[/red]")

def main():
    """Main entry point"""
    try:
        console.print("[bold blue]🔍 WebRecon Tool - Web Reconnaissance[/bold blue]")
        target = input("[bold yellow]Enter target URL or domain: [/bold yellow]").strip()
        
        if not target:
            console.print("[red]Error: Target cannot be empty[/red]")
            return
        
        recon = WebRecon(target)
        recon.run()
        
    except KeyboardInterrupt:
        console.print("\n[red]Program terminated by user[/red]")
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")

if __name__ == "__main__":
    main()