#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT AI Tool
Version: 1.0.0
Owner: Aditya Hansda
A professional cybersecurity reconnaissance framework for OSINT gathering,
domain analysis, and security assessments.
"""

import os
import sys
import re
import json
import logging
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path

# Third-party imports
try:
    import requests
    import whois
    import dns.resolver
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
    REPORTLAB_AVAILABLE = False
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as PDFTable, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        REPORTLAB_AVAILABLE = True
    except ImportError:
        pass
except ImportError as e:
    print(f"Error: Missing required module. Please install: pip install rich requests python-whois dnspython reportlab")
    print(f"Details: {e}")
    sys.exit(1)

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "osint.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Rich console
console = Console()

@dataclass
class ScanResult:
    """Base class for scan results"""
    module_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None

class DomainValidator:
    """Domain name validation utility"""
    
    @staticmethod
    def is_valid(domain: str) -> bool:
        domain = domain.strip().lower()
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def normalize(domain: str) -> str:
        return domain.strip().lower()

class PortScanner:
    """Port scanning utilities"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 8080: "HTTP-Alt"
    }
    
    @staticmethod
    def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str]:
        service = PortScanner.COMMON_PORTS.get(port, "Unknown")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            status = "🟢 Open" if result == 0 else "🔴 Closed"
            return (port, service, status)
        except Exception:
            return (port, service, "⚠️ Error")

class SecurityHeadersChecker:
    """Check HTTP security headers"""
    
    IMPORTANT_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    
    @staticmethod
    def check(url: str) -> Dict[str, Any]:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        try:
            response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
            headers = response.headers
            result = {}
            for header in SecurityHeadersChecker.IMPORTANT_HEADERS:
                value = headers.get(header, "❌ Not Set")
                if value != "❌ Not Set":
                    value = "✅ " + value[:50] + ("..." if len(value) > 50 else "")
                result[header] = value
            return {"success": True, "headers": result, "status_code": response.status_code}
        except Exception as e:
            return {"success": False, "error": str(e)}

class OWASPReference:
    """OWASP Top 10 vulnerability reference"""
    
    TOP_10 = [
        {"id": "🔴 A01:2021", "name": "Broken Access Control", "description": "Users can act outside their intended permissions", "risk": "Critical"},
        {"id": "🟠 A02:2021", "name": "Cryptographic Failures", "description": "Sensitive data exposure due to weak crypto", "risk": "High"},
        {"id": "🔴 A03:2021", "name": "Injection", "description": "SQL, NoSQL, OS command injection flaws", "risk": "Critical"},
        {"id": "🟠 A04:2021", "name": "Insecure Design", "description": "Missing security controls in design phase", "risk": "High"},
        {"id": "🟡 A05:2021", "name": "Security Misconfiguration", "description": "Improperly configured security settings", "risk": "Medium"},
        {"id": "🟠 A06:2021", "name": "Vulnerable Components", "description": "Outdated or vulnerable libraries", "risk": "High"},
        {"id": "🔴 A07:2021", "name": "Identification Failures", "description": "Weak authentication/session management", "risk": "Critical"},
        {"id": "🟡 A08:2021", "name": "Software Integrity Failures", "description": "Unverified software updates", "risk": "Medium"},
        {"id": "🟢 A09:2021", "name": "Monitoring Failures", "description": "Insufficient logging and monitoring", "risk": "Low"},
        {"id": "🟠 A10:2021", "name": "SSRF", "description": "Server-side request forgery attacks", "risk": "High"}
    ]
    
    @staticmethod
    def get_table() -> Table:
        table = Table(title="🔒 OWASP Top 10 (2021)", box=box.ROUNDED, style="bright_white")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Vulnerability", style="bright_yellow")
        table.add_column("Description", style="dim")
        table.add_column("Risk Level", style="red")
        
        for item in OWASPReference.TOP_10:
            risk_color = "bright_red" if item["risk"] == "Critical" else "yellow" if item["risk"] == "High" else "green"
            table.add_row(item["id"], item["name"], item["description"], f"[{risk_color}]{item['risk']}[/{risk_color}]")
        return table

class ReportGenerator:
    """Generate reports in multiple formats"""
    
    def __init__(self, target: str, results: Dict[str, ScanResult]):
        self.target = target
        self.results = results
        self.timestamp = datetime.now()
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_txt(self) -> Path:
        filename = self.report_dir / f"{self.target.replace('.', '_')}_report.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("OSINT AI TOOL - Professional Security Reconnaissance Report\n")
            f.write("="*80 + "\n")
            f.write(f"Target Domain: {self.target}\n")
            f.write(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tool Owner: Aditya Hansda\n")
            f.write(f"Version: 1.0.0\n")
            f.write("="*80 + "\n\n")
            
            for module_name, result in self.results.items():
                f.write(f"\n{'='*60}\n")
                f.write(f"📊 {module_name.upper()}\n")
                f.write(f"{'='*60}\n")
                if result.success:
                    for key, value in result.data.items():
                        if isinstance(value, dict):
                            f.write(f"\n{key}:\n")
                            for sub_key, sub_value in value.items():
                                f.write(f"  • {sub_key}: {sub_value}\n")
                        elif isinstance(value, list):
                            f.write(f"\n{key}:\n")
                            for item in value[:10]:
                                if isinstance(item, dict):
                                    f.write(f"  • {item.get('port', '')}: {item.get('status', '')}\n")
                                else:
                                    f.write(f"  • {item}\n")
                        else:
                            f.write(f"  {key}: {value}\n")
                else:
                    f.write(f"❌ Error: {result.error}\n")
                f.write("\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("End of Report - Generated by OSINT AI Tool\n")
            f.write("="*80 + "\n")
        
        logger.info(f"✅ TXT report generated: {filename}")
        return filename
    
    def generate_json(self) -> Path:
        filename = self.report_dir / f"{self.target.replace('.', '_')}_report.json"
        export_data = {
            "tool": "OSINT AI Tool",
            "version": "1.0.0",
            "owner": "Aditya Hansda",
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "results": {}
        }
        
        for module_name, result in self.results.items():
            export_data["results"][module_name] = {
                "success": result.success,
                "timestamp": result.timestamp.isoformat(),
                "data": result.data,
                "error": result.error
            }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ JSON report generated: {filename}")
        return filename
    
    def generate_pdf(self) -> Optional[Path]:
        if not REPORTLAB_AVAILABLE:
            logger.warning("⚠️ ReportLab not available, skipping PDF generation")
            console.print("[yellow]⚠️ ReportLab not installed. Please run: pip install reportlab[/yellow]")
            return None
        
        try:
            filename = self.report_dir / f"{self.target.replace('.', '_')}_report.pdf"
            doc = SimpleDocTemplate(str(filename), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#FF4444'), alignment=1, spaceAfter=30)
            story.append(Paragraph("OSINT AI Tool", title_style))
            story.append(Paragraph("Professional Security Reconnaissance Report", styles['Heading2']))
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph(f"<b>Target Domain:</b> {self.target}", styles['Normal']))
            story.append(Paragraph(f"<b>Scan Date:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph("<b>Tool Owner:</b> Aditya Hansda", styles['Normal']))
            story.append(Paragraph("<b>Version:</b> 1.0.0", styles['Normal']))
            story.append(Spacer(1, 1*inch))
            story.append(PageBreak())
            
            # Results
            story.append(Paragraph("Detailed Scan Results", styles['Heading1']))
            story.append(Spacer(1, 0.3*inch))
            
            for module_name, result in self.results.items():
                story.append(Paragraph(module_name, styles['Heading2']))
                if result.success:
                    for key, value in result.data.items():
                        if isinstance(value, dict):
                            story.append(Paragraph(f"<b>{key}:</b>", styles['Normal']))
                            for sub_key, sub_value in value.items():
                                story.append(Paragraph(f"• {sub_key}: {sub_value}", styles['Normal']))
                        elif isinstance(value, list):
                            story.append(Paragraph(f"<b>{key}:</b>", styles['Normal']))
                            for item in value[:5]:
                                if isinstance(item, dict):
                                    story.append(Paragraph(f"• Port {item.get('port', 'N/A')}: {item.get('status', 'N/A')}", styles['Normal']))
                        else:
                            story.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))
                else:
                    story.append(Paragraph(f"<font color='red'>Error: {result.error}</font>", styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
            
            doc.build(story)
            logger.info(f"✅ PDF report generated: {filename}")
            console.print(f"[green]✅ PDF Report created: {filename}[/green]")
            return filename
        except Exception as e:
            logger.error(f"❌ PDF generation failed: {e}")
            console.print(f"[red]❌ PDF generation failed: {e}[/red]")
            return None

class OSINTAI:
    """Main OSINT AI Tool Framework"""
    
    def __init__(self):
        self.target: Optional[str] = None
        self.results: Dict[str, ScanResult] = {}
    
    def display_banner(self):
        """Display colorful professional ASCII banner"""
        banner_art = """
╔═════════════════════════════════════════════════════════════════════╗
║                                                                     ║
║    ██████╗ ███████╗██╗███╗   ██╗████████╗     █████╗ ██╗            ║
║   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██║            ║
║   ██║   ██║███████╗██║██╔██╗ ██║   ██║       ███████║██║            ║
║   ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██║██║            ║
║   ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║██║            ║
║    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚═╝            ║
║                                                                     ║
║                                                                     ║
║                                                                  ═══╝
"""
        title = "[bold bright_red]OSINT AI TOOL[/bold bright_red]"
        subtitle = "[bold bright_yellow]🔐 Advanced Cybersecurity Reconnaissance Framework 🔐[/bold bright_yellow]"
        developer = "[italic cyan]👨‍💻 Developed By: Aditya Hansda | Version: 1.0.0[/italic cyan]"
        
        content = f"\n{banner_art}\n\n{title:^80}\n{subtitle:^80}\n\n{developer:^80}\n"
        panel = Panel(content, border_style="bright_red", padding=(1, 2), title="[bold bright_white]⚡ SECURITY TOOL ⚡[/bold bright_white]", title_align="center")
        
        console.print(panel)
        console.print("[dim]🔒 OSINT AI Tool | Developed By Aditya Hansda | For Authorized Use Only 🔒[/dim]\n")
    
    def get_target(self) -> str:
        console.print("[bold bright_cyan]🎯 TARGET ACQUISITION PHASE[/bold bright_cyan]")
        while True:
            domain = Prompt.ask("[bold green]Enter Target Domain[/bold green]")
            if DomainValidator.is_valid(domain):
                console.print(f"[green]✅ Target set: {domain}[/green]")
                return DomainValidator.normalize(domain)
            console.print("[red]❌ Invalid domain format. Please try again.[/red]")
    
    def display_main_menu(self) -> str:
        menu_content = """
[bold bright_yellow]📋 MAIN MENU[/bold bright_yellow]

[bold cyan]1️⃣[/bold cyan] [green]Full Scan[/green] - Complete reconnaissance
[bold cyan]2️⃣[/bold cyan] [yellow]Selective Scan[/yellow] - Choose specific modules  
[bold cyan]3️⃣[/bold cyan] [blue]Change Target[/blue] - Set new target domain
[bold cyan]4️⃣[/bold cyan] [red]Exit[/red] - Close the tool
"""
        panel = Panel(menu_content, border_style="bright_blue", padding=(1, 4), title="[bold white]⚙️ SCAN CONFIGURATION ⚙️[/bold white]", title_align="center")
        console.print(panel)
        return Prompt.ask("[bold bright_white]Select Option[/bold bright_white]", choices=["1", "2", "3", "4"])
    
    def display_selective_menu(self) -> List[int]:
        modules = [
            "🌐 Domain Information", "🔍 DNS Lookup", "📋 WHOIS Lookup", "🌍 IP Information",
            "🔒 SSL Information", "🚪 Port Scanner", "🛡️ Security Headers Checker", "📚 OWASP Top 10"
        ]
        
        table = Table(title="📡 AVAILABLE SCAN MODULES", box=box.ROUNDED, style="bright_white")
        table.add_column("🆔", style="cyan", width=6)
        table.add_column("📦 Module", style="bright_yellow")
        table.add_column("📝 Description", style="dim")
        
        descriptions = [
            "Domain registration data", "DNS records (A, AAAA, MX, NS, TXT)",
            "Complete WHOIS information", "IP geolocation and network data",
            "SSL/TLS certificate details", "Common port scanning (21-8080)",
            "HTTP security headers analysis", "OWASP Top 10 vulnerabilities"
        ]
        
        for idx, (module, desc) in enumerate(zip(modules, descriptions), 1):
            table.add_row(str(idx), module, desc)
        
        console.print(table)
        console.print("[bold yellow]💡 Tip: Enter numbers separated by commas (e.g., 1,3,5,7)[/bold yellow]")
        choice_str = Prompt.ask("[bold green]Select modules to scan[/bold green]")
        
        choices = []
        for part in choice_str.split(','):
            try:
                num = int(part.strip())
                if 1 <= num <= 8:
                    choices.append(num)
            except ValueError:
                continue
        
        if choices:
            console.print(f"[green]✅ Selected modules: {', '.join(map(str, choices))}[/green]")
        else:
            console.print("[red]❌ No valid modules selected[/red]")
        
        return sorted(set(choices)) if choices else []
    
    def scan_domain_info(self) -> ScanResult:
        result = ScanResult("🌐 Domain Information")
        try:
            w = whois.whois(self.target)
            data = {
                "Domain Name": self.target,
                "Registrar": str(w.registrar)[:100] if w.registrar else "N/A",
                "Creation Date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                "Expiration Date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                "Name Servers": ", ".join(w.name_servers[:3]) if w.name_servers else "N/A"
            }
            result.data = data
            logger.info(f"✅ Domain info retrieved for {self.target}")
        except Exception as e:
            result.success = False
            result.error = str(e)
            logger.error(f"❌ Domain info failed: {e}")
        return result
    
    def scan_dns(self) -> ScanResult:
        result = ScanResult("🔍 DNS Lookup")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        dns_data = {}
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record)
                dns_data[record] = [str(rdata) for rdata in answers][:5]
            except Exception:
                dns_data[record] = ["No records found"]
        result.data = dns_data
        logger.info(f"✅ DNS lookup completed for {self.target}")
        return result
    
    def scan_whois(self) -> ScanResult:
        result = ScanResult("📋 WHOIS Lookup")
        try:
            w = whois.whois(self.target)
            whois_text = str(w.text) if hasattr(w, 'text') else str(w)
            if len(whois_text) > 1500:
                whois_text = whois_text[:1500] + "... (truncated)"
            result.data = {"WHOIS Data": whois_text}
            logger.info(f"✅ WHOIS lookup completed for {self.target}")
        except Exception as e:
            result.success = False
            result.error = str(e)
            logger.error(f"❌ WHOIS lookup failed: {e}")
        return result
    
    def scan_ip_info(self) -> ScanResult:
        result = ScanResult("🌍 IP Information")
        try:
            ip = socket.gethostbyname(self.target)
            data = {"IP Address": ip}
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                api_data = response.json()
                if api_data.get('status') == 'success':
                    data.update({
                        "Country": f"{api_data.get('country', 'N/A')}",
                        "City": api_data.get('city', 'N/A'),
                        "ISP": api_data.get('isp', 'N/A'),
                        "Organization": api_data.get('org', 'N/A'),
                        "ASN": api_data.get('as', 'N/A')
                    })
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
                data["Reverse DNS"] = reverse_dns
            except:
                data["Reverse DNS"] = "No PTR record"
            result.data = data
            logger.info(f"✅ IP info retrieved for {self.target}")
        except Exception as e:
            result.success = False
            result.error = str(e)
            logger.error(f"❌ IP info failed: {e}")
        return result
    
    def scan_ssl(self) -> ScanResult:
        result = ScanResult("🔒 SSL Information")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    data = {
                        "Issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'N/A'),
                        "Subject": dict(x[0] for x in cert['subject']).get('commonName', 'N/A'),
                        "Valid From": cert['notBefore'],
                        "Expires On": cert['notAfter']
                    }
                    result.data = data
            logger.info(f"✅ SSL info retrieved for {self.target}")
        except Exception as e:
            result.success = False
            result.error = str(e)
            logger.error(f"❌ SSL info failed: {e}")
        return result
    
    def scan_ports(self) -> ScanResult:
        result = ScanResult("🚪 Port Scanner")
        host = socket.gethostbyname(self.target)
        port_results = []
        for port in PortScanner.COMMON_PORTS.keys():
            p, svc, status = PortScanner.scan_port(host, port)
            port_results.append({"port": p, "service": svc, "status": status})
        open_ports = [p for p in port_results if "Open" in p["status"]]
        result.data = {"total_scanned": len(port_results), "open_ports": len(open_ports), "ports": port_results}
        logger.info(f"✅ Port scan completed for {self.target}")
        return result
    
    def scan_security_headers(self) -> ScanResult:
        result = ScanResult("🛡️ Security Headers")
        check_result = SecurityHeadersChecker.check(self.target)
        if check_result["success"]:
            result.data = check_result["headers"]
        else:
            result.success = False
            result.error = check_result.get("error", "Unknown error")
        logger.info(f"✅ Security headers check completed for {self.target}")
        return result
    
    def scan_owasp(self) -> ScanResult:
        result = ScanResult("📚 OWASP Top 10")
        result.data = {"reference": "OWASP Top 10 (2021)", "total_risks": len(OWASPReference.TOP_10)}
        return result
    
    def display_results(self):
        console.print("\n[bold bright_green]📊 SCAN RESULTS SUMMARY[/bold bright_green]")
        console.print("─" * 80)
        for module_name, result in self.results.items():
            if not result.success:
                console.print(f"[red]❌ {module_name}: {result.error}[/red]")
                continue
            console.print(f"\n[bold bright_cyan]✓ {module_name}[/bold bright_cyan]")
            if module_name == "🚪 Port Scanner":
                table = Table(title="🔌 Port Scan Results", box=box.ROUNDED)
                table.add_column("Port", style="cyan", justify="center")
                table.add_column("Service", style="yellow")
                table.add_column("Status", style="white")
                for p in result.data.get("ports", []):
                    table.add_row(str(p["port"]), p["service"], p["status"])
                console.print(table)
            elif module_name == "📚 OWASP Top 10":
                console.print(OWASPReference.get_table())
            elif module_name == "🛡️ Security Headers":
                table = Table(title="🔐 Security Headers Analysis", box=box.ROUNDED)
                table.add_column("Header", style="cyan", width=30)
                table.add_column("Value", style="white")
                for header, value in result.data.items():
                    color = "green" if "✅" in str(value) else "red" if "❌" in str(value) else "yellow"
                    table.add_row(header, f"[{color}]{value}[/{color}]")
                console.print(table)
            elif module_name == "🔍 DNS Lookup":
                for record_type, records in result.data.items():
                    console.print(f"[bold yellow]{record_type}[/bold yellow] Records: [cyan]{', '.join(records)}[/cyan]")
            else:
                for key, value in result.data.items():
                    if key not in ["items", "ports"]:
                        console.print(f"  [green]▶[/green] {key}: [cyan]{value}[/cyan]")
    
    def generate_report_prompt(self):
        console.print("\n[bold]Generate Report?[/bold]")
        console.print("[1] PDF\n[2] TXT\n[3] JSON\n[4] Skip")
        choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"])
        generator = ReportGenerator(self.target, self.results)
        if choice == "1":
            generator.generate_pdf()
        elif choice == "2":
            generator.generate_txt()
        elif choice == "3":
            generator.generate_json()
        else:
            console.print("[dim]Report generation skipped[/dim]")
    
    def run_full_scan(self):
        modules = [self.scan_domain_info, self.scan_dns, self.scan_whois, self.scan_ip_info, self.scan_ssl, self.scan_ports, self.scan_security_headers, self.scan_owasp]
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Running Full Scan...", total=len(modules))
            for scan_func in modules:
                progress.update(task, description=f"[cyan]Running {scan_func.__name__}...")
                result = scan_func()
                self.results[result.module_name] = result
                progress.advance(task)
        self.display_results()
        self.generate_report_prompt()
    
    def run_selective_scan(self, choices: List[int]):
        module_map = {1: self.scan_domain_info, 2: self.scan_dns, 3: self.scan_whois, 4: self.scan_ip_info, 5: self.scan_ssl, 6: self.scan_ports, 7: self.scan_security_headers, 8: self.scan_owasp}
        modules_to_run = [module_map[choice] for choice in choices if choice in module_map]
        if not modules_to_run:
            console.print("[red]No valid modules selected.[/red]")
            return
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Running Selective Scan...", total=len(modules_to_run))
            for scan_func in modules_to_run:
                progress.update(task, description=f"[cyan]Running {scan_func.__name__}...")
                result = scan_func()
                self.results[result.module_name] = result
                progress.advance(task)
        self.display_results()
        self.generate_report_prompt()
    
    def run(self):
        logger.info("OSINT AI Tool started")
        console.clear()
        self.display_banner()
        self.target = self.get_target()
        while True:
            self.results.clear()
            choice = self.display_main_menu()
            if choice == "1":
                logger.info(f"Starting full scan for {self.target}")
                self.run_full_scan()
            elif choice == "2":
                selected = self.display_selective_menu()
                if selected:
                    logger.info(f"Starting selective scan for {self.target}")
                    self.run_selective_scan(selected)
            elif choice == "3":
                self.target = self.get_target()
                console.print(f"[green]Target changed to: {self.target}[/green]")
            elif choice == "4":
                console.print("[bold red]Exiting OSINT AI Tool. Stay secure![/bold red]")
                logger.info("OSINT AI Tool terminated")
                break

def main():
    try:
        tool = OSINTAI()
        tool.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user. Exiting...[/bold red]")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        console.print(f"[bold red]Fatal Error: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
