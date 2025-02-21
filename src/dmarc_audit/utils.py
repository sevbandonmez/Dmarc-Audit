from datetime import datetime
import json
import csv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pyfiglet import Figlet
from colorama import Fore, Style
from .config import BANNER_SETTINGS

console = Console()

def print_banner():
    f = Figlet(font=BANNER_SETTINGS['font'])
    banner = f.renderText('DMARC Audit')
    
    # Footer text
    footer = "\n@sevbandonmez | v1.0 | DMARC Security Audit Tool"
    
    # Combine banner and footer in panel
    full_banner = banner + footer
    
    console.print(Panel.fit(
        full_banner,
        border_style=BANNER_SETTINGS['border_style'],
        padding=(1, 2)
    ))
    
    console.print("=" * 50, style="blue")
    console.print(f"Scan started at: {datetime.now()}", style="yellow")
    console.print("=" * 50, style="blue")

def create_report(domain, spf_vulns, dmarc_vulns, dkim_vulns, format='text'):
    report = {
        "scan_time": datetime.now().isoformat(),
        "domain": domain,
        "spf_vulnerabilities": spf_vulns,
        "dmarc_vulnerabilities": dmarc_vulns,
        "dkim_vulnerabilities": dkim_vulns
    }
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if format == 'json':
        with open(f"report_{domain}_{timestamp}.json", 'w') as f:
            json.dump(report, f, indent=4)
    elif format == 'csv':
        with open(f"report_{domain}_{timestamp}.csv", 'w') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Finding'])
            for v in spf_vulns:
                writer.writerow(['SPF', v])
            for v in dmarc_vulns:
                writer.writerow(['DMARC', v])
            for v in dkim_vulns:
                writer.writerow(['DKIM', v])

def print_results_table(title, vulns, recs):
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Type", style="dim")
    table.add_column("Finding")
    table.add_column("Severity")
    
    for v in vulns:
        table.add_row("Vulnerability", v, "ERROR")
    for r in recs:
        table.add_row("Recommendation", r, "WARNING")
    
    console.print(table)

def print_status(message, status):
    color = Fore.GREEN if status == "OK" else Fore.YELLOW if status == "WARNING" else Fore.RED
    print(f"{color}[{status}]{Style.RESET_ALL} {message}") 