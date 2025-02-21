#!/usr/bin/env python3
"""
DMARC Audit Tool
---------------
Created by: Sevban Dönmez
"""

import sys
import argparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
from dmarc_audit.utils import print_banner, create_report, print_results_table
from dmarc_audit.analyzer import (
    analyze_spf, 
    analyze_dmarc, 
    check_dkim,
    SecurityAnalyzer,
    get_dns_record
)

console = Console()

def main():
    try:
        parser = argparse.ArgumentParser(description="DMARC Security Audit Tool")
        parser.add_argument("domain", help="Domain to audit")
        parser.add_argument("--dkim-selector", help="DKIM selector (default: selector1)", default="selector1")
        parser.add_argument("--format", choices=['text', 'json', 'csv'], default='text', help="Output format")
        parser.add_argument("--detailed", action="store_true", help="Generate detailed security report")
        parser.add_argument("--dns-timeout", type=int, default=10, help="DNS query timeout in seconds")
        args = parser.parse_args()

        print_banner()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=False,
            refresh_per_second=1,
            disable=False
        ) as progress:
            # Tüm taskları başlangıçta oluştur
            tasks = {}
            
            # SPF Analizi
            tasks['spf'] = progress.add_task("[cyan]Analyzing SPF records...", total=1)
            spf_record = get_dns_record(args.domain, "TXT")
            spf_vulns, spf_recs = analyze_spf([r for r in spf_record if "v=spf1" in r.lower()])
            progress.update(tasks['spf'], completed=1)
            
            # DMARC Analizi
            tasks['dmarc'] = progress.add_task("[cyan]Analyzing DMARC records...", total=1)
            dmarc_record = get_dns_record(f"_dmarc.{args.domain}", "TXT")
            dmarc_vulns, dmarc_recs = analyze_dmarc([r for r in dmarc_record if "v=dmarc1" in r.lower()])
            progress.update(tasks['dmarc'], completed=1)
            
            # DKIM Analizi
            tasks['dkim'] = progress.add_task("[cyan]Analyzing DKIM records...", total=1)
            dkim_vulns, dkim_recs = check_dkim(args.domain, args.dkim_selector)
            progress.update(tasks['dkim'], completed=1)
            
            # Güvenlik Analizi
            tasks['security'] = progress.add_task("[cyan]Performing security analysis...", total=1)
            security_analyzer = SecurityAnalyzer(args.domain)
            mx_vulns = security_analyzer.check_mx_records()
            email_vulns, headers = security_analyzer.check_email_headers()
            progress.update(tasks['security'], completed=1)

        # Sonuçları göster
        console.print("\n[bold cyan]Results:[/bold cyan]")
        
        # SPF Sonuçları
        if spf_vulns or spf_recs:
            print_results_table("SPF Analysis", spf_vulns, spf_recs)
        else:
            console.print("[yellow]No SPF records found[/yellow]")
        
        # DMARC Sonuçları
        if dmarc_vulns or dmarc_recs:
            print_results_table("DMARC Analysis", dmarc_vulns, dmarc_recs)
        else:
            console.print("[yellow]No DMARC records found[/yellow]")
        
        # DKIM Sonuçları
        if dkim_vulns or dkim_recs:
            print_results_table(f"DKIM Analysis ({args.dkim_selector})", dkim_vulns, dkim_recs)
        else:
            console.print(f"[yellow]No DKIM records found for selector: {args.dkim_selector}[/yellow]")
        
        # Güvenlik Kontrolleri
        if mx_vulns or email_vulns:
            print_results_table("Additional Security Checks", mx_vulns + email_vulns, [])
        else:
            console.print("[green]No additional security issues found[/green]")

        # Rapor oluştur
        if args.format in ['json', 'csv']:
            create_report(args.domain, spf_vulns, dmarc_vulns, dkim_vulns, args.format)
            console.print(f"\n[green]Report saved in {args.format} format[/green]")

        console.print("\n=== Audit Complete ===", style="cyan bold")

    except Exception as e:
        console.print(f"\nError during scan: {str(e)}", style="bold red")
        sys.exit(1)

if __name__ == "__main__":
    main() 