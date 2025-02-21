import dns.resolver
import socket
import ssl
from datetime import datetime
from rich.console import Console
from .config import DNS_TIMEOUT, DNS_LIFETIME, DNS_SERVERS
from .logger import logger

console = Console()

def get_dns_record(domain, record_type):
    resolver = dns.resolver.Resolver()
    
    # DNS sunucularını yapılandır
    resolver.nameservers = [
        DNS_SERVERS['google_primary'],      # 8.8.8.8
        DNS_SERVERS['google_secondary'],    # 8.8.4.4
        DNS_SERVERS['cloudflare_primary'],  # 1.1.1.1
        DNS_SERVERS['cloudflare_secondary'] # 1.0.0.1
    ]
    
    # Timeout ayarları
    resolver.timeout = 2.0    # Her sorgu için timeout
    resolver.lifetime = 10.0  # Toplam sorgu süresi limiti
    
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.Timeout:
        console.print(f"[yellow]Warning:[/yellow] DNS timeout while querying {domain}. Retrying with different DNS servers...")
        # Alternatif DNS sunucuları ile tekrar dene
        for ns in resolver.nameservers[1:]:
            resolver.nameservers = [ns]
            try:
                answers = resolver.resolve(domain, record_type)
                return [str(rdata) for rdata in answers]
            except:
                continue
        return []
    except dns.resolver.NXDOMAIN:
        logger.info(f"No DNS record found for {domain} ({record_type})")
        return []
    except Exception as e:
        logger.error(f"DNS lookup error for {domain}: {str(e)}")
        return []

def analyze_spf(spf_record):
    vulnerabilities = []
    recommendations = []
    if not spf_record:
        vulnerabilities.append("Missing SPF record")
        return vulnerabilities, recommendations
    spf = spf_record[0].lower()
    # Recommendations
    # Common vulnerability checks
    if "+all" in spf:
        vulnerabilities.append("Overly permissive SPF policy (+all)")
    if "include:mailgun.org" in spf or "include:sendgrid.net" in spf:
        vulnerabilities.append("Third-party email service included without proper restriction")
    if spf.count("include:") > 10:
        vulnerabilities.append("Excessive DNS lookups (more than 10 includes)")
    if "ptr" in spf:
        vulnerabilities.append("Insecure PTR mechanism used")
    recommendations = []
    # Recommendations
    if "redirect=" not in spf and "-all" not in spf:
        recommendations.append("Consider adding '-all' to enforce strict policy")
    if "exp=" not in spf:
        recommendations.append("Consider adding exp= modifier to receive explanation on failures")
    
    return vulnerabilities, recommendations
    
def analyze_dmarc(dmarc_record):
    vulnerabilities = []
    recommendations = []
    tags = {}
    
    if not dmarc_record:
        vulnerabilities.append("Missing DMARC record")
        return vulnerabilities, recommendations
        
    dmarc = dmarc_record[0].lower()
    
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key] = value

    # Policy checks
    policy = tags.get('p', 'none')
    if policy == 'none':
        vulnerabilities.append("Policy set to monitoring only (p=none)")
    if policy == 'reject' and 'pct' in tags and tags['pct'] != '100':
        vulnerabilities.append(f"Partial policy enforcement (pct={tags['pct']})")
    if 'ruf' in tags and len(tags['ruf'].split(",")) > 2:
        vulnerabilities.append("Too many forensic reporting URIs (max 2 recommended)")
    recommendations = []
    # Protocol validation
    if 'adkim' not in tags:
        recommendations.append("Consider specifying DKIM alignment mode (adkim)")
    if 'aspf' not in tags:
        recommendations.append("Consider specifying SPF alignment mode (aspf)")
    
    return vulnerabilities, recommendations

def check_rsa_key_strength(record):
    vulnerabilities = []
    recommendations = []
    try:
        if "k=rsa" in record.lower():
            key_parts = record.split('p=')[1].split(';')[0].strip()
            key_length = len(key_parts) * 6
            
            if key_length < 2048:
                vulnerabilities.append(f"Weak RSA key length detected ({key_length} bits)")
                recommendations.append("Upgrade RSA key length to at least 2048 bits")
            elif key_length < 4096:
                recommendations.append("Consider upgrading to 4096-bit RSA key for future-proof security")
    except:
        vulnerabilities.append("Unable to analyze RSA key length")
        
    return vulnerabilities, recommendations

def check_mta_security(domain):
    vulnerabilities = []
    recommendations = []
    try:
        mta_sts = get_dns_record(f"_mta-sts.{domain}", "TXT")
        if not mta_sts:
            recommendations.append("Implement MTA-STS for enhanced mail transport security")
        tls_rpt = get_dns_record(f"_smtp._tls.{domain}", "TXT")
        if not tls_rpt:
            recommendations.append("Enable TLS reporting (TLS-RPT) for monitoring mail transport security")
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                with socket.create_connection((mx_host, 25), timeout=5) as sock:
                    response = sock.recv(1024).decode()
                    if "STARTTLS" not in response:
                        vulnerabilities.append(f"STARTTLS not supported on {mx_host}")
                        recommendations.append(f"Enable STARTTLS on mail server {mx_host}")
            except:
                vulnerabilities.append(f"Unable to check STARTTLS on {mx_host}")
    except Exception as e:
        vulnerabilities.append(f"MTA security check failed: {str(e)}")
    return vulnerabilities, recommendations

def check_dkim(domain, selector):
    try:
        dkim_record = get_dns_record(f"{selector}._domainkey.{domain}", "TXT")
        if not dkim_record:
            return ["Missing DKIM record"], []
        vulnerabilities = []
        recommendations = []
        record = "".join(dkim_record).lower()
        mta_vulns, mta_recs = check_mta_security(domain)
        if "k=rsa;" in record:
            if "p= " in record or "p=" not in record:
                vulnerabilities.append("Invalid or missing public key in DKIM record")
            
            # Add RSA key strength check
            rsa_vulns, rsa_recs = check_rsa_key_strength(record)
            vulnerabilities.extend(rsa_vulns)
            recommendations.extend(rsa_recs)
        
        # Add MTA security check
        mta_vulns, mta_recs = check_mta_security(domain)
        vulnerabilities.extend(mta_vulns)
        recommendations.extend(mta_recs)
        return vulnerabilities, recommendations
    except Exception as e:
        return [f"DKIM check failed: {str(e)}"], []

class SecurityAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [
            DNS_SERVERS['google_primary'],
            DNS_SERVERS['cloudflare_primary']
        ]
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 10.0

    def check_mx_records(self):
        vulnerabilities = []
        try:
            mx_records = self.resolver.resolve(self.domain, 'MX')
            if not mx_records:
                vulnerabilities.append("No MX records found")
            for mx in mx_records:
                host = str(mx.exchange).rstrip('.')
                vulnerabilities.extend(self.check_mx_security(host))
        except dns.resolver.Timeout:
            console.print(f"[yellow]Warning:[/yellow] DNS timeout while checking MX records. Try again later.")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] MX record check failed: {str(e)}")
        return vulnerabilities

    def check_ssl_tls(self, host):
        vulnerabilities = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    # Check certificate expiration
                    if datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') < datetime.now():
                        vulnerabilities.append(f"SSL certificate expired for {host}")
                    # Check SSL version
                    if ssock.version() < 'TLSv1.2':
                        vulnerabilities.append(f"Weak SSL/TLS version detected: {ssock.version()}")
        except Exception as e:
            vulnerabilities.append(f"SSL/TLS check failed for {host}: {str(e)}")
        return vulnerabilities

    def check_reverse_dns(self, host):
        vulnerabilities = []
        try:
            ip_address = socket.gethostbyname(host)
            reverse_name = socket.gethostbyaddr(ip_address)[0]
            if not reverse_name.endswith(self.domain):
                vulnerabilities.append(f"Reverse DNS mismatch for {host}")
        except Exception as e:
            vulnerabilities.append(f"Reverse DNS check failed: {str(e)}")
        return vulnerabilities

    def check_email_headers(self):
        vulnerabilities = []
        headers = {
            'STARTTLS': False,
            'MTA-STS': False,
            'TLS-RPT': False
        }
        
        try:
            mta_sts = self.resolver.resolve(f"_mta-sts.{self.domain}", "TXT")
            headers['MTA-STS'] = True
        except dns.resolver.NXDOMAIN:
            vulnerabilities.append("MTA-STS policy not configured (Recommended for enhanced security)")
        except dns.resolver.Timeout:
            console.print("[yellow]Warning:[/yellow] DNS timeout while checking MTA-STS. Try again later.")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Unable to check MTA-STS: {str(e)}")
        
        try:
            tls_rpt = self.resolver.resolve(f"_smtp._tls.{self.domain}", "TXT")
            headers['TLS-RPT'] = True
        except dns.resolver.NXDOMAIN:
            vulnerabilities.append("TLS-RPT not configured")
        except dns.resolver.Timeout:
            console.print("[yellow]Warning:[/yellow] DNS timeout while checking TLS-RPT. Try again later.")
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Unable to check TLS-RPT: {str(e)}")
        
        return vulnerabilities, headers