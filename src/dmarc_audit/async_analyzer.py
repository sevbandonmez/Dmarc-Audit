import asyncio
import dns.asyncresolver
from .config import DNS_TIMEOUT, DNS_SERVERS
from .logger import logger

async def async_dns_lookup(domain, record_type):
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.nameservers = [DNS_SERVERS[server] for server in DNS_SERVERS]
    
    try:
        answers = await resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.error(f"Async DNS lookup error for {domain}: {str(e)}")
        return []

class AsyncSecurityAnalyzer:
    def __init__(self, domain):
        self.domain = domain

    async def check_all(self):
        tasks = [
            self.check_spf(),
            self.check_dmarc(),
            self.check_dkim(),
            self.check_mx_records()
        ]
        return await asyncio.gather(*tasks) 