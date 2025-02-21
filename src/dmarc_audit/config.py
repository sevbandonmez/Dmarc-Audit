"""Configuration settings for DMARC Audit Tool"""

# DNS Settings
DNS_SERVERS = {
    'google_primary': '8.8.8.8',
    'google_secondary': '8.8.4.4',
    'cloudflare_primary': '1.1.1.1',
    'cloudflare_secondary': '1.0.0.1'
}

DNS_TIMEOUT = 30
DNS_LIFETIME = 30

# Report Settings
REPORT_FORMATS = ['text', 'json', 'csv']
DEFAULT_REPORT_FORMAT = 'text'
DEFAULT_DKIM_SELECTOR = 'selector1'

# Security Settings
MINIMUM_TLS_VERSION = 'TLSv1.2'
MAX_FORENSIC_URIS = 2
MAX_SPF_INCLUDES = 10

# Output Settings
SEVERITY_COLORS = {
    'ERROR': 'red',
    'WARNING': 'yellow',
    'INFO': 'blue'
}

# Banner Settings
BANNER_SETTINGS = {
    'font': 'slant',
    'border_style': 'cyan'
}

# File Paths
REPORT_OUTPUT_DIR = 'reports'
LOG_FILE = 'dmarc_audit.log'

# Logging Settings
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Email Settings
EMAIL_PORTS = {
    'smtp': 25,
    'submission': 587,
    'submissions': 465
}

# Feature Flags
ENABLE_DETAILED_REPORTING = True
ENABLE_SSL_VERIFICATION = True
ENABLE_MTA_STS_CHECK = True 