"""
DMARC Audit Tool
---------------
A comprehensive DMARC, SPF and DKIM security analyzer

Created by: Sevban Dönmez
Version: 1.0.0
"""

from .main import main
from .analyzer import (
    analyze_dmarc,
    analyze_spf,
    check_dkim,
    SecurityAnalyzer
)
from .utils import (
    print_banner,
    create_report,
    print_results_table,
    print_status
)

__version__ = "1.0.0"
__author__ = "Sevban Dönmez" 