import unittest
from unittest.mock import patch, MagicMock
from dmarc_audit.analyzer import (
    analyze_dmarc,
    analyze_spf,
    check_dkim,
    SecurityAnalyzer,
    get_dns_record
)

class TestDMARCAnalyzer(unittest.TestCase):
    def test_missing_dmarc(self):
        vulns, recs = analyze_dmarc([])
        self.assertIn("Missing DMARC record", vulns)

    def test_weak_policy(self):
        record = ["v=DMARC1; p=none;"]
        vulns, recs = analyze_dmarc(record)
        self.assertIn("Policy set to monitoring only (p=none)", vulns)

    def test_partial_enforcement(self):
        record = ["v=DMARC1; p=reject; pct=50;"]
        vulns, recs = analyze_dmarc(record)
        self.assertIn("Partial policy enforcement (pct=50)", vulns)

class TestSPFAnalyzer(unittest.TestCase):
    def test_missing_spf(self):
        vulns, recs = analyze_spf([])
        self.assertIn("Missing SPF record", vulns)

    def test_permissive_policy(self):
        record = ["v=spf1 +all"]
        vulns, recs = analyze_spf(record)
        self.assertIn("Overly permissive SPF policy (+all)", vulns)

    @patch('dmarc_audit.analyzer.get_dns_record')
    def test_dkim_check(self, mock_dns):
        mock_dns.return_value = ["v=DKIM1; k=rsa; p=MIGfMA0..."]
        vulns, recs = check_dkim("example.com", "selector1")
        self.assertEqual(len(vulns), 0)

class TestSecurityAnalyzer(unittest.TestCase):
    @patch('socket.create_connection')
    def test_ssl_check(self, mock_socket):
        mock_socket.return_value = MagicMock()
        analyzer = SecurityAnalyzer("example.com")
        vulns = analyzer.check_ssl_tls("mail.example.com")
        self.assertEqual(len(vulns), 0)

    @patch('dns.resolver.Resolver.resolve')
    def test_mx_records(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(exchange="mail.example.com")]
        analyzer = SecurityAnalyzer("example.com")
        vulns = analyzer.check_mx_records()
        self.assertIsInstance(vulns, list)

if __name__ == '__main__':
    unittest.main() 