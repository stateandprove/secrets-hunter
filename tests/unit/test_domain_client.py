import ssl
import urllib.error
import unittest

from email.message import Message
from unittest.mock import MagicMock, patch

from secrets_hunter.scan_modes.domain.client import DomainClient


class TestDomainClient(unittest.TestCase):
    def test_normalizes_plain_domain_to_https_base_url(self):
        client = DomainClient("fvlcn.dev")

        self.assertEqual(client.base_url, "https://fvlcn.dev/")

    def test_normalizes_url_path_to_trailing_slash_base_url(self):
        client = DomainClient("https://fvlcn.dev/app")

        self.assertEqual(client.base_url, "https://fvlcn.dev/app/")

    def test_normalizes_url_by_dropping_query_and_fragment(self):
        client = DomainClient("https://fvlcn.dev/app?token=abc#section")

        self.assertEqual(client.base_url, "https://fvlcn.dev/app/")

    def test_rejects_non_http_domain_scheme(self):
        with self.assertRaises(ValueError):
            DomainClient("file:///etc/passwd")

    def test_rejects_malformed_domain_without_host(self):
        with self.assertRaises(ValueError):
            DomainClient("https:///missing-host")

    def test_read_url_returns_body_for_2xx_response(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN"
        response.__enter__.return_value = response

        with patch("urllib.request.urlopen", return_value=response) as urlopen:
            body, success = DomainClient("fvlcn.dev").read_url("https://fvlcn.dev/.env")

        self.assertEqual(body, b"GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN")
        self.assertTrue(success)
        urlopen.assert_called_once()

    def test_read_url_skips_non_2xx_response_as_successful_fetch(self):
        response = MagicMock()
        response.status = 302
        response.__enter__.return_value = response

        with patch("urllib.request.urlopen", return_value=response):
            body, success = DomainClient("fvlcn.dev").read_url("https://fvlcn.dev/.env")

        self.assertIsNone(body)
        self.assertTrue(success)

    def test_read_url_treats_404_as_successful_miss(self):
        error = urllib.error.HTTPError(
            "https://fvlcn.dev/.env",
            404,
            "Not Found",
            hdrs=Message(),
            fp=None
        )

        with patch("urllib.request.urlopen", side_effect=error):
            body, success = DomainClient("fvlcn.dev").read_url("https://fvlcn.dev/.env")

        self.assertIsNone(body)
        self.assertTrue(success)

    def test_read_url_treats_url_error_as_failed_fetch(self):
        error = urllib.error.URLError("connection refused")

        with patch("urllib.request.urlopen", side_effect=error):
            body, success = DomainClient("fvlcn.dev").read_url("https://fvlcn.dev/.env")

        self.assertIsNone(body)
        self.assertFalse(success)

    def test_read_url_rejects_non_http_url_without_opening_it(self):
        with patch("urllib.request.urlopen") as urlopen:
            body, success = DomainClient("fvlcn.dev").read_url("file:///etc/passwd")

        self.assertIsNone(body)
        self.assertFalse(success)
        urlopen.assert_not_called()

    def test_read_url_rejects_url_without_host_without_opening_it(self):
        with patch("urllib.request.urlopen") as urlopen:
            body, success = DomainClient("fvlcn.dev").read_url("https:///missing-host")

        self.assertIsNone(body)
        self.assertFalse(success)
        urlopen.assert_not_called()

    def test_tls_verification_uses_urlopen_default_by_default(self):
        client = DomainClient("fvlcn.dev")

        self.assertIsNone(client.ssl_context)

    def test_skip_tls_verify_creates_ssl_context(self):
        client = DomainClient("fvlcn.dev", skip_tls_verify=True)

        self.assertIsNotNone(client.ssl_context)
        self.assertFalse(client.ssl_context.check_hostname)
        self.assertEqual(client.ssl_context.verify_mode, ssl.CERT_NONE)
