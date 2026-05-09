import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request

from secrets_hunter._version import __version__

logger = logging.getLogger(__name__)

ALLOWED_URL_SCHEMES = {"http", "https"}


class DomainClient:
    def __init__(self, domain: str, timeout: float = 5.0, skip_tls_verify: bool = False):
        self.base_url = self._normalize_domain(domain)
        self.timeout = timeout
        self.ssl_context = self._build_ssl_context(skip_tls_verify)

    def read_url(self, url: str) -> tuple[bytes | None, bool]:
        if not self._is_http_url(url):
            logger.debug("Skipping non-HTTP(S) URL: %s", url)
            return None, False

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"fvlcn-secrets-hunter v{__version__}"
            },
            method="GET"
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                status = response.status

                if status < 200 or status >= 300:
                    return None, True

                return response.read(), True
        except urllib.error.HTTPError as e:
            if e.code != 404:
                logger.debug("Skipping %s: HTTP %s", url, e.code)
            return None, True
        except urllib.error.URLError as e:
            logger.debug("Failed to fetch %s: %s", url, e)
            return None, False

    @staticmethod
    def display_path(url: str) -> str:
        return url

    @staticmethod
    def _build_ssl_context(skip_tls_verify: bool) -> ssl.SSLContext | None:
        if skip_tls_verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        return None

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        if "://" not in domain:
            domain = f"https://{domain}"

        parsed = urllib.parse.urlparse(domain)

        if parsed.scheme not in ALLOWED_URL_SCHEMES or not parsed.netloc:
            raise ValueError("domain must be an HTTP(S) URL or domain")

        path = parsed.path.rstrip("/")
        base_path = f"{path}/" if path else "/"

        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            base_path,
            "",
            "",
            ""
        ))

    @staticmethod
    def _is_http_url(url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ALLOWED_URL_SCHEMES and bool(parsed.netloc)
