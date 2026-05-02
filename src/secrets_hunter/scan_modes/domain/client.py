import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request

from secrets_hunter._version import __version__

logger = logging.getLogger(__name__)


class DomainClient:
    def __init__(self, domain: str, timeout: float = 5.0, skip_tls_verify: bool = False):
        self.base_url = self._normalize_domain(domain)
        self.timeout = timeout
        self.ssl_context = ssl._create_unverified_context() if skip_tls_verify else None

    def read_url(self, url: str) -> tuple[bytes | None, bool]:
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
    def _normalize_domain(domain: str) -> str:
        if "://" not in domain:
            domain = f"https://{domain}"

        parsed = urllib.parse.urlparse(domain)
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
