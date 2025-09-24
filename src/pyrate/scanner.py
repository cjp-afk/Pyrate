"""Core vulnerability scanning functionality."""

import httpx
from bs4 import BeautifulSoup
from pydantic import BaseModel, HttpUrl


class ScanResult(BaseModel):
    """Represents the result of a vulnerability scan."""

    url: HttpUrl
    status_code: int
    vulnerabilities: list[str] = []
    warnings: list[str] = []
    info: dict[str, str] = {}


class WebScanner:
    """Main vulnerability scanner class."""

    def __init__(self, timeout: int = 30) -> None:
        """Initialize the scanner with configuration."""
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)

    def scan_url(self, url: str) -> ScanResult:
        """Scan a single URL for vulnerabilities."""
        try:
            response = self.client.get(url)
            result = ScanResult(url=url, status_code=response.status_code)

            # Basic checks
            self._check_security_headers(response, result)
            self._check_content(response, result)

            return result

        except (httpx.RequestError, Exception) as exc:
            return ScanResult(
                url=url, status_code=0, vulnerabilities=[f"Request failed: {str(exc)}"]
            )

    def _check_security_headers(
        self, response: httpx.Response, result: ScanResult
    ) -> None:
        """Check for missing security headers."""
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]

        for header in security_headers:
            if header not in response.headers:
                result.warnings.append(f"Missing security header: {header}")

    def _check_content(self, response: httpx.Response, result: ScanResult) -> None:
        """Check response content for potential issues."""
        if "text/html" in response.headers.get("content-type", ""):
            soup = BeautifulSoup(response.text, "html.parser")

            # Check for forms without CSRF protection
            forms = soup.find_all("form")
            for form in forms:
                csrf_token = form.find("input", {"name": "csrf_token"}) or form.find(
                    "input", {"name": "_token"}
                )
                if not csrf_token:
                    result.warnings.append(
                        "Form found without apparent CSRF protection"
                    )

            # Store basic info
            title = soup.find("title")
            if title:
                result.info["title"] = title.get_text().strip()

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self) -> "WebScanner":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()
