"""
HTTP client utilities for Pyrate vulnerability scanner.
"""

import asyncio
import logging
import time
from typing import Dict, Optional, Any, Union
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.client_exceptions import ClientError

from ..core.config import Config

logger = logging.getLogger(__name__)


class HTTPClient:
    """Asynchronous HTTP client for vulnerability scanning."""
    
    def __init__(self, config: Config):
        """
        Initialize HTTP client.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(config.scanner.max_concurrent_requests)
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def start(self) -> None:
        """Start the HTTP client session."""
        if self._session and not self._session.closed:
            return
            
        timeout = aiohttp.ClientTimeout(total=self.config.scanner.request_timeout)
        
        connector = aiohttp.TCPConnector(
            limit=self.config.scanner.max_concurrent_requests * 2,
            verify_ssl=self.config.scanner.verify_ssl,
        )
        
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': self.config.scanner.user_agent,
            },
        )
        
        logger.debug("HTTP client session started")
    
    async def close(self) -> None:
        """Close the HTTP client session."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("HTTP client session closed")
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        allow_redirects: Optional[bool] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Perform GET request.
        
        Args:
            url: Target URL
            headers: Additional headers
            params: Query parameters
            allow_redirects: Whether to follow redirects
            **kwargs: Additional arguments for aiohttp
            
        Returns:
            HTTP response
        """
        return await self._request(
            'GET', url, headers=headers, params=params,
            allow_redirects=allow_redirects, **kwargs
        )
    
    async def post(
        self,
        url: str,
        data: Union[str, bytes, Dict[str, Any], None] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: Optional[bool] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Perform POST request.
        
        Args:
            url: Target URL
            data: Request body data
            json: JSON data to send
            headers: Additional headers
            allow_redirects: Whether to follow redirects
            **kwargs: Additional arguments for aiohttp
            
        Returns:
            HTTP response
        """
        return await self._request(
            'POST', url, data=data, json=json, headers=headers,
            allow_redirects=allow_redirects, **kwargs
        )
    
    async def put(
        self,
        url: str,
        data: Union[str, bytes, Dict[str, Any], None] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Perform PUT request."""
        return await self._request('PUT', url, data=data, json=json, headers=headers, **kwargs)
    
    async def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Perform DELETE request."""
        return await self._request('DELETE', url, headers=headers, **kwargs)
    
    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Perform HEAD request."""
        return await self._request('HEAD', url, headers=headers, **kwargs)
    
    async def options(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Perform OPTIONS request."""
        return await self._request('OPTIONS', url, headers=headers, **kwargs)
    
    async def _request(
        self,
        method: str,
        url: str,
        allow_redirects: Optional[bool] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Perform HTTP request with retry logic and rate limiting.
        
        Args:
            method: HTTP method
            url: Target URL
            allow_redirects: Whether to follow redirects
            **kwargs: Additional arguments for aiohttp
            
        Returns:
            HTTP response
            
        Raises:
            ClientError: If request fails after all retries
        """
        if not self._session:
            await self.start()
        
        # Set default redirect behavior
        if allow_redirects is None:
            allow_redirects = self.config.scanner.follow_redirects
        
        async with self._semaphore:
            for attempt in range(self.config.scanner.retry_attempts + 1):
                try:
                    start_time = time.time()
                    
                    async with self._session.request(
                        method, url, allow_redirects=allow_redirects, **kwargs
                    ) as response:
                        # Read response content to ensure it's fully received
                        await response.read()
                        
                        response_time = time.time() - start_time
                        
                        logger.debug(
                            f"{method} {url} -> {response.status} ({response_time:.2f}s)"
                        )
                        
                        # Add delay between requests
                        if self.config.scanner.delay_between_requests > 0:
                            await asyncio.sleep(self.config.scanner.delay_between_requests)
                        
                        return response
                        
                except ClientError as e:
                    if attempt < self.config.scanner.retry_attempts:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.debug(f"Request failed (attempt {attempt + 1}), retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Request failed after {attempt + 1} attempts: {e}")
                        raise
                except Exception as e:
                    logger.error(f"Unexpected error during request: {e}")
                    raise
    
    def build_url(self, base_url: str, path: str) -> str:
        """
        Build complete URL from base URL and path.
        
        Args:
            base_url: Base URL
            path: Path to append
            
        Returns:
            Complete URL
        """
        return urljoin(base_url, path)
    
    def is_valid_url(self, url: str) -> bool:
        """
        Check if URL is valid.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def get_base_url(self, url: str) -> str:
        """
        Extract base URL from a complete URL.
        
        Args:
            url: Complete URL
            
        Returns:
            Base URL (scheme + netloc)
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def test_connection(self, url: str) -> bool:
        """
        Test if connection to URL is possible.
        
        Args:
            url: URL to test
            
        Returns:
            True if connection is successful
        """
        try:
            async with self.head(url) as response:
                return response.status < 500
        except Exception:
            try:
                # Try GET if HEAD fails
                async with self.get(url) as response:
                    return response.status < 500
            except Exception:
                return False