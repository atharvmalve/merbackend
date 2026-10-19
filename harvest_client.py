"""
Dedicated, asynchronous HarvestAPI client for Merit.
Direct integration with https://api.harvestapi.io for LinkedIn data extraction.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("merit.harvest_client")


class HarvestAPIError(Exception):
    """Base exception for HarvestAPI operations."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class HarvestAPIAuthError(HarvestAPIError):
    """Authentication or authorization failure (HTTP 401/403)."""
    pass


class HarvestAPIRateLimitError(HarvestAPIError):
    """Rate limit exceeded or quota exhausted (HTTP 429)."""
    def __init__(self, message: str, retry_after: Optional[float] = None, response_body: Optional[str] = None):
        super().__init__(message, status_code=429, response_body=response_body)
        self.retry_after = retry_after


class HarvestAPINotFoundError(HarvestAPIError):
    """Requested resource (profile, company, post) was not found (HTTP 404)."""
    pass


class HarvestAPIClient:
    """
    Asynchronous client for HarvestAPI.
    Uses X-API-Key header and supports bounded retries for transient errors.
    """

    def __init__(
        self,
        api_key: Any = "",
        base_url: str = "https://api.harvestapi.io",
        timeout: float = 30.0,
        max_retries: int = 3,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._external_client = client
        self._internal_client: Optional[httpx.AsyncClient] = None

    @property
    def api_key(self) -> str:
        if callable(self._api_key):
            return str(self._api_key() or "").strip()
        return str(self._api_key or "").strip()

    @api_key.setter
    def api_key(self, value: Any):
        self._api_key = value

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._external_client is not None:
            return self._external_client
        if self._internal_client is None or self._internal_client.is_closed:
            self._internal_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                headers={
                    "X-API-Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "Merit-Backend/1.0",
                },
            )
        return self._internal_client

    async def close(self):
        if self._internal_client and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes an HTTP request with bounded exponential backoff for transient errors.
        Never logs or exposes the API key.
        """
        if not self.is_configured():
            raise HarvestAPIAuthError("HarvestAPI is not configured. HARVESTAPI_API_KEY is missing.")

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}

        client = await self._get_client()

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    params=clean_params,
                    json=json_data,
                    headers={"X-API-Key": self.api_key},
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            # Provider-level error check inside JSON payload
                            if data.get("error") and not data.get("element") and not data.get("elements"):
                                err_msg = str(data.get("error"))
                                if "not found" in err_msg.lower():
                                    raise HarvestAPINotFoundError(f"Resource not found: {err_msg}", status_code=404)
                                raise HarvestAPIError(f"HarvestAPI provider error: {err_msg}", status_code=200)
                        return data
                    except ValueError as json_err:
                        raise HarvestAPIError(f"Invalid JSON returned by HarvestAPI: {json_err}", status_code=200)

                if response.status_code == 404:
                    raise HarvestAPINotFoundError(
                        f"HarvestAPI resource not found ({endpoint}).",
                        status_code=404,
                        response_body=response.text,
                    )

                if response.status_code in (401, 403):
                    raise HarvestAPIAuthError(
                        f"HarvestAPI authentication failed ({response.status_code}). Verify HARVESTAPI_API_KEY.",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

                if response.status_code == 429:
                    retry_after_header = response.headers.get("Retry-After")
                    retry_after = float(retry_after_header) if retry_after_header and retry_after_header.isdigit() else (2.0 ** attempt)
                    if attempt < self.max_retries:
                        logger.warning("HarvestAPI rate limited (429). Retrying in %.1f seconds...", retry_after)
                        await asyncio.sleep(retry_after)
                        continue
                    raise HarvestAPIRateLimitError(
                        "HarvestAPI rate limit reached or credits exhausted.",
                        retry_after=retry_after,
                        response_body=response.text,
                    )

                # Retryable 5xx server errors
                if response.status_code >= 500:
                    if attempt < self.max_retries:
                        backoff = 1.5 ** attempt
                        logger.warning("HarvestAPI 5xx error (%d). Retrying in %.1f seconds...", response.status_code, backoff)
                        await asyncio.sleep(backoff)
                        continue
                    raise HarvestAPIError(
                        f"HarvestAPI server error ({response.status_code}).",
                        status_code=response.status_code,
                        response_body=response.text,
                    )

                # 4xx client errors (non-retryable)
                raise HarvestAPIError(
                    f"HarvestAPI request failed with status {response.status_code}.",
                    status_code=response.status_code,
                    response_body=response.text,
                )

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.NetworkError) as net_err:
                if attempt < self.max_retries:
                    backoff = 1.5 ** attempt
                    logger.warning("HarvestAPI network error (%s). Retrying in %.1f seconds...", type(net_err).__name__, backoff)
                    await asyncio.sleep(backoff)
                    continue
                raise HarvestAPIError(f"HarvestAPI network failure after {self.max_retries} attempts: {type(net_err).__name__}")

        raise HarvestAPIError("HarvestAPI request attempts exhausted.")

    # -------------------------------------------------------------------------
    # Account / User verification
    # -------------------------------------------------------------------------
    async def get_my_api_user(self) -> Dict[str, Any]:
        """Fetches the current API user account status and balance."""
        return await self._request("GET", "/users/my-api-user")

    # -------------------------------------------------------------------------
    # Profile operations
    # -------------------------------------------------------------------------
    async def get_profile(self, profile_url_or_id: str, main: bool = True) -> Dict[str, Any]:
        """
        Retrieves a LinkedIn profile by URL or identifier.
        Passes main='true' to fetch core profile without unnecessary sections.
        """
        params = {
            "query": profile_url_or_id,
            "main": "true" if main else "false",
        }
        res = await self._request("GET", "/linkedin/profile", params=params)
        return res.get("element") or res

    async def get_profile_posts(
        self,
        profile_url_or_id: str,
        page: int = 1,
        posted_limit: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves posts by a LinkedIn profile author.
        Returns dictionary with 'elements' list and 'pagination' info.
        """
        params = {
            "profile": profile_url_or_id,
            "page": page,
        }
        if posted_limit:
            params["postedLimit"] = posted_limit
        return await self._request("GET", "/linkedin/profile-posts", params=params)

    # -------------------------------------------------------------------------
    # Company operations
    # -------------------------------------------------------------------------
    async def get_company(self, company_url_or_id: str) -> Dict[str, Any]:
        """
        Retrieves LinkedIn company metadata by URL or identifier/slug.
        """
        params = {"query": company_url_or_id}
        res = await self._request("GET", "/linkedin/company", params=params)
        return res.get("element") or res

    async def get_company_posts(
        self,
        company_url_or_id: str,
        page: int = 1,
        posted_limit: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves posts published by a LinkedIn company page.
        Returns dictionary with 'elements' list and 'pagination' info.
        """
        params = {
            "company": company_url_or_id,
            "page": page,
        }
        if posted_limit:
            params["postedLimit"] = posted_limit
        return await self._request("GET", "/linkedin/company-posts", params=params)

    # -------------------------------------------------------------------------
    # Post engagement operations
    # -------------------------------------------------------------------------
    async def get_post_comments(self, post_url_or_urn: str, page: int = 1) -> Dict[str, Any]:
        """
        Retrieves comments on a post.
        Returns dictionary with 'elements' list containing comment commentary and actor details.
        """
        params = {
            "post": post_url_or_urn,
            "page": page,
            "sortBy": "date",
        }
        return await self._request("GET", "/linkedin/post-comments", params=params)

    async def get_post_reactions(self, post_url_or_urn: str, page: int = 1) -> Dict[str, Any]:
        """
        Retrieves reactions on a post.
        Returns dictionary with 'elements' list containing reactionType and actor details.
        """
        params = {
            "post": post_url_or_urn,
            "page": page,
        }
        return await self._request("GET", "/linkedin/post-reactions", params=params)
