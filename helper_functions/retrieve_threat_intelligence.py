"""Thin wrappers for several threat intelligence HTTP APIs.

This module provides small clients for VirusTotal, AbuseIPDB, ipinfo.io, AlienVault OTX, urlscan.io that reuse :class:`helper_functions.http_handler.BaseClient` for session and retry management. Environment variables are used to provide API keys when available.

Supported environment variables:
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `IPINFO_API_KEY`
- `ALIENVAULT_API_KEY`
- `URLSCAN_API_KEY`
- `SHODAN_API_KEY`

The clients expose simple `fetch_*` methods returning parsed JSON responses from the respective services.
"""

import os
import time
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")


class VirusTotalClient(BaseClient):
    """Client for querying VirusTotal for IPs, files and domains.

    Args:
        session (requests.Session | None): Optional session passed to class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `VIRUSTOTAL_API_KEY` environment variable.
        headers (dict): Default headers to send with requests.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key}

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP information from VirusTotal.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response from the VirusTotal API.
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()

    def fetch_file(self, file_hash: str) -> dict:
        """Fetch file hash information from VirusTotal.

        Args:
            file_hash (str): File hash to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()

    def fetch_domain(self, domain: str) -> dict:
        """Fetch domain information from VirusTotal.

        Args:
            domain (str): Domain name to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = self.request("GET", url, headers=self.headers, timeout=10)
        return response.json()


class AbuseIPDBClient(BaseClient):
    """Client for querying AbuseIPDB for IP reputation data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.headers = {"Key": self.api_key, "Accept": "application/json"}

    def fetch_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Fetch an IP report from AbuseIPDB.

        Args:
            ip (str): IP address to query.
            max_age_days (int): Maximum age in days for returned reports.

        Returns:
            dict: Parsed JSON response.
        """
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
        response = self.request(
            "GET", url, headers=self.headers, params=params, timeout=10
        )
        return response.json()


class IPInfoClient(BaseClient):
    """Client for querying ipinfo.io for IP metadata.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `IPINFO_API_KEY` environment variable; if not provided ipinfo allows unauthenticated requests with stricter rate limits.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("IPINFO_API_KEY")

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP metadata from ipinfo.io.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://ipinfo.io/{ip}/json"
        params = (
            {"token": self.api_key} if self.api_key else None
        )  # ipinfo allows unauthenticated requests with limits
        response = self.request("GET", url, params=params, timeout=10)
        return response.json()


class AlienVaultClient(BaseClient):
    """Client for querying AlienVault OTX for threat intelligence data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `ALIENVAULT_API_KEY` environment variable.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("ALIENVAULT_API_KEY")

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP information from AlienVault OTX.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = self.request("GET", url, headers=headers, timeout=10)
        return response.json()

    def fetch_domain(self, domain: str) -> dict:
        """Fetch domain information from AlienVault OTX.

        Args:
            domain (str): Domain name to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        response = self.request("GET", url, headers=headers, timeout=10)
        return response.json()


class URLScanClient(BaseClient):
    """Client for querying URLScan.io for URL threat intelligence data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("URLSCAN_API_KEY")

    def submit_url(self, url: str) -> str:
        """Submit a URL to URLScan.io for scanning.

        Args:
            url (str): URL to submit for scanning.

        Returns:
            str: URL scan UUID
        """
        api_url = "https://urlscan.io/api/v1/scan/"
        headers = {"api-key": self.api_key, "Content-Type": "application/json"}
        payload = {"url": url}
        # Use requests library instead of custom handler for error handling later
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)

        # Detect submission errors indicated by non-200 status code
        if response.status_code != 200:
            # Extract status, description from response
            error_info = response.json()
            error_message = error_info.get("message", "Unknown error")
            error_status = error_info.get("status", "No status code provided")
            logger.debug(
                f"URLScan.io URL submission failed. Status: {error_status}, Message: {error_message}"
            )
            raise ValueError(
                f"Failed to submit URL for scanning; Status: {error_status}, Message: {error_message}"
            )
        else:
            # Extract and return UUID from successful response
            return response.json().get("uuid")

    def fetch_url_scan_result(self, url_scan_uuid: str) -> dict:
        """Fetch URL scan results from URLScan.io.

        Args:
            url_scan_uuid (str): UUID of the URL scan to fetch.

        Returns:
            dict: Parsed JSON response.
        """
        api_url = f"https://urlscan.io/api/v1/result/{url_scan_uuid}/"
        headers = {"api-key": self.api_key}

        # Custom handling to allow for scan processing status
        max_retries, retry_count = 24, 0

        while retry_count < max_retries:
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.debug(
                    f"URL scan result for UUID {url_scan_uuid} retrieved successfully."
                )
                return response.json()
            else:
                logger.debug(
                    f"URL scan result for UUID {url_scan_uuid} not ready yet. Polling attempt: {retry_count + 1}/{max_retries}."
                )

            time.sleep(5)
            retry_count += 1

        return response.json()

    def fetch_url_scan_screenshot(self, url_scan_uuid: str, save_location: str) -> None:
        """Fetch URL scan screenshot from URLScan.io.

        Args:
            url_scan_uuid (str): UUID of the URL scan to fetch.
            save_location (str): Location to save the screenshot image.

        Returns:
            bool: True if screenshot was successfully retrieved and saved.
        """
        api_url = f"https://urlscan.io/screenshots/{url_scan_uuid}.png"
        headers = {"api-key": self.api_key, "Content-Type": "image/png"}

        # Custom handling to allow for scan processing status
        max_retries, retry_count = 24, 0

        while retry_count < max_retries:
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                if response.headers.get("Content-Type") != "image/png":
                    logger.error(
                        f"Unexpected content type for screenshot: {response.headers.get('Content-Type')}"
                    )
                    raise ValueError(
                        f"Unexpected content type for screenshot: {response.headers.get('Content-Type')}"
                    )
                else:
                    # Save screenshot to specified location
                    with open(save_location, "wb") as file:
                        file.write(response.content)
                    logger.debug(
                        f"URL scan screenshot for UUID {url_scan_uuid} saved to {save_location}."
                    )
                    return
            else:
                logger.debug(
                    f"URL scan screenshot for UUID {url_scan_uuid} not ready yet. Polling attempt: {retry_count + 1}/{max_retries}."
                )

            time.sleep(5)
            retry_count += 1

        # If max retries reached without success, raise an error
        logger.error(
            f"Failed to retrieve screenshot for UUID {url_scan_uuid} after {max_retries} attempts."
        )
        raise ValueError(
            f"Failed to retrieve screenshot for UUID {url_scan_uuid} after {max_retries} attempts."
        )


class ShodanClient(BaseClient):
    """Client for querying Shodan for IP threat intelligence data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.

    Attributes:
        api_key (str | None): Value of the `SHODAN_API_KEY` environment variable.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("SHODAN_API_KEY")

    def fetch_ip(self, ip: str) -> dict:
        """Fetch IP information from Shodan.

        Args:
            ip (str): IP address to query.

        Returns:
            dict: Parsed JSON response.
        """
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": self.api_key}
        response = self.request("GET", url, params=params, timeout=10)
        return response.json()


# Import environment variables from .env file
load_dotenv()
