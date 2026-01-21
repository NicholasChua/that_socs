import os
import requests
import time
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


class URLScanClient(BaseClient):
    """Client for querying URLScan.io for URL threat intelligence data.

    Args:
        session (requests.Session | None): Optional session passed to :class:`BaseClient`.
    """

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session=session)
        self.api_key = os.getenv("URLSCAN_API_KEY")

    def fetch_url(self, url: str) -> str:
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

    def fetch_urlscan_result(self, url_scan_uuid: str) -> dict:
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

    def fetch_urlscan_screenshot(self, url_scan_uuid: str, save_location: str) -> None:
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

    def normalize_url_data(self, raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
        """Normalize URLScan.io URL data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from URLScan.io for a URL scan.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        # Extract task information
        task = raw_data.get("task", {})
        ioc = task.get("url", "")

        # Extract page information
        page = raw_data.get("page", {})

        # Extract verdicts
        verdicts = raw_data.get("verdicts", {})
        overall_verdict = verdicts.get("overall", {})
        urlscan_verdict = verdicts.get("urlscan", {})
        engines_verdict = verdicts.get("engines", {})
        community_verdict = verdicts.get("community", {})

        # Determine if malicious
        malicious = overall_verdict.get("malicious", False)

        # Get confidence score from overall verdict
        # URLScan scores range from -100 to 100, normalize to 0-100
        overall_score = overall_verdict.get("score", 0)
        if overall_score < 0:
            confidence_score = 0
        else:
            confidence_score = min(overall_score, 100)

        # Build detection stats from engines verdict
        detection_stats = None
        if engines_verdict.get("hasVerdicts"):
            detection_stats = {
                "malicious": engines_verdict.get("maliciousTotal", 0),
                "suspicious": 0,  # URLScan doesn't have this category
                "harmless": engines_verdict.get("benignTotal", 0),
                "undetected": 0,
                "total": engines_verdict.get("enginesTotal", 0),
            }

        # Extract geo info from page
        geo_info = {
            "country": page.get("country"),
            "city": page.get("city"),
        }

        # Extract network info
        network_info = {
            "asn": page.get("asn"),
            "organization": page.get("asnname"),
            "domain": page.get("domain"),
        }

        # Extract domain info
        domain_info = None
        apex_domain = page.get("apexDomain")
        if apex_domain:
            domain_info = {
                "apex_domain": apex_domain,
                "domain_age_days": page.get("domainAgeDays"),
                "apex_domain_age_days": page.get("apexDomainAgeDays"),
                "tls_issuer": page.get("tlsIssuer"),
                "tls_valid_days": page.get("tlsValidDays"),
                "tls_age_days": page.get("tlsAgeDays"),
                "tls_valid_from": page.get("tlsValidFrom"),
            }

        # Extract timestamps
        timestamps = {
            "scan_time": task.get("time"),
        }

        # Combine tags from overall verdict and task
        tags = []
        tags.extend(overall_verdict.get("tags", []))
        tags.extend(task.get("tags", []))
        tags.extend(engines_verdict.get("tags", []))
        tags = list(set(tags))  # Deduplicate

        # Extract categories from verdicts
        categories = []
        categories.extend(overall_verdict.get("categories", []))
        categories.extend(urlscan_verdict.get("categories", []))
        categories.extend(engines_verdict.get("categories", []))
        categories = list(set(categories))  # Deduplicate

        # Extract brands
        brands = []
        brands.extend(overall_verdict.get("brands", []))
        brands.extend(urlscan_verdict.get("brands", []))
        brands = list(set(brands))  # Deduplicate

        # Extract lists
        lists = raw_data.get("lists", {})

        # Extract stats
        stats = raw_data.get("stats", {})

        # Build additional info
        additional_info = {
            "scan_uuid": task.get("uuid"),
            "report_url": task.get("reportURL"),
            "screenshot_url": task.get("screenshotURL"),
            "dom_url": task.get("domURL"),
            "visibility": task.get("visibility"),
            "submitter_country": raw_data.get("submitter", {}).get("country"),
            "scanner_country": raw_data.get("scanner", {}).get("country"),
            "page_ip": page.get("ip"),
            "page_status": page.get("status"),
            "page_title": page.get("title"),
            "page_server": page.get("server"),
            "page_mime_type": page.get("mimeType"),
            "page_language": page.get("language"),
            "umbrella_rank": page.get("umbrellaRank"),
            "redirected": page.get("redirected"),
            "brands": brands,
            "associated_ips": lists.get("ips", []),
            "associated_domains": lists.get("domains", []),
            "associated_urls": lists.get("urls", []),
            "link_domains": lists.get("linkDomains", []),
            "certificates": lists.get("certificates", []),
            "hashes": lists.get("hashes", []),
            "malicious_count": stats.get("malicious", 0),
            "total_links": stats.get("totalLinks", 0),
            "ad_blocked": stats.get("adBlocked", 0),
            "secure_percentage": stats.get("securePercentage", 0),
            "community_votes": {
                "total": community_verdict.get("votesTotal", 0),
                "malicious": community_verdict.get("votesMalicious", 0),
                "benign": community_verdict.get("votesBenign", 0),
            },
            "engines_verdicts": {
                "malicious": engines_verdict.get("maliciousVerdicts", []),
                "benign": engines_verdict.get("benignVerdicts", []),
            },
        }

        # Logging for debugging
        logger.debug(
            "Normalized URLScan data for IOC %s: malicious=%s, score=%s, engines_total=%s",
            ioc,
            malicious,
            overall_score,
            engines_verdict.get("enginesTotal", 0),
        )

        return ThreatIntelligenceNormalizedSchema(
            source="URLScan.io",
            ioc_type="url",
            ioc=ioc,
            malicious=malicious,
            confidence_score=confidence_score,
            detection_stats=detection_stats,
            geo_info=geo_info,
            network_info=network_info,
            domain_info=domain_info,
            timestamps=timestamps,
            tags=tags,
            categories=categories,
            additional_info=additional_info,
        )

    def enrich_url(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich URLScan.io URL normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized URLScan.io URL data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        confidence = data.get("confidence_score", 0)

        additional_info = data.get("additional_info", {})
        report_url = additional_info.get("report_url", "Unknown")

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"URLScan Report: {report_url}\n"
        comment += f"Defanged URL: {ioc.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')}\n"
        comment += f"Status: {'🚨 MALICIOUS' if malicious else '✓ Clean'}\n"
        comment += f"Confidence Score: {confidence}%\n"

        # Detection stats
        detection_stats = data.get("detection_stats", {})
        if detection_stats and detection_stats.get("total", 0) > 0:
            malicious_count = detection_stats.get("malicious", 0)
            total = detection_stats.get("total", 0)

            comment += f"Engine Detection: {malicious_count}/{total} engines flagged as malicious\n"

        # Page information
        page_title = additional_info.get("page_title")
        page_status = additional_info.get("page_status")
        page_server = additional_info.get("page_server")

        if page_title:
            comment += f"Page Title: {page_title}\n"
        if page_status:
            comment += f"HTTP Status: {page_status}\n"
        if page_server:
            comment += f"Server: {page_server}\n"

        # Domain information
        domain_info = data.get("domain_info", {})
        if domain_info:
            apex_domain = domain_info.get("apex_domain")
            domain_age_days = domain_info.get("domain_age_days")
            tls_issuer = domain_info.get("tls_issuer")
            tls_valid_days = domain_info.get("tls_valid_days")

            if apex_domain:
                comment += f"Apex Domain: {apex_domain}\n"
            if domain_age_days is not None:
                comment += f"Domain Age: {domain_age_days} days\n"
            if tls_issuer:
                comment += f"TLS Issuer: {tls_issuer}\n"
            if tls_valid_days is not None:
                comment += f"TLS Valid Days: {tls_valid_days}\n"

        # Location and network
        geo_info = data.get("geo_info", {})
        if geo_info:
            city = geo_info.get("city")
            country = geo_info.get("country")

            location_parts = []
            if city:
                location_parts.append(city)
            if country:
                location_parts.append(country)

            if location_parts:
                comment += f"Location: {', '.join(location_parts)}\n"

        network_info = data.get("network_info", {})
        if network_info:
            asn = network_info.get("asn")
            org = network_info.get("organization")
            domain = network_info.get("domain")

            if asn:
                comment += f"ASN: {asn}\n"
            if org:
                comment += f"Organization: {org}\n"
            if domain:
                comment += f"Domain: {domain}\n"

        # Associated resources
        associated_ips = additional_info.get("associated_ips", [])
        if associated_ips:
            comment += (
                f"Associated IPs ({len(associated_ips)}): {', '.join(associated_ips[:5])}"
            )
            if len(associated_ips) > 5:
                comment += f" (+{len(associated_ips) - 5} more)"
            comment += "\n"

        associated_domains = additional_info.get("associated_domains", [])
        if associated_domains:
            comment += f"Associated Domains ({len(associated_domains)}): {', '.join(associated_domains[:5])}"
            if len(associated_domains) > 5:
                comment += f" (+{len(associated_domains) - 5} more)"
            comment += "\n"

        # Security metrics
        malicious_count = additional_info.get("malicious_count", 0)
        secure_percentage = additional_info.get("secure_percentage")
        total_links = additional_info.get("total_links", 0)

        if malicious_count > 0:
            comment += f"⚠️ Malicious Resources Found: {malicious_count}\n"
        if secure_percentage is not None:
            comment += f"Secure Requests: {secure_percentage}%\n"
        if total_links > 0:
            comment += f"Total Links: {total_links}\n"

        # Brands
        brands = additional_info.get("brands", [])
        if brands:
            comment += f"Detected Brands: {', '.join(brands)}\n"

        # Tags
        tags = data.get("tags", [])
        if tags:
            comment += f"Tags: {', '.join(tags[:8])}"
            if len(tags) > 8:
                comment += f" (+{len(tags) - 8} more)"
            comment += "\n"

        # Categories
        categories = data.get("categories", [])
        if categories:
            comment += f"Categories: {', '.join(categories[:5])}"
            if len(categories) > 5:
                comment += f" (+{len(categories) - 5} more)"
            comment += "\n"

        # Screenshots and resources
        screenshot_url = additional_info.get("screenshot_url")
        if screenshot_url:
            comment += f"Screenshot: {screenshot_url}\n"

        return comment