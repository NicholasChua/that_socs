import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


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

    def normalize_ip_data(self, raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
        """Normalize AbuseIPDB IP data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from AbuseIPDB for an IP.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        data = raw_data.get("data", {})

        # Extract IP address
        ioc = data.get("ipAddress", "")

        # Get abuse confidence score
        abuse_confidence = data.get("abuseConfidenceScore", 0)

        # Determine if malicious (typically >50% confidence)
        malicious = abuse_confidence > 50

        # Build abuse info
        abuse_info = {
            "abuse_confidence_score": abuse_confidence,
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "num_distinct_users": data.get("numDistinctUsers", 0),
        }

        # Build geo info
        geo_info = {
            "country": data.get("countryCode"),
        }

        # Build network info
        network_info = {
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "usage_type": data.get("usageType"),
        }

        # Additional info
        additional_info = {
            "is_public": data.get("isPublic"),
            "ip_version": data.get("ipVersion"),
        }

        # Logging for debugging
        logger.debug(
            "Normalized AbuseIPDB data for IOC %s: malicious=%s, abuse_confidence=%s",
            ioc,
            malicious,
            abuse_confidence,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="AbuseIPDB",
            ioc_type="ip",
            ioc=ioc,
            malicious=malicious,
            confidence_score=abuse_confidence,
            geo_info=geo_info,
            network_info=network_info,
            abuse_info=abuse_info,
            additional_info=additional_info,
        )

    def enrich_ip(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich AbuseIPDB IP normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized AbuseIPDB IP data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        normalized_time = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", "Unknown")
        confidence = data.get("confidence_score", "Unknown")
        abuse_info = data.get("abuse_info", {})

        comment = f"Analyzed at: {normalized_time}\n"
        comment += f"AbuseIPDB Link: https://www.abuseipdb.com/check/{ioc}\n"
        comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'Malicious' if malicious else 'Clean'}\n"
        comment += f"Abuse Confidence Score: {confidence}%\n"

        if abuse_info:
            total_reports = abuse_info.get("total_reports", 0)
            distinct_users = abuse_info.get("num_distinct_users", 0)
            last_reported = abuse_info.get("last_reported", "N/A")

            comment += (
                f"Total Reports: {total_reports} from {distinct_users} distinct users\n"
            )
            comment += f"Last Reported: {last_reported}\n"

            if abuse_info.get("is_tor"):
                comment += "⚠️ This IP is associated with TOR\n"
            if abuse_info.get("is_whitelisted"):
                comment += "✓ This IP is whitelisted\n"

        geo_info = data.get("geo_info", {})
        if geo_info:
            comment += f"Country: {geo_info.get('country', 'Unknown')}\n"

        network_info = data.get("network_info", {})
        if network_info:
            comment += f"ISP: {network_info.get('isp', 'Unknown')}\n"
            usage_type = network_info.get("usage_type")
            if usage_type:
                comment += f"Usage Type: {usage_type}\n"

        return comment
