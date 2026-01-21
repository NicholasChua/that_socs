import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


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

    def normalize_ip_data(self, raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
        """Normalize ipinfo.io IP data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from ipinfo.io for an IP.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        # Extract IP address
        ioc = raw_data.get("ip", "")

        # Build geo info
        geo_info = {
            "country": raw_data.get("country"),
            "city": raw_data.get("city"),
            "region": raw_data.get("region"),
            "coordinates": raw_data.get("loc"),
            "timezone": raw_data.get("timezone"),
            "postal": raw_data.get("postal"),
        }

        # Build network info
        # Parse ASN from org field (format: "AS15169 Google LLC")
        org = raw_data.get("org", "")
        asn = None
        organization = org
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            if len(parts) == 2:
                asn = parts[0]
                organization = parts[1]

        network_info = {
            "asn": asn,
            "organization": organization,
            "hostnames": [raw_data.get("hostname")] if raw_data.get("hostname") else [],
        }

        # Additional info
        additional_info = {
            "anycast": raw_data.get("anycast"),
        }

        # Logging for debugging
        logger.debug("Normalized ipinfo.io data for IOC %s", ioc)

        return ThreatIntelligenceNormalizedSchema(
            source="ipinfo.io",
            ioc_type="ip",
            ioc=ioc,
            geo_info=geo_info,
            network_info=network_info,
            additional_info=additional_info,
        )

    def enrich_ip(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich ipinfo.io IP normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized ipinfo.io IP data dictionary
        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"ipinfo.io Link: https://ipinfo.io/{ioc}\n"
        comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"

        geo_info = data.get("geo_info", {})
        if geo_info:
            city = geo_info.get("city", "Unknown")
            region = geo_info.get("region", "Unknown")
            country = geo_info.get("country", "Unknown")
            coordinates = geo_info.get("coordinates", "Unknown")
            timezone = geo_info.get("timezone", "Unknown")
            postal = geo_info.get("postal", "Unknown")

            comment += f"Location: {city}, {region}, {country}\n"
            comment += f"Coordinates: {coordinates}\n"
            comment += f"Timezone: {timezone}\n"
            comment += f"Postal Code: {postal}\n"

        network_info = data.get("network_info", {})
        if network_info:
            asn = network_info.get("asn", "Unknown")
            org = network_info.get("organization", "Unknown")
            comment += f"ASN: {asn}\n"
            comment += f"Organization: {org}\n"

            hostnames = network_info.get("hostnames", [])
            if hostnames:
                comment += f"Hostnames: {', '.join(hostnames)}\n"

        return comment
