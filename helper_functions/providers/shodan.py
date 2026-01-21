import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


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

    def normalize_ip_data(
        self, raw_data: dict
    ) -> ThreatIntelligenceNormalizedSchema:
        """Normalize Shodan IP data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from Shodan for an IP.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        # Extract IP address
        ioc = raw_data.get("ip_str", "")

        # Determine if malicious based on vulnerabilities or tags
        vulnerabilities = raw_data.get("vulns", {})
        tags = raw_data.get("tags", [])
        malicious = len(vulnerabilities) > 0 or "malicious" in tags

        # Build geo info
        geo_info = {
            "country": raw_data.get("country_name"),
            "city": raw_data.get("city"),
            "region": raw_data.get("region_name"),
            "coordinates": f"{raw_data.get('latitude')},{raw_data.get('longitude')}",
            "postal": raw_data.get("postal_code"),
            "timezone": raw_data.get("timezone"),
        }

        # Build network info
        network_info = {
            "asn": raw_data.get("asn"),
            "organization": raw_data.get("org"),
            "hostnames": raw_data.get("hostnames", []),
            "domains": raw_data.get("domains", []),
        }

        # Build abuse info
        abuse_info = {
            "vulnerabilities": list(vulnerabilities.keys()),
            "tag_count": len(tags),
        }

        # Additional info
        additional_info = {
            "ports": raw_data.get("ports", []),
            "os": raw_data.get("os"),
            "data_count": raw_data.get("data_count"),
        }

        # Timestamps
        timestamps = {
            "last_update": raw_data.get("last_update"),
        }

        # Logging for debugging
        logger.debug(
            "Normalized Shodan IP data for IOC %s: malicious=%s, vulnerabilities=%s",
            ioc,
            malicious,
            list(vulnerabilities.keys()),
        )

        return ThreatIntelligenceNormalizedSchema(
            source="Shodan",
            ioc_type="ip",
            ioc=ioc,
            malicious=malicious,
            geo_info=geo_info,
            network_info=network_info,
            abuse_info=abuse_info,
            timestamps=timestamps,
            tags=tags,
            additional_info=additional_info,
        )

    def enrich_ip(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich Shodan IP normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized Shodan IP data dictionary
        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"Shodan Link: https://www.shodan.io/host/{ioc}\n"
        comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'⚠️ MALICIOUS' if malicious else '✓ Clean'}\n"

        # Geo information
        geo_info = data.get("geo_info", {})
        if geo_info:
            city = geo_info.get("city")
            country = geo_info.get("country", "Unknown")
            coordinates = geo_info.get("coordinates")

            location_parts = []
            if city:
                location_parts.append(city)
            if country:
                location_parts.append(country)

            if location_parts:
                comment += f"Location: {', '.join(location_parts)}\n"
            if coordinates:
                comment += f"Coordinates: {coordinates}\n"

        # Network information
        network_info = data.get("network_info", {})
        if network_info:
            asn = network_info.get("asn")
            org = network_info.get("organization", "Unknown")
            hostnames = network_info.get("hostnames", [])
            domains = network_info.get("domains", [])

            if asn:
                comment += f"ASN: {asn}\n"
            comment += f"Organization: {org}\n"

            if hostnames:
                comment += f"Hostnames: {', '.join(hostnames)}\n"
            if domains and domains != hostnames:
                comment += f"Domains: {', '.join(domains)}\n"

        # Additional information (ports, OS, etc.)
        additional_info = data.get("additional_info", {})
        if additional_info:
            ports = additional_info.get("ports", [])
            os = additional_info.get("os")
            data_count = additional_info.get("data_count")

            if ports:
                comment += f"Open Ports: {', '.join(map(str, ports))}\n"
            if os:
                comment += f"Operating System: {os}\n"
            if data_count is not None:
                comment += f"Data Records: {data_count}\n"

        # Abuse information
        abuse_info = data.get("abuse_info", {})
        if abuse_info:
            vulnerabilities = abuse_info.get("vulnerabilities", [])
            tag_count = abuse_info.get("tag_count", 0)

            if vulnerabilities:
                comment += f"⚠️ Vulnerabilities ({len(vulnerabilities)}): {', '.join(vulnerabilities[:5])}"
                if len(vulnerabilities) > 5:
                    comment += f" (+{len(vulnerabilities) - 5} more)"
                comment += "\n"
            if tag_count > 0:
                comment += f"Tag Count: {tag_count}\n"

        # Timestamps
        timestamps = data.get("timestamps", {})
        if timestamps:
            last_update = timestamps.get("last_update")
            if last_update:
                comment += f"Last Updated: {last_update}\n"

        # Tags
        tags = data.get("tags", [])
        if tags:
            comment += f"Tags: {', '.join(tags[:8])}"
            if len(tags) > 8:
                comment += f" (+{len(tags) - 8} more)"
            comment += "\n"

        return comment
