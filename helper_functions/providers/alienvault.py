import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


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

    def normalize_ip_data(self, raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
        """Normalize AlienVault OTX IP data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from AlienVault OTX for an IP.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        # Extract IP address
        ioc = raw_data.get("indicator", "")

        # Extract reputation score
        reputation = raw_data.get("reputation", 0)

        # Extract pulse information
        pulse_info = raw_data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Determine if malicious based on reputation and pulse count
        # Negative reputation or multiple pulses may indicate malicious activity
        malicious = reputation < 0 or pulse_count > 0

        # Extract validation and false positive info
        validation = raw_data.get("validation", [])
        false_positive = raw_data.get("false_positive", [])

        # Check if whitelisted
        is_whitelisted = any(v.get("name") == "Whitelisted IP" for v in validation)

        # Extract tags and categories from pulses
        tags = []
        categories = []
        adversaries = []
        malware_families = []

        for pulse in pulses:
            pulse_tags = pulse.get("tags", [])
            tags.extend(pulse_tags)

            # Extract adversary info
            adversary = pulse.get("adversary", "")
            if adversary:
                adversaries.append(adversary)

            # Extract malware families
            malware = pulse.get("malware_families", [])
            if malware:
                for family in malware:
                    if isinstance(family, dict):
                        malware_families.append(family.get("display_name", ""))
                    else:
                        malware_families.append(str(family))

        # Deduplicate tags
        tags = list(set(tags))
        categories = list(set(malware_families))

        # Build geo info
        geo_info = {
            "country": raw_data.get("country_code"),
            "country_name": raw_data.get("country_name"),
            "city": raw_data.get("city"),
            "region": raw_data.get("region"),
            "coordinates": (
                f"{raw_data.get('latitude')},{raw_data.get('longitude')}"
                if raw_data.get("latitude")
                else None
            ),
            "continent_code": raw_data.get("continent_code"),
        }

        # Build network info
        asn_info = raw_data.get("asn", "")
        network_info = {
            "asn": asn_info.split()[0] if asn_info else None,
            "organization": " ".join(asn_info.split()[1:]) if asn_info else None,
        }

        # Build abuse info
        abuse_info = {
            "is_whitelisted": is_whitelisted,
            "pulse_count": pulse_count,
            "false_positive_count": len(false_positive),
        }

        # Calculate confidence score based on pulse count and validation
        confidence_score = None
        if pulse_count > 0:
            # Higher pulse count = higher confidence in malicious verdict
            confidence_score = min(pulse_count * 10, 100)  # Cap at 100

        # Reduce confidence if whitelisted or false positives exist
        if is_whitelisted:
            confidence_score = 0
            malicious = False
        elif len(false_positive) > 0:
            confidence_score = max(
                0, (confidence_score or 0) - len(false_positive) * 10
            )

        # Additional info
        additional_info = {
            "whois_link": raw_data.get("whois"),
            "sections": raw_data.get("sections", []),
            "validation": validation,
            "false_positive": false_positive,
            "adversaries": list(set(adversaries)),
        }

        # Logging for debugging
        logger.debug(
            "Normalized AlienVault IP data for IOC %s: malicious=%s, reputation=%s, pulse_count=%s",
            ioc,
            malicious,
            reputation,
            pulse_count,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="AlienVault OTX",
            ioc_type="ip",
            ioc=ioc,
            reputation_score=reputation,
            malicious=malicious,
            confidence_score=confidence_score,
            geo_info=geo_info,
            network_info=network_info,
            abuse_info=abuse_info,
            tags=tags,
            categories=categories,
            additional_info=additional_info,
        )

    def normalize_domain_data(
        self,
        raw_data: dict,
    ) -> ThreatIntelligenceNormalizedSchema:
        """Normalize AlienVault OTX domain data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from AlienVault OTX for a domain.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        # Extract domain
        ioc = raw_data.get("indicator", "")

        # Extract pulse information
        pulse_info = raw_data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Extract validation and false positive info
        validation = raw_data.get("validation", [])
        false_positive = raw_data.get("false_positive", [])

        # Check if whitelisted
        is_whitelisted = any(
            "Whitelisted domain" in v.get("name", "") for v in validation
        )

        # Determine if malicious based on pulse count and validation
        malicious = pulse_count > 0 and not is_whitelisted

        # Extract tags and categories from pulses
        tags = []
        categories = []
        adversaries = []
        malware_families = []

        for pulse in pulses:
            pulse_tags = pulse.get("tags", [])
            tags.extend(pulse_tags)

            # Extract adversary info
            adversary = pulse.get("adversary", "")
            if adversary:
                adversaries.append(adversary)

            # Extract malware families
            malware = pulse.get("malware_families", [])
            if malware:
                for family in malware:
                    if isinstance(family, dict):
                        malware_families.append(family.get("display_name", ""))
                    else:
                        malware_families.append(str(family))

        # Deduplicate tags and categories
        tags = list(set(tags))
        categories = list(set(malware_families))

        # Calculate confidence score based on pulse count and validation
        confidence_score = None
        if pulse_count > 0:
            # Higher pulse count = higher confidence
            confidence_score = min(pulse_count * 5, 100)  # Cap at 100

        # Adjust confidence based on validation
        if is_whitelisted:
            confidence_score = 0
            malicious = False
        elif len(false_positive) > 0:
            confidence_score = max(
                0, (confidence_score or 0) - len(false_positive) * 10
            )

        # Extract Alexa rank from validation if available
        alexa_rank = None
        akamai_rank = None
        for v in validation:
            if "Akamai" in v.get("name", ""):
                message = v.get("message", "")
                # Parse "Akamai rank: #1458"
                if "#" in message:
                    try:
                        akamai_rank = int(message.split("#")[1])
                    except (ValueError, IndexError):
                        pass
            elif "Alexa" in v.get("name", ""):
                message = v.get("message", "")
                if "#" in message:
                    try:
                        alexa_rank = int(message.split("#")[1])
                    except (ValueError, IndexError):
                        pass

        # Build domain info
        domain_info = {
            "alexa_rank": alexa_rank,
            "akamai_rank": akamai_rank,
        }

        # Build abuse info
        abuse_info = {
            "is_whitelisted": is_whitelisted,
            "pulse_count": pulse_count,
            "false_positive_count": len(false_positive),
        }

        # Additional info
        additional_info = {
            "whois_link": raw_data.get("whois"),
            "alexa_link": raw_data.get("alexa"),
            "sections": raw_data.get("sections", []),
            "validation": validation,
            "false_positive": false_positive,
            "adversaries": list(set(adversaries)),
        }

        # Logging for debugging
        logger.debug(
            "Normalized AlienVault domain data for IOC %s: malicious=%s, pulse_count=%s, whitelisted=%s",
            ioc,
            malicious,
            pulse_count,
            is_whitelisted,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="AlienVault OTX",
            ioc_type="domain",
            ioc=ioc,
            malicious=malicious,
            confidence_score=confidence_score,
            domain_info=domain_info,
            abuse_info=abuse_info,
            tags=tags,
            categories=categories,
            additional_info=additional_info,
        )

    def enrich_ip(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich AlienVault OTX IP normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized AlienVault OTX IP data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        reputation = data.get("reputation_score", 0)
        confidence = data.get("confidence_score")

        comment = f"Analyzed at: {time_generated}\n"
        comment += (
            f"AlienVault OTX Link: https://otx.alienvault.com/indicator/ip/{ioc}\n"
        )
        comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'⚠️ MALICIOUS' if malicious else '✓ Clean'}\n"
        comment += f"Reputation Score: {reputation}\n"
        if confidence is not None:
            comment += f"Confidence Score: {confidence}%\n"

        abuse_info = data.get("abuse_info", {})
        if abuse_info:
            pulse_count = abuse_info.get("pulse_count", 0)
            is_whitelisted = abuse_info.get("is_whitelisted", False)

            comment += f"Pulse Count: {pulse_count}\n"
            if is_whitelisted:
                comment += "✓ This IP is whitelisted\n"

        geo_info = data.get("geo_info", {})
        if geo_info:
            country = geo_info.get("country_name") or geo_info.get("country", "Unknown")
            city = geo_info.get("city")
            coordinates = geo_info.get("coordinates")

            location_parts = [country]
            if city:
                location_parts.insert(0, city)

            comment += f"Location: {', '.join(location_parts)}\n"
            if coordinates:
                comment += f"Coordinates: {coordinates}\n"

        network_info = data.get("network_info", {})
        if network_info:
            asn = network_info.get("asn", "Unknown")
            org = network_info.get("organization", "Unknown")
            comment += f"ASN: {asn}\n"
            comment += f"Organization: {org}\n"

        additional_info = data.get("additional_info", {})
        adversaries = additional_info.get("adversaries", [])
        if adversaries:
            comment += f"Associated Adversaries: {', '.join(adversaries)}\n"

        return comment

    def enrich_domain(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich AlienVault OTX domain normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized AlienVault OTX domain data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        confidence = data.get("confidence_score")

        comment = f"Analyzed at: {time_generated}\n"
        comment += (
            f"AlienVault OTX Link: https://otx.alienvault.com/indicator/domain/{ioc}\n"
        )
        comment += f"Defanged Domain: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'⚠️ MALICIOUS' if malicious else '✓ Clean'}\n"
        if confidence is not None:
            comment += f"Confidence Score: {confidence}%\n"

        abuse_info = data.get("abuse_info", {})
        if abuse_info:
            pulse_count = abuse_info.get("pulse_count", 0)
            is_whitelisted = abuse_info.get("is_whitelisted", False)

            comment += f"Pulse Count: {pulse_count}\n"
            if is_whitelisted:
                comment += "✓ This domain is whitelisted\n"

        domain_info = data.get("domain_info", {})
        if domain_info:
            alexa = domain_info.get("alexa_rank")
            akamai = domain_info.get("akamai_rank")

            if alexa:
                comment += f"Alexa Rank: #{alexa}\n"
            if akamai:
                comment += f"Akamai Rank: #{akamai}\n"

        additional_info = data.get("additional_info", {})
        adversaries = additional_info.get("adversaries", [])
        if adversaries:
            comment += f"Associated Adversaries: {', '.join(adversaries)}\n"

        tags = data.get("tags", [])
        if tags:
            comment += f"Tags: {', '.join(tags[:8])}"
            if len(tags) > 8:
                comment += f" (+{len(tags) - 8} more)"
            comment += "\n"

        return comment
