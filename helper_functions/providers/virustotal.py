import os
import requests
from dotenv import load_dotenv
from helper_functions.http_handler import BaseClient
from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema, to_dict


logger = setup_logger(name="retrieve_threat_intelligence", log_file="that-socs.log")
load_dotenv()


class VirusTotalClient(BaseClient):
    """Client for querying VirusTotal for IPs, files and domains, and normalizing the data.

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

    def fetch_file_hash(self, file_hash: str) -> dict:
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

    def normalize_ip_data(self, raw_data: dict) -> ThreatIntelligenceNormalizedSchema:
        """Normalize VirusTotal IP data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from VirusTotal for an IP.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        data = raw_data.get("data", {})
        attributes = data.get("attributes", {})

        # Extract IP address
        ioc = data.get("id", "")

        # Calculate detection stats from last_analysis_results
        last_analysis_results = attributes.get("last_analysis_results", {})
        detection_stats = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": len(last_analysis_results),
        }

        for _, result in last_analysis_results.items():
            category = result.get("category", "undetected")
            if category in detection_stats:
                detection_stats[category] += 1

        # Determine if malicious
        reputation = attributes.get("reputation")
        malicious = detection_stats["malicious"] > 0 or (
            reputation is not None and reputation < 0
        )

        # Extract network info
        network_info = {
            "asn": attributes.get("asn"),
            "organization": attributes.get("as_owner"),
        }

        # Extract geo info
        geo_info = {
            "country": attributes.get("country"),
            "continent": attributes.get("continent"),
        }

        # Extract timestamps
        timestamps = {
            "last_analysis": attributes.get("last_analysis_date"),
            "last_modified": attributes.get("last_modification_date"),
        }

        # Extract tags and categories
        tags = attributes.get("tags", [])
        categories = list(attributes.get("categories", {}).values())

        # Logging for debugging
        logger.debug(
            "Normalized VirusTotal IP data for IOC %s: malicious=%s, reputation=%s",
            ioc,
            malicious,
            reputation,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="VirusTotal",
            ioc_type="ip",
            ioc=ioc,
            reputation_score=reputation,
            malicious=malicious,
            detection_stats=detection_stats,
            geo_info=geo_info,
            network_info=network_info,
            timestamps=timestamps,
            tags=tags,
            categories=categories,
        )

    def normalize_file_hash_data(
        self, raw_data: dict
    ) -> ThreatIntelligenceNormalizedSchema:
        """Normalize VirusTotal file hash data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from VirusTotal for a file hash.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        data = raw_data.get("data", {})
        attributes = data.get("attributes", {})

        # Extract file hash
        ioc = data.get("id", "")

        # Extract detection stats
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        detection_stats = {
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "total": sum(last_analysis_stats.values()) if last_analysis_stats else 0,
        }

        # Determine if malicious
        malicious = detection_stats["malicious"] > 0
        reputation = attributes.get("reputation")

        # Calculate confidence score based on detection ratio
        confidence_score = None
        if detection_stats["total"] > 0:
            confidence_score = int(
                (detection_stats["malicious"] / detection_stats["total"]) * 100
            )

        # Extract file info
        known_distributors = attributes.get("known_distributors", {})
        file_info = {
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "magic": attributes.get("magic"),
            "names": known_distributors.get("filenames", []),
            "ssdeep": attributes.get("ssdeep"),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "sha256": attributes.get("sha256"),
        }

        # Extract timestamps
        timestamps = {
            "first_seen": attributes.get("first_submission_date"),
            "last_seen": attributes.get("last_submission_date"),
            "last_analysis": attributes.get("last_analysis_date"),
            "last_modified": attributes.get("last_modification_date"),
        }

        # Extract tags and categories
        tags = attributes.get("tags", [])

        # Extract sandbox verdicts as categories
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        categories = []
        for _, verdict_info in sandbox_verdicts.items():
            if isinstance(verdict_info, dict):
                category = verdict_info.get("category")
                if category:
                    categories.append(category)
                malware_classification = verdict_info.get("malware_classification", [])
                categories.extend(malware_classification)

        # Add distributors info to additional_info
        additional_info = {
            "times_submitted": attributes.get("times_submitted"),
            "unique_sources": attributes.get("unique_sources"),
            "known_distributors": known_distributors.get("distributors", []),
            "products": known_distributors.get("products", []),
        }

        # Logging for debugging
        logger.debug(
            "Normalized VirusTotal file hash data for IOC %s: malicious=%s, reputation=%s",
            ioc,
            malicious,
            reputation,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="VirusTotal",
            ioc_type="file_hash",
            ioc=ioc,
            reputation_score=reputation,
            malicious=malicious,
            confidence_score=confidence_score,
            detection_stats=detection_stats,
            file_info=file_info,
            timestamps=timestamps,
            tags=tags,
            categories=categories,
            additional_info=additional_info,
        )

    def normalize_domain_data(
        self, raw_data: dict
    ) -> ThreatIntelligenceNormalizedSchema:
        """Normalize VirusTotal domain data into the common schema.

        Args:
            raw_data (dict): Raw JSON data from VirusTotal for a domain.

        Returns:
            ThreatIntelligenceNormalizedSchema: Normalized threat intelligence data.
        """
        data = raw_data.get("data", {})
        attributes = data.get("attributes", {})

        # Extract domain
        ioc = data.get("id", "")

        # Calculate detection stats from last_analysis_results
        last_analysis_results = attributes.get("last_analysis_results", {})
        detection_stats = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": len(last_analysis_results),
        }

        for _, result in last_analysis_results.items():
            category = result.get("category", "undetected")
            if category in detection_stats:
                detection_stats[category] += 1

        # Determine if malicious
        reputation = attributes.get("reputation")
        malicious = detection_stats["malicious"] > 0 or (
            reputation is not None and reputation < 0
        )

        # Extract total votes for confidence
        total_votes = attributes.get("total_votes", {})
        harmless_votes = total_votes.get("harmless", 0)
        malicious_votes = total_votes.get("malicious", 0)
        total_vote_count = harmless_votes + malicious_votes

        confidence_score = None
        if total_vote_count > 0:
            confidence_score = int((malicious_votes / total_vote_count) * 100)

        # Extract domain info
        whois = attributes.get("whois", "")
        registrar = None
        if "Registrar:" in whois:
            for line in whois.split("\n"):
                if line.startswith("Registrar:"):
                    registrar = line.split(":", 1)[1].strip()
                    break

        # Extract creation date from whois
        creation_date = None
        if "Creation Date:" in whois:
            for line in whois.split("\n"):
                if line.startswith("Creation Date:"):
                    creation_date = line.split(":", 1)[1].strip()
                    break

        domain_info = {
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": attributes.get("expiration_date"),
            "whois_date": attributes.get("whois_date"),
            "tld": attributes.get("tld"),
        }

        # Extract timestamps
        timestamps = {
            "last_analysis": attributes.get("last_analysis_date"),
            "last_modified": attributes.get("last_update_date"),
        }

        # Extract tags and categories
        tags = attributes.get("tags", [])
        categories = list(attributes.get("categories", {}).values())

        # Extract popularity ranks
        popularity_ranks = attributes.get("popularity_ranks", {})
        additional_info = {
            "popularity_ranks": popularity_ranks,
            "total_votes": total_votes,
        }

        # Logging for debugging
        logger.debug(
            "Normalized VirusTotal domain data for IOC %s: malicious=%s, reputation=%s",
            ioc,
            malicious,
            reputation,
        )

        return ThreatIntelligenceNormalizedSchema(
            source="VirusTotal",
            ioc_type="domain",
            ioc=ioc,
            reputation_score=reputation,
            malicious=malicious,
            confidence_score=confidence_score,
            detection_stats=detection_stats,
            domain_info=domain_info,
            timestamps=timestamps,
            tags=tags,
            categories=categories,
            additional_info=additional_info,
        )

    def enrich_ip(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich VirusTotal IP normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized VirusTotal IP data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        reputation = data.get("reputation_score", 0)

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"VirusTotal Link: https://www.virustotal.com/gui/ip-address/{ioc}\n"
        comment += f"Defanged IP: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'Malicious' if malicious else 'Clean'}\n"
        comment += f"Reputation Score: {reputation}\n"

        detection_stats = data.get("detection_stats", {})
        if detection_stats:
            malicious_count = detection_stats.get("malicious", 0)
            suspicious_count = detection_stats.get("suspicious", 0)
            harmless_count = detection_stats.get("harmless", 0)
            undetected_count = detection_stats.get("undetected", 0)
            total = detection_stats.get("total", 0)

            comment += f"Detection: {malicious_count} malicious, {suspicious_count} suspicious, "
            comment += f"{harmless_count} harmless, {undetected_count} undetected ({total} total engines)\n"

        geo_info = data.get("geo_info", {})
        if geo_info:
            country = geo_info.get("country", "Unknown")
            continent = geo_info.get("continent", "Unknown")
            comment += f"Location: {country}, {continent}\n"

        network_info = data.get("network_info", {})
        if network_info:
            asn = network_info.get("asn", "Unknown")
            org = network_info.get("organization", "Unknown")
            comment += f"ASN: {asn}\n"
            comment += f"Organization: {org}\n"

        return comment

    def enrich_file_hash(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich VirusTotal file hash normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized VirusTotal file hash data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        reputation = data.get("reputation_score", 0)
        confidence = data.get("confidence_score", 0)

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"VirusTotal Link: https://www.virustotal.com/gui/file/{ioc}\n"
        comment += f"Status: {'🚨 MALICIOUS' if malicious else '✓ Clean'}\n"
        comment += f"Reputation Score: {reputation}\n"
        comment += f"Confidence Score: {confidence}%\n"

        detection_stats = data.get("detection_stats", {})
        if detection_stats:
            malicious_count = detection_stats.get("malicious", 0)
            suspicious_count = detection_stats.get("suspicious", 0)
            harmless_count = detection_stats.get("harmless", 0)
            undetected_count = detection_stats.get("undetected", 0)
            total = detection_stats.get("total", 0)

            comment += (
                f"Detection: {malicious_count}/{total} engines flagged as malicious\n"
            )
            comment += (
                f"Details: {malicious_count} malicious, {suspicious_count} suspicious, "
            )
            comment += f"{harmless_count} harmless, {undetected_count} undetected\n"

        file_info = data.get("file_info", {})
        if file_info:
            file_type = file_info.get("file_type", "Unknown")
            file_size = file_info.get("file_size", 0)
            names = file_info.get("names", [])
            md5 = file_info.get("md5", "Unknown")
            sha1 = file_info.get("sha1", "Unknown")
            sha256 = file_info.get("sha256", "Unknown")

            comment += f"File Type: {file_type}\n"
            comment += f"File Size: {file_size:,} bytes\n"
            comment += f"MD5: {md5}\n"
            comment += f"SHA1: {sha1}\n"
            comment += f"SHA256: {sha256}\n"

            if names:
                comment += f"Known Names: {', '.join(names[:3])}"
                if len(names) > 3:
                    comment += f" (+{len(names) - 3} more)"
                comment += "\n"

        tags = data.get("tags", [])
        if tags:
            comment += f"Tags: {', '.join(tags[:8])}"
            if len(tags) > 8:
                comment += f" (+{len(tags) - 8} more)"
            comment += "\n"

        return comment

    def enrich_domain(self, data: ThreatIntelligenceNormalizedSchema | dict) -> str:
        """Enrich VirusTotal domain normalized data.

        Args:
            data (ThreatIntelligenceNormalizedSchema | dict): Normalized VirusTotal domain data dictionary

        Returns:
            str: A human-readable comment string
        """
        data = to_dict(data)
        time_generated = data.get("normalized_time", "Unknown")
        ioc = data.get("ioc", "Unknown")
        malicious = data.get("malicious", False)
        reputation = data.get("reputation_score", 0)
        confidence = data.get("confidence_score", 0)

        comment = f"Analyzed at: {time_generated}\n"
        comment += f"VirusTotal Link: https://www.virustotal.com/gui/domain/{ioc}\n"
        comment += f"Defanged Domain: {ioc.replace('.', '[.]')}\n"
        comment += f"Status: {'⚠️ MALICIOUS' if malicious else '✓ Clean'}\n"
        comment += f"Reputation Score: {reputation}\n"
        comment += f"Confidence Score: {confidence}%\n"

        detection_stats = data.get("detection_stats", {})
        if detection_stats:
            malicious_count = detection_stats.get("malicious", 0)
            suspicious_count = detection_stats.get("suspicious", 0)
            harmless_count = detection_stats.get("harmless", 0)
            undetected_count = detection_stats.get("undetected", 0)
            total = detection_stats.get("total", 0)

            comment += f"Detection: {malicious_count} malicious, {suspicious_count} suspicious, "
            comment += f"{harmless_count} harmless, {undetected_count} undetected ({total} total engines)\n"

        domain_info = data.get("domain_info", {})
        if domain_info:
            registrar = domain_info.get("registrar", "Unknown")
            creation_date = domain_info.get("creation_date", "Unknown")
            tld = domain_info.get("tld", "Unknown")

            comment += f"Registrar: {registrar}\n"
            comment += f"Creation Date: {creation_date}\n"
            comment += f"TLD: .{tld}\n"

        categories = data.get("categories", [])
        if categories:
            comment += f"Categories: {', '.join(categories[:5])}"
            if len(categories) > 5:
                comment += f" (+{len(categories) - 5} more)"
            comment += "\n"

        return comment
