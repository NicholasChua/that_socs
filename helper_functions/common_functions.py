from helper_functions.logging_config import setup_logger
from helper_functions.schema import ThreatIntelligenceNormalizedSchema
from helper_functions.providers.virustotal import VirusTotalClient
from helper_functions.providers.abuseipdb import AbuseIPDBClient
from helper_functions.providers.ipinfo import IPInfoClient
from helper_functions.providers.alienvault import AlienVaultClient
from helper_functions.providers.urlscan import URLScanClient
from helper_functions.providers.shodan import ShodanClient


logger = setup_logger(name="normalize_threat_intelligence", log_file="that-socs.log")


class InvestigationClient:
    """Class for threat intelligence investigation. Wraps multiple providers and normalizes/enriches data."""

    def __init__(
        self,
        virustotal: bool = False,
        abuseipdb: bool = False,
        ipinfo: bool = False,
        alienvault: bool = False,
        urlscan: bool = False,
        shodan: bool = False,
    ):
        if virustotal:
            self.virustotal_client = VirusTotalClient()
        if abuseipdb:
            self.abuseipdb_client = AbuseIPDBClient()
        if ipinfo:
            self.ipinfo_client = IPInfoClient()
        if alienvault:
            self.alienvault_client = AlienVaultClient()
        if urlscan:
            self.urlscan_client = URLScanClient()
        if shodan:
            self.shodan_client = ShodanClient()

    def fetch_ip(self, ioc_value: str) -> dict:
        """Fetch data for an IP IOC from all initialized clients."""
        results = {}
        if hasattr(self, "virustotal_client"):
            results["virustotal"] = self.virustotal_client.fetch_ip(ioc_value)
        if hasattr(self, "abuseipdb_client"):
            results["abuseipdb"] = self.abuseipdb_client.fetch_ip(ioc_value)
        if hasattr(self, "ipinfo_client"):
            results["ipinfo"] = self.ipinfo_client.fetch_ip(ioc_value)
        if hasattr(self, "alienvault_client"):
            results["alienvault"] = self.alienvault_client.fetch_ip(ioc_value)
        if hasattr(self, "shodan_client"):
            results["shodan"] = self.shodan_client.fetch_ip(ioc_value)
        return results

    def fetch_domain(self, ioc_value: str) -> dict:
        """Fetch data for a domain IOC from all initialized clients."""
        results = {}
        if hasattr(self, "virustotal_client"):
            results["virustotal"] = self.virustotal_client.fetch_domain(ioc_value)
        if hasattr(self, "alienvault_client"):
            results["alienvault"] = self.alienvault_client.fetch_domain(ioc_value)
        return results

    def fetch_file_hash(self, ioc_value: str) -> dict:
        """Fetch data for a file hash IOC from all initialized clients."""
        results = {}
        if hasattr(self, "virustotal_client"):
            results["virustotal"] = self.virustotal_client.fetch_file_hash(ioc_value)
        return results

    def fetch_url(self, ioc_value: str) -> dict:
        """Fetch data for a URL IOC from all initialized clients."""
        results = {}
        if hasattr(self, "urlscan_client"):
            scan_id = self.urlscan_client.fetch_url(ioc_value)
            results["urlscan"] = self.urlscan_client.fetch_urlscan_result(scan_id)
        return results

    def normalize_ip(
        self, raw_data: dict
    ) -> dict[str, ThreatIntelligenceNormalizedSchema]:
        """Normalize IP data from all initialized clients."""
        normalized_results = {}
        if "virustotal" in raw_data and hasattr(self, "virustotal_client"):
            normalized_results["virustotal"] = self.virustotal_client.normalize_ip_data(
                raw_data["virustotal"]
            )
        if "abuseipdb" in raw_data and hasattr(self, "abuseipdb_client"):
            normalized_results["abuseipdb"] = self.abuseipdb_client.normalize_ip_data(
                raw_data["abuseipdb"]
            )
        if "ipinfo" in raw_data and hasattr(self, "ipinfo_client"):
            normalized_results["ipinfo"] = self.ipinfo_client.normalize_ip_data(
                raw_data["ipinfo"]
            )
        if "alienvault" in raw_data and hasattr(self, "alienvault_client"):
            normalized_results["alienvault"] = self.alienvault_client.normalize_ip_data(
                raw_data["alienvault"]
            )
        if "shodan" in raw_data and hasattr(self, "shodan_client"):
            normalized_results["shodan"] = self.shodan_client.normalize_ip_data(
                raw_data["shodan"]
            )
        return normalized_results

    def normalize_domain(
        self, raw_data: dict
    ) -> dict[str, ThreatIntelligenceNormalizedSchema]:
        """Normalize domain data from all initialized clients."""
        normalized_results = {}
        if "virustotal" in raw_data and hasattr(self, "virustotal_client"):
            normalized_results["virustotal"] = (
                self.virustotal_client.normalize_domain_data(raw_data["virustotal"])
            )
        if "alienvault" in raw_data and hasattr(self, "alienvault_client"):
            normalized_results["alienvault"] = (
                self.alienvault_client.normalize_domain_data(raw_data["alienvault"])
            )
        return normalized_results

    def normalize_file_hash(
        self, raw_data: dict
    ) -> dict[str, ThreatIntelligenceNormalizedSchema]:
        """Normalize file hash data from all initialized clients."""
        normalized_results = {}
        if "virustotal" in raw_data and hasattr(self, "virustotal_client"):
            normalized_results["virustotal"] = (
                self.virustotal_client.normalize_file_hash_data(raw_data["virustotal"])
            )
        return normalized_results

    def normalize_url(
        self, raw_data: dict
    ) -> dict[str, ThreatIntelligenceNormalizedSchema]:
        """Normalize URL data from all initialized clients."""
        normalized_results = {}
        if "urlscan" in raw_data and hasattr(self, "urlscan_client"):
            normalized_results["urlscan"] = self.urlscan_client.normalize_url_data(
                raw_data["urlscan"]
            )
        return normalized_results

    def combined_enrichment(
        self,
        ip_virustotal_data: ThreatIntelligenceNormalizedSchema | None = None,
        domain_virustotal_data: ThreatIntelligenceNormalizedSchema | None = None,
        file_hash_virustotal_data: ThreatIntelligenceNormalizedSchema | None = None,
        abuseipdb_data: ThreatIntelligenceNormalizedSchema | None = None,
        ipinfo_data: ThreatIntelligenceNormalizedSchema | None = None,
        ip_alienvault_data: ThreatIntelligenceNormalizedSchema | None = None,
        domain_alienvault_data: ThreatIntelligenceNormalizedSchema | None = None,
        urlscan_data: ThreatIntelligenceNormalizedSchema | None = None,
        shodan_data: ThreatIntelligenceNormalizedSchema | None = None,
    ) -> str:
        """Combine comments from multiple threat intelligence sources.

        Args:
            ip_virustotal_data: Normalized VirusTotal IP data dictionary
            domain_virustotal_data: Normalized VirusTotal domain data dictionary
            file_hash_virustotal_data: Normalized VirusTotal file hash data dictionary
            abuseipdb_data: Normalized AbuseIPDB data dictionary
            ipinfo_data: Normalized ipinfo.io data dictionary
            ip_alienvault_data: Normalized AlienVault OTX IP data dictionary
            domain_alienvault_data: Normalized AlienVault OTX domain data dictionary
            urlscan_data: Normalized URLScan.io data dictionary
            shodan_data: Normalized Shodan data dictionary

        Returns:
            str: A combined human-readable comment string from all provided sources
        """
        comments = []

        # Only add comments for sources where data is provided
        if ip_virustotal_data:
            comments.append("=" * 60)
            comments.append("VIRUSTOTAL IP ANALYSIS")
            comments.append("=" * 60)
            comments.append(VirusTotalClient().enrich_ip(ip_virustotal_data))

        if domain_virustotal_data:
            comments.append("=" * 60)
            comments.append("VIRUSTOTAL DOMAIN ANALYSIS")
            comments.append("=" * 60)
            comments.append(VirusTotalClient().enrich_domain(domain_virustotal_data))

        if file_hash_virustotal_data:
            comments.append("=" * 60)
            comments.append("VIRUSTOTAL FILE HASH ANALYSIS")
            comments.append("=" * 60)
            comments.append(
                VirusTotalClient().enrich_file_hash(file_hash_virustotal_data)
            )

        if abuseipdb_data:
            comments.append("=" * 60)
            comments.append("ABUSEIPDB ANALYSIS")
            comments.append("=" * 60)
            comments.append(AbuseIPDBClient().enrich_ip(abuseipdb_data))

        if ipinfo_data:
            comments.append("=" * 60)
            comments.append("IPINFO.IO ANALYSIS")
            comments.append("=" * 60)
            comments.append(IPInfoClient().enrich_ip(ipinfo_data))

        if ip_alienvault_data:
            comments.append("=" * 60)
            comments.append("ALIENVAULT OTX IP ANALYSIS")
            comments.append("=" * 60)
            comments.append(AlienVaultClient().enrich_ip(ip_alienvault_data))

        if domain_alienvault_data:
            comments.append("=" * 60)
            comments.append("ALIENVAULT OTX DOMAIN ANALYSIS")
            comments.append("=" * 60)
            comments.append(AlienVaultClient().enrich_domain(domain_alienvault_data))

        if urlscan_data:
            comments.append("=" * 60)
            comments.append("URLSCAN.IO ANALYSIS")
            comments.append("=" * 60)
            comments.append(URLScanClient().enrich_url(urlscan_data))

        if shodan_data:
            comments.append("=" * 60)
            comments.append("SHODAN ANALYSIS")
            comments.append("=" * 60)
            comments.append(ShodanClient().enrich_ip(shodan_data))

        if not comments:
            return "No threat intelligence data provided."

        # Add summary header
        header = ["=" * 60, "That SOCs Enrichment Summary", "=" * 60, ""]

        return "\n".join(header + comments)

    def full_ip_investigation(
        self,
        ioc_value: str,
        virustotal: bool | None = None,
        abuseipdb: bool | None = None,
        ipinfo: bool | None = None,
        alienvault: bool | None = None,
        shodan: bool | None = None,
    ) -> str:
        """Perform a full IP investigation: fetch, normalize, and enrich data from all initialized clients.

        Args:
            ioc_value (str): The IP address to investigate.

        Returns:
            str: A combined human-readable comment string from all sources.
        """
        # Ensure relevant clients are initialized. Default to True (load all)
        desired = {
            "virustotal": True if virustotal is None else virustotal,
            "abuseipdb": True if abuseipdb is None else abuseipdb,
            "ipinfo": True if ipinfo is None else ipinfo,
            "alienvault": True if alienvault is None else alienvault,
            "shodan": True if shodan is None else shodan,
        }
        clients_map = {
            "virustotal": VirusTotalClient,
            "abuseipdb": AbuseIPDBClient,
            "ipinfo": IPInfoClient,
            "alienvault": AlienVaultClient,
            "shodan": ShodanClient,
        }
        for name, should in desired.items():
            if should and not hasattr(self, f"{name}_client"):
                setattr(self, f"{name}_client", clients_map[name]())

        # Fetch raw data from all clients
        raw_data = self.fetch_ip(ioc_value)

        # Normalize data from all clients
        normalized_data = self.normalize_ip(raw_data)

        # Prepare parameters for combined enrichment
        enrichment_params = {
            "ip_virustotal_data": normalized_data.get("virustotal"),
            "abuseipdb_data": normalized_data.get("abuseipdb"),
            "ipinfo_data": normalized_data.get("ipinfo"),
            "ip_alienvault_data": normalized_data.get("alienvault"),
            "shodan_data": normalized_data.get("shodan"),
        }

        # Generate combined enrichment comment
        comment = self.combined_enrichment(**enrichment_params)

        return comment

    def full_file_hash_investigation(
        self,
        ioc_value: str,
        virustotal: bool | None = None,
    ) -> str:
        """Perform a full file hash investigation: fetch, normalize, and enrich data from all initialized clients.

        Args:
            ioc_value (str): The file hash to investigate.

        Returns:
            str: A combined human-readable comment string from all sources.
        """
        # Ensure relevant clients are initialized. Default to True (load VT)
        if (virustotal is None or virustotal) and not hasattr(
            self, "virustotal_client"
        ):
            self.virustotal_client = VirusTotalClient()

        # Fetch raw data from all clients
        raw_data = self.fetch_file_hash(ioc_value)

        # Normalize data from all clients
        normalized_data = self.normalize_file_hash(raw_data)

        # Prepare parameters for combined enrichment
        enrichment_params = {
            "file_hash_virustotal_data": normalized_data.get("virustotal"),
        }

        # Generate combined enrichment comment
        comment = self.combined_enrichment(**enrichment_params)

        return comment

    def full_domain_investigation(
        self,
        ioc_value: str,
        virustotal: bool | None = None,
        alienvault: bool | None = None,
    ) -> str:
        """Perform a full domain investigation: fetch, normalize, and enrich data from all initialized clients.

        Args:
            ioc_value (str): The domain to investigate.

        Returns:
            str: A combined human-readable comment string from all sources.
        """
        # Ensure relevant clients are initialized. Default to True (load VT + AlienVault)
        if (virustotal is None or virustotal) and not hasattr(
            self, "virustotal_client"
        ):
            self.virustotal_client = VirusTotalClient()
        if (alienvault is None or alienvault) and not hasattr(
            self, "alienvault_client"
        ):
            self.alienvault_client = AlienVaultClient()

        # Fetch raw data from all clients
        raw_data = self.fetch_domain(ioc_value)

        # Normalize data from all clients
        normalized_data = self.normalize_domain(raw_data)

        # Prepare parameters for combined enrichment
        enrichment_params = {
            "domain_virustotal_data": normalized_data.get("virustotal"),
            "domain_alienvault_data": normalized_data.get("alienvault"),
        }

        # Generate combined enrichment comment
        comment = self.combined_enrichment(**enrichment_params)

        return comment

    def full_url_investigation(
        self,
        ioc_value: str,
        urlscan: bool | None = None,
    ) -> str:
        """Perform a full URL investigation: fetch, normalize, and enrich data from all initialized clients.

        Args:
            ioc_value (str): The URL to investigate.

        Returns:
            str: A combined human-readable comment string from all sources.
        """
        # Ensure relevant clients are initialized. Default to True (load URLScan)
        if (urlscan is None or urlscan) and not hasattr(self, "urlscan_client"):
            self.urlscan_client = URLScanClient()

        # Fetch raw data from all clients
        raw_data = self.fetch_url(ioc_value)

        # Normalize data from all clients
        normalized_data = self.normalize_url(raw_data)

        # Prepare parameters for combined enrichment
        enrichment_params = {
            "urlscan_data": normalized_data.get("urlscan"),
        }

        # Generate combined enrichment comment
        comment = self.combined_enrichment(**enrichment_params)

        return comment
