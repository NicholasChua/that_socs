from datetime import datetime, timezone

# TODO: Fine tune schema as needed
class ThreatIntelligenceNormalizedSchema:
    """Common schema for normalized threat intelligence data.

    Attributes:
        # Metadata
        schema_version (str): Version of the normalization schema. Added for future backwards compatibility considerations.
        normalized_time (str): ISO 8601 timestamp when normalization was performed.

        # Core IOC Information
        source (str): Source of the threat intelligence data (e.g., 'VirusTotal', 'AbuseIPDB', 'ipinfo.io')
        ioc_type (str): Type of IOC ('ip', 'file_hash', 'domain', 'url')
        ioc (str): The actual IOC value

        # Threat Assessment
        reputation_score (int | None): Reputation score if available (source-specific scale)
        malicious (bool | None): Whether the IOC is considered malicious
        confidence_score (int | None): Confidence level in the assessment (0-100)

        # Detection Statistics
        detection_stats (dict | None): Analysis results summary
            - malicious: count of engines flagging as malicious
            - suspicious: count of engines flagging as suspicious
            - harmless: count of engines flagging as harmless
            - undetected: count of engines with no verdict
            - total: total number of engines

        # Geolocation Data (for IPs)
        geo_info (dict | None):
            - country: country code
            - country_name: full country name
            - city: city name
            - region: region/state
            - coordinates: lat/long coordinates
            - timezone: timezone

        # Network/Infrastructure Info
        network_info (dict | None):
            - asn: autonomous system number
            - isp: internet service provider
            - organization: organization name
            - hostnames: list of associated hostnames
            - domain: associated domain

        # Abuse/Threat Indicators
        abuse_info (dict | None):
            - abuse_confidence_score: confidence in abuse (0-100)
            - total_reports: number of abuse reports
            - last_reported: timestamp of last report
            - is_tor: whether it's a Tor exit node
            - is_proxy: whether it's a proxy
            - is_whitelisted: whether it's whitelisted

        # Temporal Information
        timestamps (dict | None):
            - first_seen: first observation timestamp
            - last_seen: last observation timestamp
            - last_analysis: last analysis timestamp
            - last_modified: last modification timestamp

        # Tags and Categories
        tags (list[str]): List of tags/labels
        categories (list[str]): Categorizations (phishing, malware, etc.)

        # File-specific data (for file_hash IOCs)
        file_info (dict | None):
            - file_type: type of file
            - file_size: size in bytes
            - magic: file magic description
            - names: known file names
            - ssdeep: ssdeep fuzzy hash
            - md5: MD5 hash
            - sha1: SHA1 hash
            - sha256: SHA256 hash

        # Domain-specific data
        domain_info (dict | None):
            - registrar: domain registrar
            - creation_date: domain creation date
            - expiration_date: domain expiration date
            - whois_date: whois lookup date
            - nameservers: list of nameservers

        # Additional data
        additional_info (dict): Any other source-specific information
    """

    def __init__(
        self,
        source: str,
        ioc_type: str,
        ioc: str,
        reputation_score: int | None = None,
        malicious: bool | None = None,
        confidence_score: int | None = None,
        detection_stats: dict | None = None,
        geo_info: dict | None = None,
        network_info: dict | None = None,
        abuse_info: dict | None = None,
        timestamps: dict | None = None,
        tags: list[str] | None = None,
        categories: list[str] | None = None,
        file_info: dict | None = None,
        domain_info: dict | None = None,
        additional_info: dict | None = None,
    ):
        self.schema_version = "1.0"
        self.normalized_time = datetime.now(timezone.utc).isoformat()
        self.source = source
        self.ioc_type = ioc_type
        self.ioc = ioc
        self.reputation_score = reputation_score
        self.malicious = malicious
        self.confidence_score = confidence_score
        self.detection_stats = detection_stats
        self.geo_info = geo_info
        self.network_info = network_info
        self.abuse_info = abuse_info
        self.timestamps = timestamps
        self.tags = tags or []
        self.categories = categories or []
        self.file_info = file_info
        self.domain_info = domain_info
        self.additional_info = additional_info or {}

def to_dict(data: ThreatIntelligenceNormalizedSchema | dict | None) -> dict:
    """Helper to coerce the ThreatIntelligenceNormalizedSchema to a plain dict. If a dict is provided, it is returned as-is."""
    if data is None:
        return {}
    if isinstance(data, ThreatIntelligenceNormalizedSchema):
        return data.__dict__
    return data
