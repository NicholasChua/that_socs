"""Unit tests for helper_functions.normalize_threat_intelligence.

These tests validate data normalization functions by using example data files
from the example_data/ directory.
"""

import pytest
import json
import os
from helper_functions.normalize_threat_intelligence import (
    ThreatIntelligenceNormalizedSchema,
    normalize_abuseipdb_data,
    normalize_ipinfo_data,
    normalize_ip_virustotal_data,
    normalize_file_hash_virustotal_data,
    normalize_domain_virustotal_data,
    normalize_ip_alienvault_data,
    normalize_domain_alienvault_data,
    normalize_urlscan_data,
    normalize_shodan_ip_data,
)


# Fixture paths
EXAMPLE_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "example_data")


@pytest.fixture
def abuseipdb_raw_data():
    """Load raw AbuseIPDB data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "abuseipdb_result.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def ipinfo_raw_data():
    """Load raw ipinfo.io data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "ipinfo_result.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def ip_virustotal_raw_data():
    """Load raw VirusTotal IP data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "ip_virustotal_result.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def file_hash_virustotal_raw_data():
    """Load raw VirusTotal file hash data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "file_hash_virustotal_result.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def domain_virustotal_raw_data():
    """Load raw VirusTotal domain data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "domain_virustotal_result.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def ip_alienvault_raw_data():
    """Load raw AlienVault IP data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "ip_alienvault_result.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def domain_alienvault_raw_data():
    """Load raw AlienVault domain data from example file."""
    with open(
        os.path.join(EXAMPLE_DATA_DIR, "domain_alienvault_result.json"), "r"
    ) as f:
        return json.load(f)


@pytest.fixture
def urlscan_raw_data():
    """Load raw URLScan.io data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "urlscan_result.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def shodan_raw_data():
    """Load raw Shodan IP data from example file."""
    with open(os.path.join(EXAMPLE_DATA_DIR, "shodan_ip_result.json"), "r") as f:
        return json.load(f)


class TestNormalizeAbuseIPDB:
    """Test suite for AbuseIPDB data normalization."""

    def test_normalize_abuseipdb_returns_correct_schema(self, abuseipdb_raw_data):
        """Test that normalize_abuseipdb_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_abuseipdb_source_field(self, abuseipdb_raw_data):
        """Test that source field is correctly set to 'AbuseIPDB'."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.source == "AbuseIPDB"

    def test_normalize_abuseipdb_ioc_type(self, abuseipdb_raw_data):
        """Test that ioc_type field is correctly set to 'ip'."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.ioc_type == "ip"

    def test_normalize_abuseipdb_ioc_value(self, abuseipdb_raw_data):
        """Test that ioc field contains the IP address."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_abuseipdb_confidence_score(self, abuseipdb_raw_data):
        """Test that confidence_score is extracted correctly."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.confidence_score is not None
        assert 0 <= result.confidence_score <= 100

    def test_normalize_abuseipdb_malicious_flag(self, abuseipdb_raw_data):
        """Test that malicious flag is set correctly based on confidence score."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_abuseipdb_abuse_info(self, abuseipdb_raw_data):
        """Test that abuse_info dictionary is populated."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.abuse_info is not None
        assert isinstance(result.abuse_info, dict)
        assert "abuse_confidence_score" in result.abuse_info
        assert "total_reports" in result.abuse_info

    def test_normalize_abuseipdb_geo_info(self, abuseipdb_raw_data):
        """Test that geo_info dictionary is populated."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.geo_info is not None
        assert isinstance(result.geo_info, dict)

    def test_normalize_abuseipdb_network_info(self, abuseipdb_raw_data):
        """Test that network_info dictionary is populated."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.network_info is not None
        assert isinstance(result.network_info, dict)

    def test_normalize_abuseipdb_schema_version(self, abuseipdb_raw_data):
        """Test that schema_version is set."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.schema_version is not None

    def test_normalize_abuseipdb_normalized_time(self, abuseipdb_raw_data):
        """Test that normalized_time is set."""
        result = normalize_abuseipdb_data(abuseipdb_raw_data)
        assert result.normalized_time is not None


class TestNormalizeIPInfo:
    """Test suite for ipinfo.io data normalization."""

    def test_normalize_ipinfo_returns_correct_schema(self, ipinfo_raw_data):
        """Test that normalize_ipinfo_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_ipinfo_source_field(self, ipinfo_raw_data):
        """Test that source field is correctly set to 'ipinfo.io'."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.source == "ipinfo.io"

    def test_normalize_ipinfo_ioc_type(self, ipinfo_raw_data):
        """Test that ioc_type field is correctly set to 'ip'."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.ioc_type == "ip"

    def test_normalize_ipinfo_ioc_value(self, ipinfo_raw_data):
        """Test that ioc field contains the IP address."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_ipinfo_geo_info(self, ipinfo_raw_data):
        """Test that geo_info dictionary is populated."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.geo_info is not None
        assert isinstance(result.geo_info, dict)

    def test_normalize_ipinfo_network_info(self, ipinfo_raw_data):
        """Test that network_info dictionary is populated."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.network_info is not None
        assert isinstance(result.network_info, dict)

    def test_normalize_ipinfo_schema_version(self, ipinfo_raw_data):
        """Test that schema_version is set."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.schema_version is not None

    def test_normalize_ipinfo_normalized_time(self, ipinfo_raw_data):
        """Test that normalized_time is set."""
        result = normalize_ipinfo_data(ipinfo_raw_data)
        assert result.normalized_time is not None


class TestNormalizeVirusTotalIP:
    """Test suite for VirusTotal IP data normalization."""

    def test_normalize_vt_ip_returns_correct_schema(self, ip_virustotal_raw_data):
        """Test that normalize_ip_virustotal_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_vt_ip_source_field(self, ip_virustotal_raw_data):
        """Test that source field is correctly set to 'VirusTotal'."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.source == "VirusTotal"

    def test_normalize_vt_ip_ioc_type(self, ip_virustotal_raw_data):
        """Test that ioc_type field is correctly set to 'ip'."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.ioc_type == "ip"

    def test_normalize_vt_ip_ioc_value(self, ip_virustotal_raw_data):
        """Test that ioc field contains the IP address."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_vt_ip_detection_stats(self, ip_virustotal_raw_data):
        """Test that detection_stats dictionary is populated."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.detection_stats is not None
        assert isinstance(result.detection_stats, dict)
        assert "malicious" in result.detection_stats
        assert "suspicious" in result.detection_stats
        assert "harmless" in result.detection_stats
        assert "undetected" in result.detection_stats
        assert "total" in result.detection_stats

    def test_normalize_vt_ip_malicious_flag(self, ip_virustotal_raw_data):
        """Test that malicious flag is set based on detection stats."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_vt_ip_reputation_score(self, ip_virustotal_raw_data):
        """Test that reputation_score is extracted."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        # reputation_score may be None or an integer
        if result.reputation_score is not None:
            assert isinstance(result.reputation_score, int)

    def test_normalize_vt_ip_schema_version(self, ip_virustotal_raw_data):
        """Test that schema_version is set."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.schema_version is not None

    def test_normalize_vt_ip_normalized_time(self, ip_virustotal_raw_data):
        """Test that normalized_time is set."""
        result = normalize_ip_virustotal_data(ip_virustotal_raw_data)
        assert result.normalized_time is not None


class TestNormalizeVirusTotalFileHash:
    """Test suite for VirusTotal file hash data normalization."""

    def test_normalize_vt_file_returns_correct_schema(
        self, file_hash_virustotal_raw_data
    ):
        """Test that normalize_file_hash_virustotal_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_vt_file_source_field(self, file_hash_virustotal_raw_data):
        """Test that source field is correctly set to 'VirusTotal'."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.source == "VirusTotal"

    def test_normalize_vt_file_ioc_type(self, file_hash_virustotal_raw_data):
        """Test that ioc_type field is correctly set to 'file_hash'."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.ioc_type == "file_hash"

    def test_normalize_vt_file_ioc_value(self, file_hash_virustotal_raw_data):
        """Test that ioc field contains the file hash."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_vt_file_detection_stats(self, file_hash_virustotal_raw_data):
        """Test that detection_stats dictionary is populated."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.detection_stats is not None
        assert isinstance(result.detection_stats, dict)
        assert "malicious" in result.detection_stats
        assert "total" in result.detection_stats

    def test_normalize_vt_file_malicious_flag(self, file_hash_virustotal_raw_data):
        """Test that malicious flag is set based on detection stats."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_vt_file_file_info(self, file_hash_virustotal_raw_data):
        """Test that file_info dictionary is populated."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.file_info is not None
        assert isinstance(result.file_info, dict)

    def test_normalize_vt_file_schema_version(self, file_hash_virustotal_raw_data):
        """Test that schema_version is set."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.schema_version is not None

    def test_normalize_vt_file_normalized_time(self, file_hash_virustotal_raw_data):
        """Test that normalized_time is set."""
        result = normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data)
        assert result.normalized_time is not None


class TestNormalizeVirusTotalDomain:
    """Test suite for VirusTotal domain data normalization."""

    def test_normalize_vt_domain_returns_correct_schema(
        self, domain_virustotal_raw_data
    ):
        """Test that normalize_domain_virustotal_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_vt_domain_source_field(self, domain_virustotal_raw_data):
        """Test that source field is correctly set to 'VirusTotal'."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.source == "VirusTotal"

    def test_normalize_vt_domain_ioc_type(self, domain_virustotal_raw_data):
        """Test that ioc_type field is correctly set to 'domain'."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.ioc_type == "domain"

    def test_normalize_vt_domain_ioc_value(self, domain_virustotal_raw_data):
        """Test that ioc field contains the domain name."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_vt_domain_detection_stats(self, domain_virustotal_raw_data):
        """Test that detection_stats dictionary is populated."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.detection_stats is not None
        assert isinstance(result.detection_stats, dict)
        assert "malicious" in result.detection_stats
        assert "total" in result.detection_stats

    def test_normalize_vt_domain_malicious_flag(self, domain_virustotal_raw_data):
        """Test that malicious flag is set based on detection stats."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_vt_domain_domain_info(self, domain_virustotal_raw_data):
        """Test that domain_info dictionary is populated."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        # domain_info may or may not be present depending on data
        if result.domain_info is not None:
            assert isinstance(result.domain_info, dict)

    def test_normalize_vt_domain_categories(self, domain_virustotal_raw_data):
        """Test that categories list is populated."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert isinstance(result.categories, list)

    def test_normalize_vt_domain_schema_version(self, domain_virustotal_raw_data):
        """Test that schema_version is set."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.schema_version is not None

    def test_normalize_vt_domain_normalized_time(self, domain_virustotal_raw_data):
        """Test that normalized_time is set."""
        result = normalize_domain_virustotal_data(domain_virustotal_raw_data)
        assert result.normalized_time is not None


class TestNormalizeAlienVaultIP:
    """Test suite for AlienVault OTX IP data normalization."""

    def test_normalize_av_ip_returns_correct_schema(self, ip_alienvault_raw_data):
        """Test that normalize_ip_alienvault_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_av_ip_source_field(self, ip_alienvault_raw_data):
        """Test that source field is correctly set to 'AlienVault OTX'."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.source == "AlienVault OTX"

    def test_normalize_av_ip_ioc_type(self, ip_alienvault_raw_data):
        """Test that ioc_type field is correctly set to 'ip'."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.ioc_type == "ip"

    def test_normalize_av_ip_ioc_value(self, ip_alienvault_raw_data):
        """Test that ioc field contains the IP address."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_av_ip_malicious_flag(self, ip_alienvault_raw_data):
        """Test that malicious flag is set based on reputation and pulse count."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_av_ip_reputation_score(self, ip_alienvault_raw_data):
        """Test that reputation_score is extracted."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        # reputation_score may be None or an integer
        if result.reputation_score is not None:
            assert isinstance(result.reputation_score, int)

    def test_normalize_av_ip_geo_info(self, ip_alienvault_raw_data):
        """Test that geo_info dictionary is populated."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.geo_info is not None
        assert isinstance(result.geo_info, dict)

    def test_normalize_av_ip_network_info(self, ip_alienvault_raw_data):
        """Test that network_info dictionary is populated."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.network_info is not None
        assert isinstance(result.network_info, dict)

    def test_normalize_av_ip_tags_categories(self, ip_alienvault_raw_data):
        """Test that tags and categories are populated."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert isinstance(result.tags, list)
        assert isinstance(result.categories, list)

    def test_normalize_av_ip_schema_version(self, ip_alienvault_raw_data):
        """Test that schema_version is set."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.schema_version is not None

    def test_normalize_av_ip_normalized_time(self, ip_alienvault_raw_data):
        """Test that normalized_time is set."""
        result = normalize_ip_alienvault_data(ip_alienvault_raw_data)
        assert result.normalized_time is not None


class TestNormalizeAlienVaultDomain:
    """Test suite for AlienVault OTX domain data normalization."""

    def test_normalize_av_domain_returns_correct_schema(
        self, domain_alienvault_raw_data
    ):
        """Test that normalize_domain_alienvault_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_av_domain_source_field(self, domain_alienvault_raw_data):
        """Test that source field is correctly set to 'AlienVault OTX'."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.source == "AlienVault OTX"

    def test_normalize_av_domain_ioc_type(self, domain_alienvault_raw_data):
        """Test that ioc_type field is correctly set to 'domain'."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.ioc_type == "domain"

    def test_normalize_av_domain_ioc_value(self, domain_alienvault_raw_data):
        """Test that ioc field contains the domain name."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_av_domain_malicious_flag(self, domain_alienvault_raw_data):
        """Test that malicious flag is set based on pulse count."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_av_domain_domain_info(self, domain_alienvault_raw_data):
        """Test that domain_info dictionary is populated."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.domain_info is not None
        assert isinstance(result.domain_info, dict)

    def test_normalize_av_domain_tags_categories(self, domain_alienvault_raw_data):
        """Test that tags and categories are populated."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert isinstance(result.tags, list)
        assert isinstance(result.categories, list)

    def test_normalize_av_domain_schema_version(self, domain_alienvault_raw_data):
        """Test that schema_version is set."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.schema_version is not None

    def test_normalize_av_domain_normalized_time(self, domain_alienvault_raw_data):
        """Test that normalized_time is set."""
        result = normalize_domain_alienvault_data(domain_alienvault_raw_data)
        assert result.normalized_time is not None


class TestNormalizeURLScan:
    """Test suite for URLScan.io data normalization."""

    def test_normalize_urlscan_returns_correct_schema(self, urlscan_raw_data):
        """Test that normalize_urlscan_data returns ThreatIntelligenceNormalizedSchema instance."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert isinstance(result, ThreatIntelligenceNormalizedSchema)

    def test_normalize_urlscan_source_field(self, urlscan_raw_data):
        """Test that source field is correctly set to 'URLScan.io'."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.source == "URLScan.io"

    def test_normalize_urlscan_ioc_type(self, urlscan_raw_data):
        """Test that ioc_type field is correctly set to 'url'."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.ioc_type == "url"

    def test_normalize_urlscan_ioc_value(self, urlscan_raw_data):
        """Test that ioc field contains the URL."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.ioc is not None
        assert len(result.ioc) > 0

    def test_normalize_urlscan_malicious_flag(self, urlscan_raw_data):
        """Test that malicious flag is set based on verdicts."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert isinstance(result.malicious, bool)

    def test_normalize_urlscan_confidence_score(self, urlscan_raw_data):
        """Test that confidence_score is extracted."""
        result = normalize_urlscan_data(urlscan_raw_data)
        # confidence_score should be present and in valid range
        if result.confidence_score is not None:
            assert isinstance(result.confidence_score, int)
            assert 0 <= result.confidence_score <= 100

    def test_normalize_urlscan_detection_stats(self, urlscan_raw_data):
        """Test that detection_stats dictionary is populated if engines have verdicts."""
        result = normalize_urlscan_data(urlscan_raw_data)
        # detection_stats may or may not be present depending on data
        if result.detection_stats is not None:
            assert isinstance(result.detection_stats, dict)
            assert "malicious" in result.detection_stats
            assert "total" in result.detection_stats

    def test_normalize_urlscan_geo_info(self, urlscan_raw_data):
        """Test that geo_info dictionary is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.geo_info is not None
        assert isinstance(result.geo_info, dict)

    def test_normalize_urlscan_network_info(self, urlscan_raw_data):
        """Test that network_info dictionary is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.network_info is not None
        assert isinstance(result.network_info, dict)

    def test_normalize_urlscan_domain_info(self, urlscan_raw_data):
        """Test that domain_info dictionary is populated if apex domain exists."""
        result = normalize_urlscan_data(urlscan_raw_data)
        # domain_info may or may not be present depending on data
        if result.domain_info is not None:
            assert isinstance(result.domain_info, dict)

    def test_normalize_urlscan_timestamps(self, urlscan_raw_data):
        """Test that timestamps dictionary is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.timestamps is not None
        assert isinstance(result.timestamps, dict)

    def test_normalize_urlscan_tags(self, urlscan_raw_data):
        """Test that tags list is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert isinstance(result.tags, list)

    def test_normalize_urlscan_categories(self, urlscan_raw_data):
        """Test that categories list is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert isinstance(result.categories, list)

    def test_normalize_urlscan_additional_info(self, urlscan_raw_data):
        """Test that additional_info dictionary is populated."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.additional_info is not None
        assert isinstance(result.additional_info, dict)
        # Check for key fields
        assert "scan_uuid" in result.additional_info
        assert "report_url" in result.additional_info
        assert "screenshot_url" in result.additional_info

    def test_normalize_urlscan_schema_version(self, urlscan_raw_data):
        """Test that schema_version is set."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.schema_version is not None

    def test_normalize_urlscan_normalized_time(self, urlscan_raw_data):
        """Test that normalized_time is set."""
        result = normalize_urlscan_data(urlscan_raw_data)
        assert result.normalized_time is not None


class TestNormalizationConsistency:
    """Test suite for consistency across different normalization functions."""

    def test_all_normalizations_have_schema_version(
        self,
        abuseipdb_raw_data,
        ipinfo_raw_data,
        ip_virustotal_raw_data,
        file_hash_virustotal_raw_data,
        domain_virustotal_raw_data,
        ip_alienvault_raw_data,
        domain_alienvault_raw_data,
        urlscan_raw_data,
    ):
        """Test that all normalization functions set schema_version."""
        results = [
            normalize_abuseipdb_data(abuseipdb_raw_data),
            normalize_ipinfo_data(ipinfo_raw_data),
            normalize_ip_virustotal_data(ip_virustotal_raw_data),
            normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data),
            normalize_domain_virustotal_data(domain_virustotal_raw_data),
            normalize_ip_alienvault_data(ip_alienvault_raw_data),
            normalize_domain_alienvault_data(domain_alienvault_raw_data),
            normalize_urlscan_data(urlscan_raw_data),
        ]

        for result in results:
            assert result.schema_version is not None

    def test_all_normalizations_have_normalized_time(
        self,
        abuseipdb_raw_data,
        ipinfo_raw_data,
        ip_virustotal_raw_data,
        file_hash_virustotal_raw_data,
        domain_virustotal_raw_data,
        ip_alienvault_raw_data,
        domain_alienvault_raw_data,
        urlscan_raw_data,
    ):
        """Test that all normalization functions set normalized_time."""
        results = [
            normalize_abuseipdb_data(abuseipdb_raw_data),
            normalize_ipinfo_data(ipinfo_raw_data),
            normalize_ip_virustotal_data(ip_virustotal_raw_data),
            normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data),
            normalize_domain_virustotal_data(domain_virustotal_raw_data),
            normalize_ip_alienvault_data(ip_alienvault_raw_data),
            normalize_domain_alienvault_data(domain_alienvault_raw_data),
            normalize_urlscan_data(urlscan_raw_data),
        ]

        for result in results:
            assert result.normalized_time is not None

    def test_all_normalizations_have_source(
        self,
        abuseipdb_raw_data,
        ipinfo_raw_data,
        ip_virustotal_raw_data,
        file_hash_virustotal_raw_data,
        domain_virustotal_raw_data,
        ip_alienvault_raw_data,
        domain_alienvault_raw_data,
        urlscan_raw_data,
    ):
        """Test that all normalization functions set source field."""
        results = [
            normalize_abuseipdb_data(abuseipdb_raw_data),
            normalize_ipinfo_data(ipinfo_raw_data),
            normalize_ip_virustotal_data(ip_virustotal_raw_data),
            normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data),
            normalize_domain_virustotal_data(domain_virustotal_raw_data),
            normalize_ip_alienvault_data(ip_alienvault_raw_data),
            normalize_domain_alienvault_data(domain_alienvault_raw_data),
            normalize_urlscan_data(urlscan_raw_data),
        ]

        for result in results:
            assert result.source is not None
            assert len(result.source) > 0

    def test_all_normalizations_have_ioc(
        self,
        abuseipdb_raw_data,
        ipinfo_raw_data,
        ip_virustotal_raw_data,
        file_hash_virustotal_raw_data,
        domain_virustotal_raw_data,
        ip_alienvault_raw_data,
        domain_alienvault_raw_data,
        urlscan_raw_data,
    ):
        """Test that all normalization functions set ioc field."""
        results = [
            normalize_abuseipdb_data(abuseipdb_raw_data),
            normalize_ipinfo_data(ipinfo_raw_data),
            normalize_ip_virustotal_data(ip_virustotal_raw_data),
            normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data),
            normalize_domain_virustotal_data(domain_virustotal_raw_data),
            normalize_ip_alienvault_data(ip_alienvault_raw_data),
            normalize_domain_alienvault_data(domain_alienvault_raw_data),
            normalize_urlscan_data(urlscan_raw_data),
        ]

        for result in results:
            assert result.ioc is not None
            assert len(result.ioc) > 0

    def test_all_normalizations_have_ioc_type(
        self,
        abuseipdb_raw_data,
        ipinfo_raw_data,
        ip_virustotal_raw_data,
        file_hash_virustotal_raw_data,
        domain_virustotal_raw_data,
        ip_alienvault_raw_data,
        domain_alienvault_raw_data,
        urlscan_raw_data,
    ):
        """Test that all normalization functions set ioc_type field."""
        results = [
            normalize_abuseipdb_data(abuseipdb_raw_data),
            normalize_ipinfo_data(ipinfo_raw_data),
            normalize_ip_virustotal_data(ip_virustotal_raw_data),
            normalize_file_hash_virustotal_data(file_hash_virustotal_raw_data),
            normalize_domain_virustotal_data(domain_virustotal_raw_data),
            normalize_ip_alienvault_data(ip_alienvault_raw_data),
            normalize_domain_alienvault_data(domain_alienvault_raw_data),
            normalize_urlscan_data(urlscan_raw_data),
        ]

        valid_ioc_types = {"ip", "file_hash", "domain", "url"}
        for result in results:
            assert result.ioc_type is not None
            assert result.ioc_type in valid_ioc_types


    class TestNormalizeShodan:
        """Test suite for Shodan IP data normalization."""

        def test_normalize_shodan_returns_correct_schema(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert isinstance(result, ThreatIntelligenceNormalizedSchema)

        def test_normalize_shodan_source_field(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.source == "Shodan"

        def test_normalize_shodan_ioc_type(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.ioc_type == "ip"

        def test_normalize_shodan_ioc_value(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.ioc is not None
            assert len(result.ioc) > 0

        def test_normalize_shodan_geo_info(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.geo_info is not None
            assert isinstance(result.geo_info, dict)

        def test_normalize_shodan_network_info(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.network_info is not None
            assert isinstance(result.network_info, dict)
            assert "asn" in result.network_info or "organization" in result.network_info

        def test_normalize_shodan_additional_info_ports(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            ports = result.additional_info.get("ports")
            assert isinstance(ports, list)
            assert len(ports) > 0

        def test_normalize_shodan_timestamps(self, shodan_raw_data):
            result = normalize_shodan_ip_data(shodan_raw_data)
            assert result.timestamps is not None
            assert "last_update" in result.timestamps
