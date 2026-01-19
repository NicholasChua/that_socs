#!/usr/bin/env python3
import argparse
import helper_functions.retrieve_threat_intelligence as rti
import helper_functions.normalize_threat_intelligence as nti
from helper_functions.enrich_threat_intelligence import combined_enrichment


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Data Retrieval, Normalization, and Enrichment"
    )
    parser.add_argument(
        "ioc_type",
        choices=["ip", "file_hash", "domain", "url"],
        help="Type of IOC to query",
    )
    parser.add_argument("ioc_value", help="Value of the IOC to query")
    args = parser.parse_args()
    ioc_type = args.ioc_type
    ioc_value = args.ioc_value

    # Initialize clients
    vt_client = rti.VirusTotalClient()
    abuse_client = rti.AbuseIPDBClient()
    ipinfo_client = rti.IPInfoClient()
    alienvault_client = rti.AlienVaultClient()
    urlscan_client = rti.URLScanClient()
    shodan_client = rti.ShodanClient()

    # Retrieve data based on IOC type
    if ioc_type == "ip":
        vt_data = vt_client.fetch_ip(ioc_value)
        abuse_data = abuse_client.fetch_ip(ioc_value)
        ipinfo_data = ipinfo_client.fetch_ip(ioc_value)
        alienvault_data = alienvault_client.fetch_ip(ioc_value)
        shodan_data = shodan_client.fetch_ip(ioc_value)
    elif ioc_type == "file_hash":
        vt_data = vt_client.fetch_file(ioc_value)
    elif ioc_type == "domain":
        vt_data = vt_client.fetch_domain(ioc_value)
        alienvault_data = alienvault_client.fetch_domain(ioc_value)
    elif ioc_type == "url":
        scan_id = urlscan_client.submit_url(ioc_value)
        urlscan_data = urlscan_client.fetch_url_scan_result(scan_id)
    else:
        print("Unsupported IOC type.")
        return

    # Normalize and enrich data
    if ioc_type == "ip":
        vt_normalized = nti.normalize_ip_virustotal_data(vt_data)
        abuseipdb_normalized = nti.normalize_abuseipdb_data(abuse_data)
        ipinfo_normalized = nti.normalize_ipinfo_data(ipinfo_data)
        alienvault_normalized = nti.normalize_ip_alienvault_data(alienvault_data)
        shodan_normalized = nti.normalize_shodan_ip_data(shodan_data)
        enriched_comment = combined_enrichment(
            ip_virustotal_data=vt_normalized,
            abuseipdb_data=abuseipdb_normalized,
            ipinfo_data=ipinfo_normalized,
            ip_alienvault_data=alienvault_normalized,
            shodan_data=shodan_normalized,
        )
    elif ioc_type == "file_hash":
        file_hash_virustotal_data = nti.normalize_file_hash_virustotal_data(vt_data)
        enriched_comment = combined_enrichment(file_hash_virustotal_data=file_hash_virustotal_data)
    elif ioc_type == "domain":
        vt_normalized = nti.normalize_domain_virustotal_data(vt_data)
        alienvault_normalized = nti.normalize_domain_alienvault_data(alienvault_data)
        enriched_comment = combined_enrichment(
            domain_virustotal_data=vt_normalized, domain_alienvault_data=alienvault_normalized
        )
    elif ioc_type == "url":
        urlscan_normalized = nti.normalize_urlscan_data(urlscan_data)
        enriched_comment = combined_enrichment(urlscan_data=urlscan_normalized)
    else:
        print("Unsupported IOC type for enrichment.")
        return

    # Output the enriched comment to text file and console
    with open(f"enriched_comment.txt", "w", encoding="utf-8") as f:
        f.write(enriched_comment)
    print(enriched_comment)


if __name__ == "__main__":
    main()
