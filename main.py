#!/usr/bin/env python3
import argparse
from helper_functions.common_functions import InvestigationClient


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

    # Retrieve data based on IOC type using InvestigationClient
    if ioc_type == "ip":
        client = InvestigationClient()
        comment = client.full_ip_investigation(ioc_value = ioc_value)
    elif ioc_type == "file_hash":
        client = InvestigationClient(virustotal=True)
        comment = client.full_file_hash_investigation(ioc_value = ioc_value)
    elif ioc_type == "domain":
        client = InvestigationClient(virustotal=True, alienvault=True)
        comment = client.full_domain_investigation(ioc_value = ioc_value)
    elif ioc_type == "url":
        client = InvestigationClient(urlscan=True)
        comment = client.full_url_investigation(ioc_value = ioc_value)

    # Output the enriched comment to text file and console
    with open(f"enriched_comment.txt", "w", encoding="utf-8") as f:
        f.write(comment)
    print(comment)


if __name__ == "__main__":
    main()
