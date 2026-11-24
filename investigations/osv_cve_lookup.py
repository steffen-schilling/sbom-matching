"""Look up a CVE in OSV: directly by its ID, and optionally through a
package query (PURL) to see whether OSV links it to that package.

Usage: python investigations/osv_cve_lookup.py CVE-2026-6873 pkg:pypi/django@5.2
"""

import sys

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def print_ranges(affected_entry):
    for version_range in affected_entry.get("ranges", []):
        print("      ", version_range.get("type"), version_range.get("events"))


def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: python investigations/osv_cve_lookup.py <CVE-ID> [<purl>]")
        sys.exit(1)

    cve_id = sys.argv[1]

    # 1. Direct lookup by ID
    response = requests.get(OSV_VULN_URL + cve_id)
    print("Direct lookup, status:", response.status_code)
    if response.status_code == 200:
        entry = response.json()
        print("  summary:", entry.get("summary", "-"))
        for affected in entry.get("affected", []):
            print("  affected package:", affected.get("package", "none"))
            print_ranges(affected)

    # 2. Optional: does OSV link the CVE to this package?
    if len(sys.argv) == 3:
        purl = sys.argv[2]
        response = requests.post(OSV_QUERY_URL, json={"package": {"purl": purl}})
        found = False
        for vuln in response.json().get("vulns", []):
            names = [vuln["id"]] + vuln.get("aliases", [])
            if cve_id in names:
                found = True
                print("Found via", purl + ":", vuln["id"], names)
                for affected in vuln.get("affected", []):
                    print_ranges(affected)
        if not found:
            print("Not linked to", purl, "in OSV")


if __name__ == "__main__":
    main()