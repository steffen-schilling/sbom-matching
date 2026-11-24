"""Show the NVD processing status and the CPE applicability rules
for one or more CVEs.

Usage: python investigations/nvd_cve_details.py CVE-2024-35195 CVE-2021-33203
"""

import sys
import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY_SECONDS = 6


def main():
    cve_ids = sys.argv[1:]
    if not cve_ids:
        print("Usage: python investigations/nvd_cve_details.py <CVE-ID> [<CVE-ID> ...]")
        sys.exit(1)

    for cve_id in cve_ids:
        response = requests.get(NVD_URL, params={"cveId": cve_id})
        results = response.json()["vulnerabilities"]

        if not results:
            print(cve_id, "- not found at NVD")
        else:
            cve = results[0]["cve"]
            print(cve_id, "-", cve["vulnStatus"])

            configurations = cve.get("configurations", [])
            if not configurations:
                print("    no CPE applicability rules")
            for configuration in configurations:
                for node in configuration["nodes"]:
                    for rule in node["cpeMatch"]:
                        print("   ", rule)

        print()
        time.sleep(NVD_DELAY_SECONDS)


if __name__ == "__main__":
    main()