"""Check whether the NVD returns different CVEs for different spellings
of the same version (e.g. "3.2" and "3.2.0").

Usage: python investigations/nvd_version_spelling.py cpe:2.3:a:djangoproject:django 3.2 3.2.0
"""

import sys
import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY_SECONDS = 6


def nvd_cves(cpe):
    response = requests.get(NVD_URL, params={"cpeName": cpe})
    time.sleep(NVD_DELAY_SECONDS)
    if response.status_code != 200:
        return None
    return {item["cve"]["id"] for item in response.json()["vulnerabilities"]}


def main():
    if len(sys.argv) != 4:
        print("Usage: python investigations/nvd_version_spelling.py <cpe-prefix> <version-a> <version-b>")
        sys.exit(1)

    prefix, version_a, version_b = sys.argv[1], sys.argv[2], sys.argv[3]

    cves_a = nvd_cves(prefix + ":" + version_a + ":*:*:*:*:*:*:*")
    cves_b = nvd_cves(prefix + ":" + version_b + ":*:*:*:*:*:*:*")

    if cves_a is None or cves_b is None:
        print("NVD not reachable or CPE not accepted")
        sys.exit(1)

    print(version_a, "->", len(cves_a), "CVEs")
    print(version_b, "->", len(cves_b), "CVEs")
    print("only with", version_a + ":", sorted(cves_a - cves_b))
    print("only with", version_b + ":", sorted(cves_b - cves_a))


if __name__ == "__main__":
    main()