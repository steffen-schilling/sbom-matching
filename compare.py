"""Compare known vulnerabilities from OSV (queried by PURL) and
NVD (queried by CPE) for all components in a CycloneDX SBOM."""

import json
import sys
import time

import requests

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY_SECONDS = 6
NVD_MAX_ATTEMPTS = 3

# Known corrections: PURL without version -> correct CPE prefix without version
CPE_CORRECTIONS = {
    "pkg:pypi/django": "cpe:2.3:a:djangoproject:django",
}


def load_components(sbom_path):
    with open(sbom_path) as file:
        sbom = json.load(file)
    return sbom["components"]


def osv_cves(purl):
    response = requests.post(OSV_URL, json={"package": {"purl": purl}})
    cves = set()
    for vuln in response.json().get("vulns", []):
        for name in [vuln["id"]] + vuln.get("aliases", []):
            if name.startswith("CVE-"):
                cves.add(name)
    return cves


def nvd_cves(cpe):
    for attempt in range(NVD_MAX_ATTEMPTS):
        response = requests.get(NVD_URL, params={"cpeName": cpe})
        time.sleep(NVD_DELAY_SECONDS)
        if response.status_code == 200:
            cves = set()
            for item in response.json()["vulnerabilities"]:
                cves.add(item["cve"]["id"])
            return cves
    return None


def choose_cpe(component):
    purl_without_version = component["purl"].split("@")[0]
    if purl_without_version in CPE_CORRECTIONS:
        prefix = CPE_CORRECTIONS[purl_without_version]
        return prefix + ":" + component["version"] + ":*:*:*:*:*:*:*"
    return component.get("cpe")


def main():
    if len(sys.argv) != 2:
        print("Usage: python compare.py <path/to/sbom.json>")
        sys.exit(1)

    for component in load_components(sys.argv[1]):
        if "purl" not in component:
            continue

        print(component["name"], component["version"])

        cpe = choose_cpe(component)
        if cpe is None:
            print("  no CPE, NVD not queryable")
            continue

        osv = osv_cves(component["purl"])
        nvd = nvd_cves(cpe)

        if nvd is None:
            print("  NVD not reachable, no comparison possible")
            continue

        print("  OSV:", len(osv), "  NVD:", len(nvd))
        print("  both:", len(osv & nvd))
        print("  only OSV:", sorted(osv - nvd))
        print("  only NVD:", sorted(nvd - osv))


if __name__ == "__main__":
    main()