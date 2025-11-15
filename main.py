#!/usr/bin/env python3
"""
main.py
Automated Risk Register generator:
- Reads assets.csv
- Parses a GVM XML report (gvm_report.xml)
- Maps each vulnerability to an asset by host IP
- Converts CVSS -> Likelihood
- Calculates Risk Score = Impact * Likelihood
- Produces risk_register.csv sorted by risk_score (desc)
"""

import csv
import xml.etree.ElementTree as ET
import sys

ASSETS_FILE = "assets.csv"
GVM_XML_FILE = "gvm_report.xml"   # rename the provided realistic XML to this name or update variable
OUTPUT_FILE = "risk_register.csv"

def load_assets(path):
    assets = {}
    try:
        with open(path, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip_address", "").strip()
                if not ip:
                    continue
                assets[ip] = {
                    "asset_name": row.get("asset_name", "").strip(),
                    "asset_owner": row.get("asset_owner", "").strip(),
                    "criticality": int(row.get("asset_criticality", "1").strip() or 1)
                }
    except FileNotFoundError:
        print(f"[ERROR] assets file not found: {path}")
        sys.exit(1)
    return assets

def cvss_to_likelihood(cvss):
    try:
        cv = float(cvss)
    except Exception:
        return 1
    if cv >= 7.0:
        return 5
    elif cv >= 4.0:
        return 3
    elif cv > 0:
        return 1
    else:
        return 1

def parse_gvm_xml(path):
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        print(f"[ERROR] GVM XML file not found: {path}")
        sys.exit(1)
    root = tree.getroot()

    # Search for <result> elements anywhere (robust to schema variants)
    results = root.findall('.//{http://www.greenbone.net/schema/report/2.0}result')
    if not results:
        # fallback to no-namespace tag
        results = root.findall('.//result')

    parsed = []
    for r in results:
        # name
        name = r.findtext('{http://www.greenbone.net/schema/report/2.0}name') or r.findtext('name') or r.findtext('.//name') or 'Unknown Vulnerability'

        # host
        host = r.findtext('{http://www.greenbone.net/schema/report/2.0}host') or r.findtext('host') or r.findtext('.//host')

        # cvss: try multiple paths
        cvss = None
        cvss_node = r.find('.//{http://www.greenbone.net/schema/report/2.0}cvss_base')
        if cvss_node is None:
            cvss_node = r.find('.//cvss_base')
        if cvss_node is not None and cvss_node.text:
            cvss = cvss_node.text.strip()
        else:
            # try nested cvss/base
            cvss_node2 = r.find('.//{http://www.greenbone.net/schema/report/2.0}cvss')
            if cvss_node2 is not None and cvss_node2.text:
                cvss = cvss_node2.text.strip()
        if not cvss:
            # fallback
            cvss = r.findtext('.//cvss_base') or r.findtext('.//cvss') or "0.0"

        # description
        desc = r.findtext('{http://www.greenbone.net/schema/report/2.0}description') or r.findtext('description') or ""

        parsed.append({
            "host": (host or "").strip(),
            "name": name.strip(),
            "cvss": (cvss or "0.0").strip(),
            "description": (desc or "").strip()
        })
    return parsed

def build_risk_register(assets, vulns):
    entries = []
    for v in vulns:
        host = v.get('host')
        if not host or host not in assets:
            continue
        asset = assets[host]
        impact = asset.get('criticality', 1)
        likelihood = cvss_to_likelihood(v.get('cvss', '0.0'))
        risk_score = impact * likelihood

        entries.append({
            'asset_name': asset.get('asset_name'),
            'ip_address': host,
            'vulnerability_name': v.get('name'),
            'cvss_score': v.get('cvss'),
            'impact': impact,
            'likelihood': likelihood,
            'risk_score': risk_score,
            'description': v.get('description')
        })
    entries.sort(key=lambda x: x['risk_score'], reverse=True)
    return entries

def write_csv(path, entries):
    fields = ['asset_name', 'ip_address', 'vulnerability_name',
              'cvss_score', 'impact', 'likelihood', 'risk_score', 'description']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(entries)
    print(f"[OK] Wrote {len(entries)} entries to {path}")

def main():
    assets = load_assets(ASSETS_FILE)
    print(f"[INFO] Loaded {len(assets)} assets.")
    vulns = parse_gvm_xml(GVM_XML_FILE)
    print(f"[INFO] Parsed {len(vulns)} vulnerability results from XML.")
    register = build_risk_register(assets, vulns)
    write_csv(OUTPUT_FILE, register)

if __name__ == '__main__':
    main()
