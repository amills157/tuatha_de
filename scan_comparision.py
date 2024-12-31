import argparse
import csv
import re

# List of vulnerability types with specific regex patterns, now matching any trailing word for severity.
vuln_patterns = {
    "CVE": r'CVE-\d{4}-\d{4,7}_\w+',
    "ALAS": r'ALAS-\d{4}-\d+_\w+',
    "ALAS2": r'ALAS2-\d{4}-\d+_\w+',
    "BugTraq": r'BugTraq-\d+_\w+',
    "CWE": r'CWE-\d+_\w+',
    "DLA": r'DLA-\d+_\w+',
    "EBID": r'EBID-\d+_\w+',
    "ELSA": r'ELSA-\d{4}-\d+_\w+',
    "GHSA": r'GHSA-[\w-]+_\w+',
    "GMS": r'GMS-\d{4}-\d+_\w+',
    "RHSA": r'RHSA-\d{4}:\d+_\w+',
    "VULNDB": r'VULNDB-\d+_\w+',
    "SUSE-SU": r'SUSE-SU-\d+:\d+_\w+',
    "GO": r'GO-\d{4}-\d+_\w+'
}

# Function to extract vulnerabilities using multiple regex patterns from the HTML content
def extract_vulnerabilities(html_file):
    with open(html_file, 'r') as file:
        content = file.read()
        vuln_matches = set()  # Use a set to avoid duplicates

        # Apply each regex pattern and add results to vuln_matches
        for vuln_type, pattern in vuln_patterns.items():
            matches = re.findall(pattern, content)
            vuln_matches.update(matches)
        
        print(f"Found {len(vuln_matches)} vulnerabilities in {html_file}")
        return {vuln: {"description": f"Details for {vuln}"} for vuln in vuln_matches}

# Function to compare old and new scans
def compare_scans(old_scan, new_scan):
    added = {key: val for key, val in new_scan.items() if key not in old_scan}
    removed = {key: val for key, val in old_scan.items() if key not in new_scan}
    return added, removed

# Function to generate CSV report
def generate_csv_report(added, removed, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write the headers
        writer.writerow(["Change Type", "Vulnerability ID", "Description"])

        # Write added vulnerabilities
        for vuln_id, vuln in added.items():
            writer.writerow(["Added", vuln_id, vuln['description']])

        # Write removed vulnerabilities
        for vuln_id, vuln in removed.items():
            writer.writerow(["Removed", vuln_id, vuln['description']])

    print(f"Added vulnerabilities: {len(added)}")
    print(f"Removed vulnerabilities: {len(removed)}")

# Main function to handle argument parsing and running the comparison
def main():
    parser = argparse.ArgumentParser(description="Compare two HTML vulnerability scan reports and output differences to a CSV file.")
    parser.add_argument('old_scan', help="File path for the old HTML scan report.")
    parser.add_argument('new_scan', help="File path for the new HTML scan report.")
    parser.add_argument('output_csv', help="File path for the output CSV file.")

    args = parser.parse_args()

    # Extract vulnerabilities from old and new scans
    old_scan_data = extract_vulnerabilities(args.old_scan)
    new_scan_data = extract_vulnerabilities(args.new_scan)

    # Compare the scans and generate CSV report
    added, removed = compare_scans(old_scan_data, new_scan_data)
    generate_csv_report(added, removed, args.output_csv)
    print(f"Comparison complete. Report saved to {args.output_csv}")

if __name__ == "__main__":
    main()
