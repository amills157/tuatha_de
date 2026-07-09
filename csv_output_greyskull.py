import os
import csv
import glob
import re
import argparse

severity_order = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Negligible": 5,
    "Unknown": 6
}

av_order = {
    "NETWORK": 1,
    "Unknown": 2,
    "LOCAL": 3
}

csv_file_name = "master_csv_output_vulnerabilities.csv"


def get_order(value, order_dict):
    value = (value or "").strip()
    for key in order_dict:
        if key in value:
            return order_dict[key]
    return order_dict["Unknown"]


def extract_ids(vuln_text):
    if not vuln_text:
        return []
    parts = re.split(r'[\n,]+', vuln_text)
    return [part.strip() for part in parts if part and part.strip()]


def canonical_vuln_id(vuln_text):
    ids = extract_ids(vuln_text)

    for prefix in ("CVE-", "GHSA-", "GO-"):
        for item in ids:
            if item.startswith(prefix):
                return item

    return ids[0] if ids else ""


def normalize_row(row):
    return {
        'Status': (row.get('Status') or '').strip(),
        'Vulnerability': (row.get('Vulnerability') or '').strip(),
        'Severity': (row.get('Severity') or 'Unknown').strip() or 'Unknown',
        'Attack Vector': (row.get('Attack Vector') or 'Unknown').strip() or 'Unknown',
        'Exploits': (row.get('Exploits') or '').strip(),
        'Description': (row.get('Description') or '').strip(),
        'Image': (row.get('Image') or '').strip(),
    }


def merge_preferred(existing_value, new_value):
    return existing_value if existing_value.strip() else new_value.strip()


def merge_richer_text(old_value, new_value):
    old_value = (old_value or "").strip()
    new_value = (new_value or "").strip()

    if old_value and not new_value:
        return old_value
    if new_value and not old_value:
        return new_value
    if len(old_value) >= len(new_value):
        return old_value
    return new_value


def combine_ids(existing_text, new_text):
    merged = []
    seen = set()

    for source in (existing_text, new_text):
        for vuln_id in extract_ids(source):
            if vuln_id not in seen:
                seen.add(vuln_id)
                merged.append(vuln_id)

    return "\n".join(merged)


def combine_multiline_unique(existing_text, new_text):
    values = []
    seen = set()

    for source in (existing_text, new_text):
        for item in (source or "").splitlines():
            item = item.strip()
            if item and item not in seen:
                seen.add(item)
                values.append(item)

    return "\n".join(values)


def combine_images(existing_images_text, image_name):
    images = [img.strip() for img in existing_images_text.splitlines() if img.strip()]
    if image_name not in images:
        images.append(image_name)
    return "\n".join(images)


def build_alias_map(rows_by_canon):
    alias_map = {}
    for canon_id, row in rows_by_canon.items():
        for vuln_id in extract_ids(row['Vulnerability']):
            alias_map[vuln_id] = canon_id
    return alias_map


def load_previous_master(path):
    previous_rows = {}

    if not os.path.exists(path):
        return previous_rows

    with open(path, mode='r', newline='') as master_file:
        reader = csv.DictReader(master_file)
        for row in reader:
            row = normalize_row(row)
            canon_id = canonical_vuln_id(row['Vulnerability'])
            if not canon_id:
                continue

            if canon_id in previous_rows:
                existing = previous_rows[canon_id]
                existing['Vulnerability'] = combine_ids(existing['Vulnerability'], row['Vulnerability'])
                existing['Severity'] = merge_preferred(existing['Severity'], row['Severity']) or 'Unknown'
                existing['Attack Vector'] = merge_preferred(existing['Attack Vector'], row['Attack Vector']) or 'Unknown'
                existing['Exploits'] = merge_richer_text(existing['Exploits'], row['Exploits'])
                existing['Description'] = merge_richer_text(existing['Description'], row['Description'])
                existing['Image'] = combine_multiline_unique(existing['Image'], row['Image'])
            else:
                previous_rows[canon_id] = row

    return previous_rows


def build_current_rows(csv_file_path, previous_alias_map):
    current_rows = {}
    alias_map = dict(previous_alias_map)
    current_seen_aliases = set()

    csv_files = glob.glob(os.path.join(csv_file_path, "*.csv"))

    for csv_file in csv_files:
        image_name = os.path.splitext(os.path.basename(csv_file))[0]

        with open(csv_file, mode='r', newline='') as file:
            reader = csv.DictReader(file)

            for row in reader:
                if '' in row:
                    del row['']

                row = normalize_row(row)
                row_ids = extract_ids(row['Vulnerability'])
                if not row_ids:
                    continue

                for vuln_id in row_ids:
                    current_seen_aliases.add(vuln_id)

                resolved_canon = None
                for vuln_id in row_ids:
                    if vuln_id in alias_map:
                        resolved_canon = alias_map[vuln_id]
                        break

                if not resolved_canon:
                    resolved_canon = canonical_vuln_id(row['Vulnerability'])

                if not resolved_canon:
                    continue

                if resolved_canon in current_rows:
                    existing = current_rows[resolved_canon]
                    existing['Vulnerability'] = combine_ids(existing['Vulnerability'], row['Vulnerability'])
                    existing['Severity'] = merge_preferred(existing['Severity'], row['Severity']) or 'Unknown'
                    existing['Attack Vector'] = merge_preferred(existing['Attack Vector'], row['Attack Vector']) or 'Unknown'
                    existing['Exploits'] = merge_richer_text(existing['Exploits'], row['Exploits'])
                    existing['Description'] = merge_richer_text(existing['Description'], row['Description'])
                    existing['Image'] = combine_images(existing['Image'], image_name)
                else:
                    row['Vulnerability'] = "\n".join(row_ids)
                    row['Image'] = image_name
                    current_rows[resolved_canon] = row

                for vuln_id in extract_ids(current_rows[resolved_canon]['Vulnerability']):
                    alias_map[vuln_id] = resolved_canon

    return current_rows, current_seen_aliases


def inherit_previous_metadata(current_rows, previous_rows):
    for canon_id, row in current_rows.items():
        if canon_id not in previous_rows:
            continue

        old_row = previous_rows[canon_id]

        row['Vulnerability'] = combine_ids(old_row['Vulnerability'], row['Vulnerability'])
        row['Severity'] = merge_preferred(old_row['Severity'], row['Severity']) or 'Unknown'
        row['Attack Vector'] = merge_preferred(old_row['Attack Vector'], row['Attack Vector']) or 'Unknown'
        row['Exploits'] = merge_richer_text(old_row['Exploits'], row['Exploits'])
        row['Description'] = merge_richer_text(old_row['Description'], row['Description'])


def build_raw_file_index(scan_root):
    """
    Load all raw scan files into memory once for fast substring checks.
    """
    raw_contents = []

    if not scan_root:
        return raw_contents

    for root, _, files in os.walk(scan_root):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_contents.append((full_path, f.read()))
            except Exception:
                pass

    return raw_contents


def ids_present_in_raw_scans(vuln_ids, raw_contents):
    """
    Return True if any vuln ID appears in any raw scan file.
    """
    for vuln_id in vuln_ids:
        for _, content in raw_contents:
            if vuln_id in content:
                return True
    return False


def merge_csv_files(output_file, csv_file_path, raw_scan_path=None):
    previous_rows = load_previous_master(csv_file_name)
    previous_alias_map = build_alias_map(previous_rows)

    current_rows, current_seen_aliases = build_current_rows(csv_file_path, previous_alias_map)

    inherit_previous_metadata(current_rows, previous_rows)

    raw_contents = build_raw_file_index(raw_scan_path)

    previous_canon_ids = set(previous_rows.keys())
    output_rows = []

    # Current rows
    for canon_id, row in current_rows.items():
        row = normalize_row(row)
        if canon_id in previous_canon_ids:
            row['Status'] = 'No-Change'
        else:
            row['Status'] = 'Added'
        output_rows.append(row)

    # Removed rows with raw scan double-check
    for canon_id, old_row in previous_rows.items():
        old_aliases = set(extract_ids(old_row['Vulnerability']))

        # If present in current csv-derived set, not removed
        if old_aliases & current_seen_aliases:
            continue

        # Double-check against raw scan files
        if raw_contents and ids_present_in_raw_scans(old_aliases, raw_contents):
            continue

        removed_row = normalize_row(old_row)
        removed_row['Status'] = 'Removed'
        removed_row['Image'] = ''
        output_rows.append(removed_row)

    output_rows.sort(
        key=lambda x: (
            get_order(x['Severity'], severity_order),
            get_order(x['Attack Vector'], av_order),
            canonical_vuln_id(x['Vulnerability'])
        )
    )

    with open(output_file, mode='w', newline='') as master_file:
        fieldnames = ['Status', 'Vulnerability', 'Severity', 'Attack Vector', 'Exploits', 'Description', 'Image']
        writer = csv.DictWriter(master_file, fieldnames=fieldnames)

        writer.writeheader()
        for row in output_rows:
            writer.writerow(row)

    print(f"Master CSV created: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Create a master file for image vulnerabilities")
    parser.add_argument('csv_file_path', help="File path for csv files (input)")
    parser.add_argument(
        'raw_scan_path',
        nargs='?',
        default=None,
        help="Optional path to raw scan files for removed-entry double checking"
    )
    args = parser.parse_args()

    merge_csv_files(csv_file_name, args.csv_file_path, args.raw_scan_path)


if __name__ == "__main__":
    main()