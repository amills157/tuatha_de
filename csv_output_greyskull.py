import os
import csv
import glob
import argparse

# Define severity order for sorting
severity_order = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Negligible": 5,
    "Unknown": 6
}

# Define severity order for sorting
av_order = {
    "NETWORK": 1,
    "Unknown": 2,
    "LOCAL": 3
}

csv_file_name = "master_csv_output_vulnerabilities.csv"

def get_severity(severity_id, severity_dict):
    for key in severity_dict:
        if f"{key}" in severity_id:
            return severity_dict[key]
    return severity_dict["Unknown"]


def merge_csv_files(output_file, csv_file_path):

    master_data = []

    if os.path.exists(csv_file_name):
        with open(csv_file_name, mode='r') as master_file:
            reader = csv.DictReader(master_file)
            for row in reader:
                row['Status'] = ''
                row['Image'] = ''
                master_data.append(row)

    # Get all CSV files in the current directory (or specify a different directory)
    csv_files = glob.glob(csv_file_path + "/*.csv")
    seen_vulnerabilities = set()

    for csv_file in csv_files:
        with open(csv_file, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                del row['']
                # Create a unique key based on Vulnerability ID
                cve = row['Vulnerability']
                seen_vulnerabilities.add(cve)

                # Add image (CSV file name without extension) to the row data
                image_name = os.path.splitext(os.path.basename(csv_file))[0]

                existing = next((entry for entry in master_data if entry['Vulnerability'] == row['Vulnerability']), None)

                if existing:
                    # If the vulnerability already exists, append the new file name to the 'image' field
                    if existing['Image'] == "":
                        existing['Image'] += f"{image_name}"
                    else:
                        existing['Image'] += f"\n{image_name}"
                    existing['Status'] = 'No-Change'
                else:
                    # If it's a new vulnerability, add the row and initialize the 'image' field
                    row['Image'] = image_name
                    row['Status'] = 'Added'
                    master_data.append(row)
                
    
    for row in master_data:
        if row['Vulnerability'] not in seen_vulnerabilities:
            row['Status'] = 'Removed'

    # Sort the data: first by severity, then by attack vector and finally vuln
    master_data.sort(key=lambda x: (get_severity(x['Severity'], severity_order), get_severity(x['Attack Vector'], av_order), x['Vulnerability']))

    # Write the master CSV file
    with open(output_file, mode='w', newline='') as master_file:
        fieldnames = ['Status', 'Vulnerability','Severity','Attack Vector','Exploits','Description', 'Image']
        writer = csv.DictWriter(master_file, fieldnames=fieldnames)

        writer.writeheader()
        for row in master_data:
            writer.writerow(row)

    print(f"Master CSV created: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Create a master file for image vulnerabilities")
    parser.add_argument('csv_file_path', help="File path for csv files (input)")

    args = parser.parse_args()

    merge_csv_files(csv_file_name, args.csv_file_path)

if __name__ == "__main__":
    main()