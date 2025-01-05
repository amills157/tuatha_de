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

def get_severity(vuln_id):
    for severity in severity_order:
        if f"_{severity}" in vuln_id:
            return severity_order[severity]
    return severity_order["Unknown"]

def merge_csv_files(output_file, comparision_reports_file_path):
    master_data = []

    # Get all CSV files in the current directory (or specify a different directory)
    csv_files = glob.glob(comparision_reports_file_path + "/*.csv")

    for csv_file in csv_files:
        with open(csv_file, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # Create a unique key based on Vulnerability ID and Change Type
                key = (row['Vulnerability ID'], row['Change Type'])

                # Add image (CSV file name without extension) to the row data
                image_name = os.path.splitext(csv_file)[0]

                # Check if this vulnerability already exists in master_data
                existing = next((entry for entry in master_data if entry['Vulnerability ID'] == row['Vulnerability ID'] and entry['Change Type'] == row['Change Type']), None)

                if existing:
                    # If the vulnerability already exists, append the new file name to the 'image' field
                    existing['image'] += f" {image_name}"
                else:
                    # If it's a new vulnerability, add the row and initialize the 'image' field
                    row['image'] = image_name
                    master_data.append(row)

    # Sort the data: first by Change Type (Added first, Removed second), then by severity
    master_data.sort(key=lambda x: (x['Change Type'], get_severity(x['Vulnerability ID'])))

    # Write the master CSV file
    with open(output_file, mode='w', newline='') as master_file:
        fieldnames = ['Change Type', 'Vulnerability ID', 'Description', 'Image']
        writer = csv.DictWriter(master_file, fieldnames=fieldnames)

        writer.writeheader()
        for row in master_data:
            writer.writerow(row)

    print(f"Master CSV created: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Create a master file for image vulnerabilities")
    parser.add_argument('comparision_reports_file_path', help="File path for csv files (input)")

    args = parser.parse_args()

    merge_csv_files("master_comparision_vulnerabilities.csv", args.comparision_reports_file_path)

if __name__ == "__main__":
    main()