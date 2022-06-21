import os
import json
import requests
import pandas as pd

input_file = "dh157_research_images_geonetwork-4_2_0.json"

f = open(input_file)

data = json.load(f)

package_list = []

cve_list = []

edges_list = []

fixed_package_list = []

container_os = ""

container_os = data["Metadata"]["OS"]["Family"]

print(container_os)

for i in data["Results"]:
    if "Vulnerabilities" in i.keys():
        for cve in i["Vulnerabilities"]:

            fixed_version = "None"

            current_version = cve["InstalledVersion"]

            if "FixedVersion" in cve.keys():

                fixed_version = cve["FixedVersion"]

                if "," in fixed_version:
                    split_str = fixed_version.split(",")
                    fixed_ver_list = [item.replace(">", "").replace("=","").replace("~","").replace("v","") for item in split_str if not "<" in item]
                    if any(":" in item for item in fixed_ver_list):
                        fixed_ver_list = [item.split(":")[1] for item in fixed_ver_list]
                    major_version_list = [item.split(".")[0].strip() for item in fixed_ver_list if item.split(".")[0].strip() != ""]

                    current_major = current_version.split(".")[0].replace("v","")

                    if current_major in major_version_list:
                        idx = major_version_list.index(current_major)
                        fixed_version = fixed_ver_list[idx].strip()
                    else:
                        num_current_major = int(current_major)
                        num_major_version_list = list(map(int, major_version_list))
                        
                        nearest_current = num_major_version_list[min(range(len(num_major_version_list)), key = lambda i: abs(num_major_version_list[i]-num_current_major))]

                        idx = major_version_list.index(str(nearest_current))
                        fixed_version = fixed_ver_list[idx].strip()
                else:
                    fixed_version = fixed_version.replace(">", "").replace("=","").replace("~","").strip()

                if ":" in fixed_version:
                    fixed_version = fixed_version.split(":")[1]

            fixed_package_list.append(cve["PkgName"] + "=" + fixed_version)

            #installed_pkg = cve["PkgName"] + "_" + cve["InstalledVersion"]

            #package_list.append(installed_pkg)
            
            #cve_list.append(cve["VulnerabilityID"])

            #edges_list.append(installed_pkg + ' ' + cve["VulnerabilityID"])


#unique_pkgs = list(set(package_list))

#unique_cves = list(set(cve_list))

#print(unique_pkgs)

print(fixed_package_list)