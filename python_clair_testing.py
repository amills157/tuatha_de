import os
import re
import json
import requests
import pandas as pd
import cve_searchsploit as CS

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

def clair_formater(input_file):

    if os.stat(input_file).st_size == 0:
        return

    f = open(input_file)

    data = json.load(f)

    package_list = []
    cve_list = []

    edges_list =[]

    if "unapproved" in data:
        print("Old")
    else:

        for _, vuln_id in data["vulnerabilities"].items():
            
            if vuln_id["package"]["version"] != "":
                pkg = vuln_id["package"]["name"]+'_'+vuln_id["package"]["version"]
            else:
                pkg = vuln_id["package"]["name"]

            match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", vuln_id["links"])
            if match:
                    cve = match.group()

            sev = vuln_id["severity"]

            vuln = cve+"_"+sev

            print(f"{pkg} {vuln}")

    
    #for i in data["vulnerabilities"]:
        
    #     pkg = i["featurename"]+'_'+i["featureversion"]
    #     cve = i["vulnerability"] + '_' + i["severity"]
    #     package_list.append(pkg)
    #     cve_list.append(cve)
    #     edges_list.append(pkg + ' ' + cve)

    # unique_pkgs = list(set(package_list))

    # unique_cves = list(set(cve_list))

    # node_list = unique_pkgs + unique_cves

clair_formater("quay_io_vqcomms_conferencemanager_4_1_1.json")