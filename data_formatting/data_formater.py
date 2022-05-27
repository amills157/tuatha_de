import os
import json
import requests
import pandas as pd
import cve_searchsploit as CS

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

pd.options.mode.chained_assignment = None


# Need to change this to use the database as per ploting scripts
def get_cve_severity(cve):

    r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/"+cve)

    severity = "Unknown"

    try:
        severity = r.json()["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
    except KeyError as e:
        # NSIT doesn't yet have vuln data - normally means the CVE is still reserved
        if str(e) == "'result'":
            pass
        # It's an older CVE sir, but it checks out
        else:
            severity = r.json()["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
    
    return severity

def write_node_list(node_list,file_out):

    dir_check = os.path.dirname(file_out)

    if not os.path.isdir(dir_check):
        os.makedirs(dir_check)

    output_file = os.path.join("{}_nodes.txt".format(file_out))

    file=open(output_file,'w')
    for items in node_list:
        file.writelines([items+'\n'])

    file.close()

def write_edge_list(edges_list,file_out):

    dir_check = os.path.dirname(file_out)

    if not os.path.isdir(dir_check):
        os.makedirs(dir_check)

    output_file = os.path.join("{}_edges.txt".format(file_out))

    file=open(output_file,'w')
    for items in edges_list:
        file.writelines([items+'\n'])

    file.close()

def clair_formater(input_file,output_path,container_name):

    if os.stat(input_file).st_size == 0:
        return

    f = open(input_file)

    data = json.load(f)

    package_list = []
    cve_list = []

    edges_list =[]
    
    for i in data["vulnerabilities"]:
        pkg = i["featurename"]+'_'+i["featureversion"]
        cve = i["vulnerability"] + '_' + i["severity"]
        package_list.append(pkg)
        cve_list.append(cve)
        edges_list.append(pkg + ' ' + cve)

    unique_pkgs = list(set(package_list))

    unique_cves = list(set(cve_list))

    node_list = unique_pkgs + unique_cves

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)
    
    for pkg in unique_pkgs:
        temp = container_name.upper() + ' ' + pkg
        edges_list.append(temp)

    write_edge_list(edges_list,output_path)


def dagda_formater(input_file,output_path,container_name):

    f = open(input_file)

    data = json.load(f)

    malware_list = data[0]["static_analysis"]["malware_binaries"]

    malware_count = len(malware_list)

    package_list = []
    cve_list = []

    edges_list = []

    for i in data[0]["static_analysis"]["os_packages"]["os_packages_details"]:
        if len(i["vulnerabilities"]) > 0:
            pkg = i["product"] + "_" + i["version"]
            package_list.append(pkg)
            for j in i["vulnerabilities"]:
                for key, val in j.items():
                    if "CVE" in key:
                        cve = str(key)
                    else:
                        if "cve" in val:
                            if len(val["cve"])>0:
                                cve=val["cve"][0]
                            else:
                                cve="BugTraqID:" + str(val["bugtraq_id"])
                        elif "exploit_db_id" in val:
                            edbid=val["exploit_db_id"]
                            try:
                                cve = CS.cve_from_edbid(edbid)[0]
                            except IndexError as e:
                                cve = "N/A"
                    
                    if cve != "N/A":
                        sev = get_cve_severity(cve)
                        sev_cc = sev.capitalize()
                        cve = cve+"_"+sev_cc
                    else:
                        cve = "EBID:" + str(edbid)+"_Unknown"
                            
                    cve_list.append(cve)
                    edges_list.append(pkg + ' ' + cve)

    
    unique_pkgs = list(set(package_list))

    unique_cves = list(set(cve_list))

    node_list = unique_pkgs + unique_cves
    
    if malware_count >0:
        for malware_bin in malware_list:
            node_list.append(malware_bin)
    
    node_list.append(str(malware_count))

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)

    for pkg in unique_pkgs:
        temp = container_name.upper() + ' ' + pkg
        edges_list.append(temp)

    write_edge_list(list(set(edges_list)),output_path)


def grype_formater(input_file,output_path, container_name):

    df = pd.read_csv(input_file, sep=r'\s{2,}', engine='python')

    if "No vulnerabilities found" in df.columns:
        return

    # FIXED-IN     VULNERABILITY     SEVERITY

    if None in df['SEVERITY'].values:

        for idx, row in df.iterrows():
            if row['SEVERITY'] is None:
                df.loc[idx, 'SEVERITY'] = df.loc[idx, 'VULNERABILITY']
                df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'FIXED-IN']
                df.loc[idx, 'FIXED-IN'] = None
                

    if df['SEVERITY'].isna().all():
        for idx, row in df.iterrows():
            df.loc[idx, 'SEVERITY'] = df.loc[idx, 'VULNERABILITY']
            df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'FIXED-IN']
            df.loc[idx, 'FIXED-IN'] = None

    # If after the above fix we still have issues it's related to the installed value
    if None in df['SEVERITY'].values:
        for idx, row in df.iterrows():
            if row['SEVERITY'] is None:
                df.loc[idx, 'SEVERITY'] = df.loc[idx, 'VULNERABILITY']
                df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'INSTALLED']
                df.loc[idx, 'INSTALLED'] = ''
                df.loc[idx, 'FIXED-IN'] = None

    for idx, row in df.iterrows():
        if row['FIXED-IN'] and "won't fix" in row['FIXED-IN']:
            row['SEVERITY'] = "{}_NOFIX".format(row['SEVERITY'])
    
    df = df.drop(['FIXED-IN'], axis = 1)

    df['PACKAGE'] = df['NAME'] + "_" + df['INSTALLED']

    df['VULNERABILITY'] = df['VULNERABILITY'] + "_" +  df['SEVERITY']

    df = df[['PACKAGE', 'VULNERABILITY']]

    #with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    #    print(df)

    package_list = df['PACKAGE'].unique().tolist()

    cve_list = df['VULNERABILITY'].unique().tolist()

    node_list = package_list + cve_list

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)

    edges_list = []

    for idx, row in df.iterrows():
        temp = "{} {}".format(row['PACKAGE'],row['VULNERABILITY'])
        edges_list.append(temp)
    
    for pkg in package_list:
        temp = "{} {}".format(container_name.upper(),pkg)
        edges_list.append(temp)

    write_edge_list(edges_list,output_path)


def trivy_formater(input_file,output_path,container_name):

    f = open(input_file,"r")
    lines = f.readlines()
    f.close()

    file=open("temp",'w')
    for line in lines:
        if "-+-" in line or "|" not in line:
            continue
        else:
            file.writelines([line])

    file.close()

    try:
        df = pd.read_csv("temp", sep="|", engine='python')
    except pd.errors.EmptyDataError as e:
        return

    os.remove("temp")

    current_pkg = ""

    current_sev = ""

    df = df.rename(columns=lambda x: x.strip())

    df = df[df["VULNERABILITY ID"].notna()]

    df = df.drop(["Unnamed: 0"], axis=1)

    for idx, row in df.iterrows():

        if row["VULNERABILITY ID"].strip() == "":
            df.drop(idx, inplace=True)
        # Instances where there are multiple reports and we end up with row headers in df
        elif row["VULNERABILITY ID"].strip() == "VULNERABILITY ID":
            df.drop(idx, inplace=True)
        else:
            cve = row["VULNERABILITY ID"].strip()
            if row["SEVERITY"].strip() != "":
                current_sev = row["SEVERITY"].strip()
            sev_cc = current_sev[0] + current_sev[1:].lower()
            df.loc[idx,"VULNERABILITY ID"]= cve + "_" + sev_cc

    for idx, row in df.iterrows():
        if row["LIBRARY"].strip() != "":
            current_pkg = row["LIBRARY"].strip() 
        if row["INSTALLED VERSION"].strip() != "":
            current_version = row["INSTALLED VERSION"].strip()
        df.loc[idx,"LIBRARY"]=current_pkg + "_" + current_version

    package_list = df["LIBRARY"].unique().tolist()

    cve_list = df["VULNERABILITY ID"].unique().tolist()

    node_list = package_list + cve_list

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)

    edges_list = []

    for idx, row in df.iterrows():
        temp = row["LIBRARY"] + ' ' + row["VULNERABILITY ID"]
        edges_list.append(temp)
    
    for pkg in package_list:
        temp = container_name.upper() + ' ' + pkg
        edges_list.append(temp)

    write_edge_list(edges_list,output_path)

    
def sysdig_formater(input_file,output_path,container_name):

    col_names =  ["package","severity","vuln"]

    df = pd.DataFrame(columns = col_names)

    for root, dirs, files in os.walk(input_file):
            for file in files:
                if container_name.lower() in file:

                    file_path = os.path.join(root,file)

                    temp = pd.read_csv(file_path, index_col=0)

                    rel_df = temp[["package","severity","vuln"]]

                    df = df.append(rel_df, ignore_index=True)

    df["cve"] = df["vuln"] + "_" + df["severity"]

    df = df.drop(['vuln'], axis = 1)

    df = df.drop(['severity'], axis = 1)

    package_list = df["package"].unique().tolist()

    cve_list = df["cve"].unique().tolist()

    node_list = package_list + cve_list

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)

    edges_list = []

    for idx, row in df.iterrows():
        temp = row["package"] + ' ' + row["cve"]
        edges_list.append(temp)
    
    for pkg in package_list:
        temp = container_name.upper() + ' ' + pkg
        edges_list.append(temp)

    write_edge_list(edges_list,output_path)


def docker_scan_formater(input_file,output_path,container_name):

    if os.stat(input_file).st_size == 0:
        return

    f = open(input_file)

    data = json.load(f)

    package_list = []

    cve_list = []

    edges_list = []

    # Dynamic allocation kept failing with key errors
    # path / image name kept appearing in different locations
    #container_name = data[-1]["path"].split(":")[0].upper()

    #TODO - Formalise formatting for versions across all data 
    if isinstance(data, dict):
        vulns = data["vulnerabilities"]

        for i in range(0, len(vulns)):
                name = vulns[i]["name"]

                version = vulns[i]["version"]

                if len(vulns[i]["identifiers"]["CVE"]) > 0:

                    cve = vulns[i]["identifiers"]["CVE"][0] + "_" + vulns[i]["severity"].capitalize()
                
                else: 
                    key_list = list(vulns[i]["identifiers"].keys())

                    key_list.sort()

                    for key in key_list:

                        if len(vulns[i]["identifiers"][key]) > 0:
                            
                            cve = vulns[i]["identifiers"][key][0] + "_" + vulns[i]["severity"].capitalize()
                            break


                #if "+" in version:
                #    version = version.split("+")[0]

                if "/" in name:
                    split_str = name.split("/")
                        
                    for item in split_str:
                        pkg = item + "_" + version
                        package_list.append(pkg)
                        cve_list.append(cve)
                        edges_list.append(pkg + ' ' + cve)
                else:
                    pkg = name + "_" + version
                    package_list.append(pkg)
                    cve_list.append(cve)
                    edges_list.append(pkg + ' ' + cve)

    else:
        for i in range(0, len(data)):
            vulns = data[i]["vulnerabilities"]
            for i in range(0, len(vulns)):
                name = vulns[i]["name"]

                version = vulns[i]["version"]

                
                if len(vulns[i]["identifiers"]["CVE"]) > 0:

                    cve = vulns[i]["identifiers"]["CVE"][0] + "_" + vulns[i]["severity"].capitalize()
                
                else: 
                    key_list = list(vulns[i]["identifiers"].keys())

                    key_list.sort()

                    for key in key_list:

                        if len(vulns[i]["identifiers"][key]) > 0:
                            
                            cve = vulns[i]["identifiers"][key][0] + "_" + vulns[i]["severity"].capitalize()
                            break

                if "+" in version:
                    version = version.split("+")[0]

                if "/" in name:
                    split_str = name.split("/")
                        
                    for item in split_str:
                        pkg = item + "_" + version
                        package_list.append(pkg)
                        cve_list.append(cve)
                        edges_list.append(pkg + ' ' + cve)
                else:
                    pkg = name + "_" + version
                    package_list.append(pkg)
                    cve_list.append(cve)
                    edges_list.append(pkg + ' ' + cve)

    unique_pkgs = list(set(package_list))

    unique_cves = list(set(cve_list))

    node_list = unique_pkgs + unique_cves

    node_list.append(container_name.upper())

    write_node_list(node_list,output_path)
        
    for pkg in unique_pkgs:
        temp = container_name.upper() + ' ' + pkg
        edges_list.append(temp)

    write_edge_list(list(set(edges_list)),output_path)
