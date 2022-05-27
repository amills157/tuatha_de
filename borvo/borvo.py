import os
import re
import json
import docker
import requests
import pandas as pd

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

pd.options.mode.chained_assignment = None


def image_pull_scan(container_image, dir_path, docker_client):

    returned_pkgs = []

    container_name = container_image.split(":")[0]

    container_image_filenames = container_image.replace(':', '_').replace(".", "_").replace("/", "_")

    if "updated_" in container_image:
        scan_folder = os.path.join(dir_path,"borvo/container_scans/updated")

    else:
        scan_folder = os.path.join(dir_path,"borvo/container_scans/original")

        docker_client.images.pull(container_image)

    folder_list = ["","clair","grype","trivy"]
    for fldr in folder_list:
        if not os.path.isdir("{}/{}".format(scan_folder,fldr)):
            os.makedirs("{}/{}".format(scan_folder,fldr))

    os.system("clair-scanner --ip 192.168.172.10 -r {}/clair/{}.json {}".format(scan_folder,container_image_filenames, container_image))

    os.system("grype {} > {}/grype/{}.txt".format(container_image,scan_folder,container_image_filenames))

    os.system("trivy image {} > {}/trivy/{}.txt".format(container_image,scan_folder,container_image_filenames))

    returned_pkgs.append(clair_formater("{}/clair/{}.json".format(scan_folder,container_image_filenames)))

    returned_pkgs.append(grype_formater("{}/grype/{}.txt".format(scan_folder,container_image_filenames)))
                    
    pkg_list, container_os = trivy_formater("{}/trivy/{}.txt".format(scan_folder,container_image_filenames), container_image)
    
    returned_pkgs.append(pkg_list)

    return returned_pkgs, container_os


def clair_formater(input_file):

    if os.stat(input_file).st_size == 0:
        return

    f = open(input_file)

    data = json.load(f)

    package_list = []
    fixed_pkg_list = []

    edges_list =[]

    container_image = data["image"].split(":")[0]

    container_image = container_image.replace(".", "_").replace("/", "_")
    
    for i in data["vulnerabilities"]:
        pkg = i["featurename"]+'-'+i["featureversion"]
        if i["fixedby"] != "":
            fixedby=i["fixedby"]

            if ":" in i["fixedby"]:
                fixedby = i["fixedby"].split(":")[1]
                
            fixed_pkg = i["featurename"]+'='+fixedby
            fixed_pkg_list.append(fixed_pkg)

        package_list.append(pkg)
        
    unique_pkgs = list(set(package_list))

    unique_fixed_pkg = list(set(fixed_pkg_list))

    return unique_fixed_pkg


def grype_formater(input_file):


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

    df['PACKAGE'] = df['NAME'] + '_' + df['INSTALLED']

    # row by row check for centos / rhel specific versioning
    for idx, row in df.iterrows():
        if row['FIXED-IN'] is not None and ":" in row['FIXED-IN']:
            df.loc[idx, 'FIXED-IN'] = row['FIXED-IN'].split(":")[1]

    df['FIXED_PKG'] = df['NAME'] + '=' + df['FIXED-IN']

    #with pd.option_context('display.max_rows', None, 'display.max_columns', None):
    #    print(df)

    package_list = df['PACKAGE'].unique().tolist()

    fixed_package_list = df['FIXED_PKG'].dropna().unique().tolist()

    return fixed_package_list


def trivy_formater(input_file,container_image):

    f = open(input_file,"r")
    lines = f.readlines()
    f.close()

    container_os = ""

    file=open("temp",'w')
    for line in lines:
        if container_image in line:
            container_os=re.search("[\(]\w+", line).group(0).replace("(", "")
        if "-+-" in line or "|" not in line:
            continue
        else:
            file.writelines([line])

    file.close()

    try:
        df = pd.read_csv("temp", sep="|", engine='python')
    except pd.errors.EmptyDataError as e:

        return list(), container_os

    os.remove("temp")

    current_pkg = ""

    current_sev = ""

    df = df.rename(columns=lambda x: x.strip())

    df = df[df["VULNERABILITY ID"].notna()]

    df = df.drop(["Unnamed: 0"], axis=1)

    df["FIXED LIBRARY"] = ""

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

        fixed_version = "None"

        if row["LIBRARY"].strip() != "":
            current_pkg = row["LIBRARY"].strip() 
        if row["INSTALLED VERSION"].strip() != "":
            current_version = row["INSTALLED VERSION"].strip()
        if row["FIXED VERSION"].strip() != "":
            fixed_version = row["FIXED VERSION"].strip()
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

        df.loc[idx,"LIBRARY"]=current_pkg + "-" + current_version
        df.loc[idx,"FIXED LIBRARY"]=current_pkg + "=" + fixed_version

    package_list = df["LIBRARY"].unique().tolist()

    fixed_package_list = df["FIXED LIBRARY"].dropna().unique().tolist()

    return fixed_package_list, container_os
