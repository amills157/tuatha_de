import os
import pathlib
import re
import json
import docker
import requests
import pandas as pd
import socket

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

pd.options.mode.chained_assignment = None

def get_ip_address():
    '''
    Force a connection to 8.8.8.8 to determine the IP address of the 
    interface used by the default route.

        Parameters:
            None

        Returns:
            ip_address (str): String containing IP address.
    '''
    
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))

    return s.getsockname()[0]


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

    os.system("clair-scanner --ip {} -r {}/clair/{}.json {}".format(get_ip_address(), scan_folder, container_image_filenames, container_image))

    os.system("grype {} > {}/grype/{}.txt".format(container_image,scan_folder,container_image_filenames))

    os.system("trivy image -f json -o {}/trivy/{}.json {}".format(scan_folder,container_image_filenames, container_image))

    returned_pkgs.append(clair_formater("{}/clair/{}.json".format(scan_folder,container_image_filenames)))

    returned_pkgs.append(grype_formater("{}/grype/{}.txt".format(scan_folder,container_image_filenames)))
                    
    pkg_list, container_os = trivy_formater("{}/trivy/{}.json".format(scan_folder,container_image_filenames), container_image)
    
    returned_pkgs.append(pkg_list)

    return returned_pkgs, container_os


def clair_formater(input_file):

    try:
        if os.stat(input_file).st_size == 0:
            return
    except Exception as e: 
        print(e)
        f = open(f'{pathlib.Path(input_file).parent}/clair_error_log.txt', 'a')
        f.write(str(e)+"\n")
        f.close()

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
                df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'TYPE']
                df.loc[idx, 'TYPE'] = df.loc[idx, 'FIXED-IN']
                df.loc[idx, 'FIXED-IN'] = None
            
    if df['SEVERITY'].isna().all():
        for idx, row in df.iterrows():
            df.loc[idx, 'SEVERITY'] = df.loc[idx, 'VULNERABILITY']
            df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'TYPE']
            df.loc[idx, 'TYPE'] = df.loc[idx, 'FIXED-IN']
            df.loc[idx, 'FIXED-IN'] = None

    # If after the above fix we still have issues it's related to the installed value
    if None in df['SEVERITY'].values:
        for idx, row in df.iterrows():
            if row['SEVERITY'] is None:
                df.loc[idx, 'SEVERITY'] = df.loc[idx, 'VULNERABILITY']
                df.loc[idx, 'VULNERABILITY'] = df.loc[idx, 'TYPE']
                df.loc[idx, 'TYPE'] = df.loc[idx, 'INSTALLED']
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

    f = open(input_file)

    data = json.load(f)

    fixed_package_list = []

    container_os = ""

    container_os = data["Metadata"]["OS"]["Family"]

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

    return fixed_package_list, container_os
