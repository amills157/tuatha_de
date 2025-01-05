import requests

def description_check(cve):
    r = requests.get("https://cve.circl.lu/api/cve/"+cve) 
    if r.json():

        description = r.json()["containers"]["cna"]["descriptions"][0]["value"]

        if description.__contains__("In the Linux kernel"):
    
            return cve + " = Linux kernel"
    
    return cve

with open('cves.txt', mode='r') as file:
    lines = file.readlines()

for cve in lines:
    print(description_check(cve.rstrip('\r\n')))