import os
import data_formatting.data_formater as formater

def create_node_egde_files(input_path,container_name,container_image,scanner,output_path,borvo_flag):

    while container_name is None or container_name == "":
            container_name = input("Container name cannot be blank.\nEnter the application / container name:\n")

    if borvo_flag:

        if ":" in container_image:
            container_image = container_image.replace(":","_").replace(".","_").replace("/","_")

        update_marker = ""

        for root, dirs, files in os.walk(input_path):
            for file in files:
                if container_image.lower() in file:

                    file_path = os.path.join(root,file)

                    if "update" in file_path:
                        update_marker = "updated_"

                    if "clair" in file_path:
                        print("Found a clair file - Processing")
                        scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/clair/{}{}".format(update_marker,container_image))
                        formater.clair_formater(file_path,scanner_output_path,container_name)
                    
                    elif "grype" in file_path:
                        print("Found a grype file - Processing")
                        scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/grype/{}{}".format(update_marker,container_image))
                        formater.grype_formater(file_path,scanner_output_path,container_name)
                    
                    elif "trivy" in file_path:
                        print("Found a trivy file - Processing")
                        scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/trivy/{}{}".format(update_marker,container_image))
                        formater.trivy_formater(file_path,scanner_output_path,container_name)

    else:
        if scanner != "all":

            if scanner == "clair":
                formater.clair_formater(input_path,output_path,container_name)

            elif scanner == "dagda":
                formater.dagda_formater(input_path,output_path,container_name)
            
            elif scanner == "grype":
                formater.grype_formater(input_path,output_path,container_name)
            
            elif scanner =="trivy":
                formater.trivy_formater(input_path,output_path,container_name)

            elif scanner =="sysdig":
                formater.sysdig_formater(input_path,output_path,container_name)

            elif scanner =="docker_scan":
                formater.docker_scan_formater(input_path,output_path,container_name)

        elif scanner =="all":

            for root, dirs, files in os.walk(input_path):
                for file in files:
                    if container_image.lower() in file:

                        file_path = os.path.join(root,file)

                        if "clair" in file_path:
                            print("Found a clair file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/clair/{}".format(container_image))
                            formater.clair_formater(file_path,scanner_output_path,container_name)

                        elif "dagda" in file_path:
                            print("Found a dagda file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/dagda/{}".format(container_image))
                            formater.dagda_formater(file_path,scanner_output_path,container_name)

                        elif "docker_scan" in file_path:
                            print("Found a docker_scan file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/docker_scan/{}".format(container_image))
                            formater.docker_scan_formater(file_path,scanner_output_path,container_name)
                        
                        elif "grype" in file_path:
                            print("Found a grype file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/grype/{}".format(container_image))
                            formater.grype_formater(file_path,scanner_output_path,container_name)
                        
                        elif "trivy" in file_path:
                            print("Found a trivy file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/trivy/{}".format(container_image))
                            formater.trivy_formater(file_path,scanner_output_path,container_name)
                        
                        elif "sysdig" in file_path:
                            print("Found a sysdig file - Processing")
                            scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/sysdig/{}".format(container_image))
                            # Because sysdig files tend to be split between 2 .csv's we pass the root and let the sysdig specific formatter handle the rest
                            formater.sysdig_formater(root,scanner_output_path,container_name)
    
