import os
import data_formatting.data_formater as formater

def file_checking(file_path_list,container_image):

    new_file_path_list = []

    temp =[]

    for f in file_path_list:

        # Sysdig name formatting needs to be handled in a seperate manner
        if "docker_io_" in f:
            new_file_path_list.append("sysdig")
        else:
            temp.append(os.path.basename(f).split(".")[0])

    set_check = set(temp)

    if len(set_check) > 1:
        
        matched_image = ""

        for i in set_check:
            if i == container_image:
                matched_image = i

        for j in file_path_list:
            if matched_image == os.path.basename(j).split(".")[0]:
                new_file_path_list.append(j)

        return new_file_path_list

    else:
        return file_path_list


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

                    potential_files.append(file_path)

        checked_file_list = file_checking(potential_files,container_image)
        
        print("-----------")
        print(checked_file_list)
        print("-----------")

        for file_path in checked_file_list:

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

            elif scanner == "jfrog":
                formater.jfrog_formater(input_path,output_path,container_name)
            
            elif scanner == "grype":
                formater.grype_formater(input_path,output_path,container_name)
            
            elif scanner =="trivy":
                formater.trivy_formater(input_path,output_path,container_name)

            elif scanner =="sysdig":
                formater.sysdig_formater(input_path,output_path,container_name)

            elif scanner =="docker_scout":
                formater.docker_scout_formater(input_path,output_path,container_name)

        elif scanner =="all":

            potential_files = []

            sysdig_root =""

            for root, dirs, files in os.walk(input_path):
                for file in files:
                    if container_image.lower() in file.lower():
                                                
                        file_path = os.path.join(root,file)

                        if "sysdig" in file_path.replace(os.path.basename(file_path),''):
                            sysdig_root = root

                        potential_files.append(file_path)

            checked_file_list = file_checking(potential_files,container_image)

            for file_path in checked_file_list:
                    
                if "clair" in file_path:
                    print("Found a clair file - Processing")
                    scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/clair/{}".format(container_image))
                    formater.clair_formater(file_path,scanner_output_path,container_name)

                elif "jfrog" in file_path:
                    print("Found a jfrog file - Processing")
                    scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/jfrog/{}".format(container_image))
                    formater.jfrog_formater(file_path,scanner_output_path,container_name)

                elif "docker_scout" in file_path:
                    print("Found a docker_scout file - Processing")
                    scanner_output_path = os.path.join(output_path,"visualisation/node_edge_files/docker_scout/{}".format(container_image))
                    formater.docker_scout_formater(file_path,scanner_output_path,container_name)
                
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
                    formater.sysdig_formater(sysdig_root,scanner_output_path,container_name,container_image)
    
