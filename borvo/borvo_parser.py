import os
import re
import docker
import borvo.borvo as borvo

from io import BytesIO

def borvo_wrapper(container_image,dir_path):

    docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    returned_pkgs, container_os = borvo.image_pull_scan(container_image,dir_path,docker_client)

    single_list = [item for sublist in returned_pkgs if sublist is not None for item in sublist ]

    no_fix = ["None", "won't fix"]

    filtered_lists = [pkg for pkg in single_list if not any(item in pkg for item in  no_fix)]

    unique_filtered_lists = list(set(filtered_lists))

    print("-----------------------------------")

    pkg_managers = dict(
        ubuntu="apt install",
        debian="apt install",
        centos="yum install",
        redhat="yum install",
        alpine="apk add"
    )

    try:

        api_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        container = api_client.create_container(container_image)

        container_data = api_client.inspect_container(container)

        cmd_value = container_data["Config"]["Cmd"]
        user = container_data["Config"]["User"]

        if len(cmd_value) == 1:
            cmd_value = cmd_value[0]
        
        api_client.remove_container(container, force=True)

        pkg_manager = [str(val) for key, val in pkg_managers.items() if container_os.lower() == key][0]

        if user != "":
            dockerfile = "FROM {}\n\nUSER root\n".format(container_image)  
        
        else:
            dockerfile = "FROM {}\n".format(container_image)  
        
        if "yum" not in pkg_manager:
            dockerfile += "\nRUN {} update\n".format(pkg_manager.split(" ")[0])

        for pkg in unique_filtered_lists:
            if "yum" in pkg_manager:
                dockerfile += "RUN {} {} -y".format(pkg_manager,pkg.replace("=","-"))
            else:
                dockerfile += "RUN {} {}".format(pkg_manager,pkg)
            dockerfile += "\n"

        if user != "":
            dockerfile += "\nUSER {}".format(user)

        dockerfile += "\nCMD {}".format(cmd_value)

        problem_pkg = ""

        build_error = True

        respose = []

        new_image_tag = "updated_" + container_image

        while build_error:

            build_error = False

            f = BytesIO(dockerfile.encode('utf-8'))

            for line in api_client.build(fileobj=f, rm=True, tag=new_image_tag):
                respose.append(line)
                if b"error" in line:
                    
                    if "yum" in pkg_manager:
                        problem_pkg = re.search(b"[a-zA-Z0-9-]+-[a-zA-Z0-9:.-/]+", line).group(0).decode("utf-8")
                    else:
                        problem_pkg = re.search(b"[a-zA-Z0-9-]+=[a-zA-Z0-9:.-/]+", line).group(0).decode("utf-8")

                    print("ERROR! Retrying without install of {}".format(problem_pkg))

                    dockerfile=re.sub('.*{}.*'.format(problem_pkg), '', dockerfile)

                    build_error = True
                    break

        for line in respose:
            print(line)    

        docker_client.images.remove(container_image, force=True)

        new_returned_pkgs = borvo.image_pull_scan(new_image_tag,dir_path,docker_client)

        image = docker_client.images.get(new_image_tag)

        if not os.path.isdir("{}/output_files/updated_images".format(dir_path)):
            os.makedirs("{}/output_files/updated_images".format(dir_path))

        img_f = open('{}/output_files/updated_images/{}.tar'.format(dir_path,new_image_tag.replace(":","_").replace(".","_").replace("/","_")), 'wb')
        for chunk in image.save(named=True):
            img_f.write(chunk)
        img_f.close()

        docker_client.images.remove(new_image_tag, force=True)

        #Clean up
        api_client.prune_containers()
        docker_client.images.prune()
    
    except Exception as e: 
        print(e)

        #Clean up
        api_client.prune_containers()
        docker_client.images.prune()