import os
import csv
import visualisation.sub_plots as vis_multi

def node_data(container_image,scan_folder):

    container_image_filename = container_image.replace(":","_").replace(".","_")

    print(container_image_filename)

    count = 1

    last_line = ""

    node_input = []
    edge_input = []
    scanners = []

    scan_type =["", "updated_"]

    for sc in scan_type:
        print("{}".format(scan_folder,sc))
        for root, dirs, files in os.walk("{}".format(scan_folder)):
            for file in files:
                if file == "{}{}_nodes.txt".format(sc,container_image_filename):
                    full_path = os.path.join(root,file)
                    with open(full_path) as f:
                        if "clair" in full_path and "{}clair".format(sc) not in scanners:
                            scanners.append("{}clair".format(sc))
                        if "grype" in full_path and "{}grype".format(sc) not in scanners:
                            scanners.append("{}grype".format(sc))
                        if "trivy" in full_path and "{}trivy".format(sc) not in scanners:
                            scanners.append("{}trivy".format(sc))

                        temp = f.read().splitlines()
                        node_input.append(temp)

                    if last_line == "":
                        last_line = temp[-1]

                    count += 1

                elif file == "{}{}_edges.txt".format(sc,container_image_filename):
                    with open(os.path.join(root,file)) as f:
                        temp = f.read().splitlines()

                        edge_input.append(temp)

    return node_input, edge_input, scanners, count, last_line


def borvo_vis_wrapper(container_image,dir_path):

    scan_folder = os.path.join(dir_path,"visualisation/node_edge_files/")

    csv_file_path = os.path.join(dir_path,"output_files/csvs")

    vis_output_path = os.path.join(dir_path, "output_files")

    figures = []

    vuln_count = dict(
        original_crit=[],
        original_high=[],
        original_med=[],
        original_low=[],
        original_neg=[],
        original_unknown=[],
        original_vulns=[],
        updated_crit=[],
        updated_high=[],
        updated_med=[],
        updated_low=[],
        updated_neg=[],
        updated_unknown=[],
        updated_vulns=[]
    )

    cve_keys = ["crit", "high", "med", "low", "neg", "unknown"]

    output_dicts = []
    
    per_scanner_vuln_count = []

    node_input, edge_input, scanners, count, container = node_data(container_image,scan_folder)

    for i in range(0,len(node_input)):
        final_loop = False
        if i == (len(node_input) -1):
            final_loop= True
        fig, temp_dict = vis_multi.node_link_create_traces(node_input[i], edge_input[i], count, scanners[i], container,0,final_loop,True)
        figures.append(fig)
        vuln_sum = 0
        for key in cve_keys:
            vuln_sum += len(temp_dict[key]) 
        per_scanner_vuln_count.append(vuln_sum)

        key_list=["crit","high","med","low","neg","unknown","vulns"]

        for key in key_list:
            if "updated" in scanners[i]:
                vuln_count["updated_{}".format(key)] += temp_dict[key]
            else:
                vuln_count["original_{}".format(key)] += temp_dict[key]

        temp_dict["Scanner"] = scanners[i]
        temp_dict["Container"] = container_image
        output_dicts.append(temp_dict)

    with open("{}/{}.csv".format(csv_file_path,container_image.replace(":","_").replace(".","_")), 'w') as f:
        w = csv.DictWriter(f, temp_dict.keys())
        w.writeheader()
        w.writerows(output_dicts)

    for key, value in vuln_count.items():
        new_value = len(set(value))
        vuln_count[key] = 0
        vuln_count[key] = new_value

    vis_multi.node_link_plot(container_image, figures, vuln_count, scanners, per_scanner_vuln_count,0,[],vis_output_path,True)