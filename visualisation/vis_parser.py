import os
import csv
import visualisation.single_plot as vis_single
import visualisation.sub_plots as vis_multi

def plot_create(vis_type,container_image, scanner, dir_path,nofix_show):

    node_edge_file_path = os.path.join(dir_path,"visualisation/node_edge_files")

    csv_file_path = os.path.join(dir_path,"output_files/csvs")

    vis_output_path = os.path.join(dir_path, "output_files")

    if "single" in vis_type:

        node_input, edge_input, count, container, malware_count, malware_bins = vis_single.node_data(container_image, scanner, node_edge_file_path,nofix_show)

        fig, vuln_count = vis_single.node_link_create_traces(node_input, edge_input, count, scanner, container, malware_count)

        vis_single.node_link_plot(fig, container_image, scanner, vuln_count, malware_count, malware_bins,vis_output_path)

    if "multi" in vis_type:

        node_input, edge_input, scanners, count, container, malware_count, malware_bins = vis_multi.node_data(container_image,node_edge_file_path)

        figures = []

        vuln_count = dict(
            crit=0,
            high=0,
            med=0,
            low=0,
            neg=0,
            unknown=0,
            EBID_crit=0,
            EBID_high=0,
            EBID_med=0,
            EBID_low=0,
            EBID_neg=0,
            EBID_unknown=0
        )

        cve_keys = ["crit", "high", "med", "low", "neg", "unknown"]

        output_dicts = []

        per_scanner_vuln_count = []

        for i in range(0,len(node_input)):
            local_malware_count = 0
            final_loop = False
            if scanners[i] == "dagda":
                local_malware_count = malware_count
            if i == (len(node_input) -1):
                final_loop= True
            fig, temp_dict = vis_multi.node_link_create_traces(node_input[i], edge_input[i], count, scanners[i], container, local_malware_count,final_loop,False)
            figures.append(fig)
            vuln_sum = 0
            for key in cve_keys:
                vuln_sum += temp_dict[key] 
            per_scanner_vuln_count.append(vuln_sum)

            for key, val in temp_dict.items():
                vuln_count[key] += val

            temp_dict["Scanner"] = scanners[i]
            output_dicts.append(temp_dict)
        
        if not os.path.isdir(csv_file_path):
            os.makedirs(csv_file_path)
        
        with open("{}/{}.csv".format(csv_file_path,container_image), 'w') as f:
            w = csv.DictWriter(f, temp_dict.keys())
            w.writeheader()
            w.writerows(output_dicts)

        vis_multi.node_link_plot(container_image, figures, vuln_count, scanners, per_scanner_vuln_count, malware_count,malware_bins,vis_output_path,False)