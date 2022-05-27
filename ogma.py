#!/usr/bin/env python3
import os
import csv
import argparse
import borvo.borvo_parser as borvo_parser
import borvo.borvo_vis_parser as borvo_vis_parser
import data_formatting.data_parser as data_parser
import visualisation.vis_parser as vis_parser


if __name__ == '__main__':

    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    parser = argparse.ArgumentParser(description="CHANGEME")
    
    parser.add_argument("-report_dir", help="Directory folder which contains the report(s) or scan result(s) to read.\nIf not provided this will default to the 'container_scans' folder in the same root dir", default=os.path.join(dir_path,"container_scans"))
    parser.add_argument("-format", help="The scanner tool used - Accepted values are:\nAll\nClair\nDagda\nDocker_Scan\nGrype\n\Sysdig\nTrivy\nDefaults to 'all'\n", default="all")
    parser.add_argument("-image", help="The container image file report to use - This will also be the data name used when plotting and the file name for the output, e.g. 'rabbitmq_3_9_13' \n", required = True)
    parser.add_argument("-container", help="The container / application name to use - This will be the central node name used when plotting, e.g. 'rabbitmq' \n")
    parser.add_argument("-update", type=bool, help="Will use the BOROVO plugin to fix impacted binaries (where possible) \n")
    parser.add_argument("-refresh", type=bool, help="Will re-create the node and egdes from the container scan results avaliable - By default visulisations are created from existing node and edge files (when / where they exist) \n", default=False)
    parser.add_argument("-vis", help="Select the visualisation output\nSingle (node), Multi (node) or Both\nThis defaults to 'both' for all scanners and single for a selected format", default="both")
    parser.add_argument("-nofix", help="Select to show CVEs which have been listed as won't / no fix. Accepted values are:\nShow\nNone\nCompare\ndefaults to 'None'", default="None")

    args = parser.parse_args()
    input_path = args.report_dir
    scanner = args.format.lower()
    container_image = args.image
    container_name = args.container
    borvo_flag = args.update
    refresh_flag = args.refresh
    vis_type = args.vis.lower()
    nofix_show = args.nofix

    while scanner not in ["dagda", "docker_scan", "clair","grype","trivy", "sysdig", "all"]:
        scanner = input("Not a valid scanner format.Accepted values are:\nClair\nDagda\nDocker_Scan\nGrype\nTrivy\nSysdig\n")

    while vis_type not in ["single", "multi", "both"]:
        scanner = input("Not a valid visulisation format.Accepted values are:\nSingle\nMulti\nBoth\n")

    if borvo_flag:
        borvo_input_path = os.path.join(dir_path,"borvo/container_scans")

        borvo_parser.borvo_wrapper(container_image,dir_path)

        data_parser.create_node_egde_files(borvo_input_path,container_name,container_image,scanner,dir_path,borvo_flag)

        borvo_vis_parser.borvo_vis_wrapper(container_image,dir_path)

    else:
    
        if scanner == "all":

            if refresh_flag:
                data_parser.create_node_egde_files(input_path,container_name,container_image,scanner,dir_path,borvo_flag)

        else:
            output_path = os.path.join(dir_path,"visualisation/node_edge_files/{}/{}".format(scanner,container_image))

            ext = dict(
                json = ["clair","dagda","docker_scan"],
                txt = ["grype","trivy"]
            )
            file_ext = ""
            for key, value in ext.items():
                if scanner in value:
                    file_ext = key
            input_file = os.path.join(input_path,"{}/{}.{}".format(scanner,container_image,file_ext))

            print(input_file)

            file_check = os.path.isfile("{}_nodes".format(output_path))

            if refresh_flag or not file_check:
                data_parser.create_node_egde_files(input_file,container_name,container_image,scanner,output_path,borvo_flag)

        if vis_type == "both":
            if scanner == "all":
                vis_type = "single_multi"
            else:
                vis_type = "single"

        vis_parser.plot_create(vis_type,container_image,scanner,dir_path,nofix_show)