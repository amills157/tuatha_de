import re
import os
import json
import sqlite3
import requests
import networkx as nx
import plotly.io as plt_io
import cve_searchsploit as CS
import plotly.graph_objects as go

from tqdm import tqdm
from pathlib import Path
from plotly.subplots import make_subplots

# create our custom_dark theme from the plotly_dark template
plt_io.templates["custom_dark"] = plt_io.templates["plotly_dark"]

# set the paper_bgcolor and the plot_bgcolor to a new color
plt_io.templates["custom_dark"]['layout']['paper_bgcolor'] = '#30404D'
plt_io.templates["custom_dark"]['layout']['plot_bgcolor'] = '#30404D'

# you may also want to change gridline colors if you are modifying background
plt_io.templates['custom_dark']['layout']['yaxis']['gridcolor'] = '#4f687d'
plt_io.templates['custom_dark']['layout']['xaxis']['gridcolor'] = '#4f687d'

plt_io.renderers.default = "firefox"

CS.update_db()

legend_items = {}

def create_vuln_trace(trace_type,vuln_node):

    trace_name = trace_type.capitalize()

    vuln_trace = go.Scatter(
        x=vuln_node["{}_x".format(trace_type)], y=vuln_node["{}_y".format(trace_type)],
        mode='markers+text',
        hoverinfo='text',
        name='{} CVEs'.format(trace_name),
        text = vuln_node["{}_text".format(trace_type)],
        hovertext = vuln_node["{}_hover_text".format(trace_type)],
        marker=dict(
            color=vuln_node["{}_colour".format(trace_type)],
            size=vuln_node["{}_size".format(trace_type)],
            symbol=vuln_node["{}_marker".format(trace_type)],
            line_width=2),
        legendgroup=trace_type,
        showlegend=False)

    return vuln_trace

def node_data(container_image,node_edge_file_path,borvo_flag):

    count = 1

    last_line = ""
    node_input = []
    edge_input = []
    scanners = []

    for root, dirs, files in os.walk(node_edge_file_path):
        for file in files:
            if container_image in file:
                full_path = os.path.join(root,file)
                if "updated" in file and not borvo_flag:
                    continue

                if file.replace("_nodes.txt","").replace("_edges.txt","") != container_image:
                    continue

                if "nodes" in file:
                    if "clair" in full_path and "clair" not in scanners:
                        scanners.append("clair")
                    if "jfrog" in full_path and "jfrog" not in scanners:
                        scanners.append("jfrog")
                    if "docker_scout" in full_path and "docker_scout" not in scanners:
                        scanners.append("docker_scout")
                    if "grype" in full_path and "grype" not in scanners:
                        scanners.append("grype")
                    if "trivy" in full_path and "trivy" not in scanners:
                        scanners.append("trivy")
                    if "sysdig" in full_path and "sysdig" not in scanners:
                        scanners.append("sysdig")

                    with open(full_path) as f:
                        temp = f.read().splitlines()

                        node_input.append(temp)

                    if last_line == "":
                        last_line = temp[-1]

                    count += 1

                if "edges" in file:
                    with open(full_path) as f:
                        temp = f.read().splitlines()

                        edge_input.append(temp)

    return node_input, edge_input, scanners, count, last_line

def node_link_create_traces(node_input, edge_input, count, scanner, container, final_loop, borvo_flag):
    global legend_items

    my_graph = nx.Graph()

    blind_traces = []

    edges = nx.read_edgelist(edge_input)

    my_graph.add_edges_from(edges.edges())
    my_graph.add_nodes_from(node_input)

    # kamada_kawai_layout
    # circular_layout / shell_layout
    # spring_layout / fruchterman_reingold_layout
    pos = nx.layout.kamada_kawai_layout(my_graph)

    vuln_types = ["ALAS", "ALAS2", "BugTraq", "CVE", "CWE", "DLA","EBID", "ELSA", "GHSA", "GMS", "RHSA", "VULNDB", "SUSE-SU", "GO"]

    vuln_trace_types = ["local","network","unknown","other"]

    edge_x = []
    edge_y = []
    for edge in my_graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines',
        showlegend=False)

    vuln_node = dict()

    for item in vuln_trace_types:
        vuln_node["{}_x".format(item)] = []
        vuln_node["{}_y".format(item)] = []
        vuln_node["{}_text".format(item)] = []
        vuln_node["{}_hover_text".format(item)] = []
        vuln_node["{}_colour".format(item)] = []
        vuln_node["{}_marker".format(item)] = []
        vuln_node["{}_size".format(item)] = []

    #Critical,High,Med,Low,Neg
    if borvo_flag:
        vuln_count = dict(
            crit=[],
            high=[],
            med=[],
            low=[],
            neg=[],
            unknown=[],
            EBID_crit=[],
            EBID_high=[],
            EBID_med=[],
            EBID_low=[],
            EBID_neg=[],
            EBID_unknown=[],
            vulns = []
        )
        
    else:
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

    package_node_x = []
    package_node_y = []
    package_node_size =[]
    package_node_opacity = []
    package_node_colour = []

    central_pos = []

    conn = sqlite3.connect("{}/.config/cvedb/cvedb.sqlite".format(str(Path.home())))

    print("Processing Node data for {} - Multi plot".format(scanner))
    for node in tqdm(my_graph.nodes()):

        node_size = (node_input.count(node) * 10)
        
        x, y = pos[node]
        if any(map(str(node).__contains__, vuln_types)):
            if borvo_flag:
                vuln_count["vulns"].append(str(node).split("_")[0])
            if "Critical" in str(node):
                vuln_colour = ("red")
                if borvo_flag:
                    vuln_count["crit"].append(str(node))
                else:
                    vuln_count["crit"] = vuln_count["crit"]+1
            elif "High" in str(node):
                vuln_colour = ("orange")
                if borvo_flag:
                    vuln_count["high"].append(str(node))
                else:
                    vuln_count["high"] = vuln_count["high"]+1
            elif "Medium" in str(node):
                vuln_colour = ("yellow")
                if borvo_flag:
                    vuln_count["med"].append(str(node))
                else:
                    vuln_count["med"] = vuln_count["med"]+1
            elif "Low" in str(node):
                vuln_colour = ("yellowgreen")
                if borvo_flag:
                    vuln_count["low"].append(str(node))
                else:
                    vuln_count["low"] = vuln_count["low"]+1
            else:
                vuln_colour = ("grey")
                if "Unknown" in str(node):
                    if borvo_flag:
                        vuln_count["unknown"].append(str(node))
                    else:
                        vuln_count["unknown"] = vuln_count["unknown"]+1
                else:
                    if borvo_flag:
                        vuln_count["neg"].append(str(node))
                    else:
                        vuln_count["neg"] = vuln_count["neg"] +1

        if "CVE" in str(node):
            
            cve_assignment = str(node).split('_')[0]
                        
            exploit_check = CS.edbid_from_cve(cve_assignment)

            marker = "-open"

            exploits = ""

            # For sub plot we also created CSVs with rows per scanner
            #This data is not included in the vis, but is included in the CSV
            if len(exploit_check) >=1 :
                marker = ""
                exploits = " EBID(s): " + str(exploit_check)[1:-1]
                if "Critical" in str(node):
                    if borvo_flag:
                        vuln_count["EBID_crit"].append(str(node))
                    else:
                        vuln_count["EBID_crit"] = vuln_count["EBID_crit"]+1
                elif "High" in str(node):
                    if borvo_flag:
                        vuln_count["EBID_high"].append(str(node))
                    else:
                        vuln_count["EBID_high"] = vuln_count["EBID_high"]+1
                elif "Medium" in str(node):
                    if borvo_flag:
                        vuln_count["EBID_med"].append(str(node))
                    else:
                        vuln_count["EBID_med"] = vuln_count["EBID_med"]+1
                elif "Low" in str(node):
                    if borvo_flag:
                        vuln_count["EBID_low"].append(str(node))
                    else:
                        vuln_count["EBID_low"] = vuln_count["EBID_low"]+1
                else:
                    if "Unknown" in str(node):
                        if borvo_flag:
                            vuln_count["EBID_unknown"].append(str(node))
                        else:
                            vuln_count["EBID_unknown"] = vuln_count["EBID_unknown"]+1
                    else:
                        if borvo_flag:
                            vuln_count["EBID_neg"].append(str(node))
                        else:
                            vuln_count["EBID_neg"] = vuln_count["EBID_neg"] +1    

            av_regex=r"(?<=\bAV:).{1}"

            if "NOFIX" in str(node):
                 marker += "-dot" 

            cursor = conn.execute("SELECT impact_vector from cves where id = '"+cve_assignment+"'")

            av = "Unknown"

            for row in cursor:
                if row[0]:
                    temp = re.findall(av_regex,row[0])[0]

                    if temp.upper() == "L":
                        av = "LOCAL"
                    
                    if temp.upper() == "N":
                        av = "NETWORK"

            if av == "Unknown":
                try:
                    r = requests.get("https://cve.circl.lu/api/cve/"+cve_assignment) 
                    # NULL / missing CVE entries
                    if r.json():
                        av = r.json()["access"]["vector"] 
                # Entries without a vector
                except KeyError as e:
                    pass

            if av == "LOCAL":
                string_format = "local"
                marker = "diamond" + marker
                legend_items["Local CVE"] = ["diamond","local"]
            elif av == "NETWORK":
                string_format = "network"
                marker = "cross" + marker
                legend_items["Remote CVE"] = ["cross","network"]
            else:
                string_format = "unknown"
                marker = "hash" + marker
                legend_items["Reserved CVE"] = ["hash","unknown"]

            node_text =""" <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={}">  </a>""".format(str(node),)

            vuln_node["{}_x".format(string_format)].append(x)
            vuln_node["{}_y".format(string_format)].append(y)
            vuln_node["{}_text".format(string_format)].append(node_text)
            vuln_node["{}_hover_text".format(string_format)].append(str(node) + exploits)
            vuln_node["{}_colour".format(string_format)].append(vuln_colour)
            vuln_node["{}_marker".format(string_format)].append(marker)
            vuln_node["{}_size".format(string_format)].append(node_size)


        elif any(map(str(node).__contains__, vuln_types)):
            marker = "-open"

            vuln_node["other_x"].append(x)
            vuln_node["other_y"].append(y)
            vuln_node["other_hover_text"].append(str(node))
            vuln_node["other_colour"].append(vuln_colour)
            if "EBID" in str(node):
                marker = ""
            vuln_node["other_marker"].append("triangle-up" + marker)
            vuln_node["other_size"].append(node_size)
            legend_items["Other Vuln"] = ["triangle-up","other"]

        else: 
            if str(node).strip() == container.strip():
                package_node_size.append(30)
                package_node_opacity.append(1)
                central_pos.append(x)
                central_pos.append(y)
                package_node_colour.append("white")
            else: 
                package_node_size.append(node_size)
                package_node_opacity.append(0.7)
            package_node_x.append(x)
            package_node_y.append(y)
            package_node_colour.append("white")
            legend_items["Packages"] = ["circle","packages"]
            
    conn.close()

    visible_traces = []

    for item in vuln_trace_types:

        visible_traces.append(create_vuln_trace(item,vuln_node))

    if final_loop:
        for key,value in legend_items.items():

            new_trace = go.Scatter(
            x=[central_pos[0]], y=[central_pos[1]],
            mode='markers',
            name=key,
            marker=dict(
                color="white",
                size=10,
                symbol=value[0],
                line_width=2),
            legendgroup=value[1])

            blind_traces.append(new_trace)

    package_node_trace = go.Scatter(
        x=package_node_x, y=package_node_y,
        mode='markers',
        hoverinfo='text',
        name='Packages',
        marker=dict(
            color=package_node_colour,
            size=package_node_size,
            opacity=package_node_opacity,
            symbol='circle',
            line_width=2),
        legendgroup="packages",
        showlegend=False)

    package_node_adjacencies = []
    package_node_text = []

    vuln_types = ["ALAS", "ALAS2", "BugTraq", "CVE", "CWE", "DLA","EBID", "GHSA", "GMS", "RHSA", "VULNDB"]

    for node, adjacencies in enumerate(my_graph.adjacency()):
        if not any(map(adjacencies[0].__contains__, vuln_types)):
            if not adjacencies[0].strip() == container.strip():
                package_node_text.append(adjacencies[0] + " # of CVEs: " + str((len(adjacencies[1])-1)))
            else:
                package_node_text.append(adjacencies[0] + " # of Vuln Apps: " + str(len(adjacencies[1])))

    package_node_trace.text = package_node_text

    visible_traces.extend([edge_trace, package_node_trace])

    fig = go.Figure(data=blind_traces + visible_traces)
    
    return fig, vuln_count


def node_link_plot(container_image, figures,vuln_count,scanners,per_scanner_vuln_count,vis_output_path,borvo_flag):

    final_figure = make_subplots(
        rows=2, cols=3)

    row_col = [[1,1], [1,2], [1,3], [2,3], [2,2], [2,1]]

    if ":" in container_image:
        container_image = container_image.replace(":","_").replace(".","_")


    for i in range(0, len(figures)):
        for t in figures[i].data:
            final_figure.append_trace(t, row=row_col[i][0], col=row_col[i][1])

    for i in range(0, len(scanners)):
        final_figure.update_xaxes(row=row_col[i][0], col=row_col[i][1], 
        showgrid=False, zeroline=False, showticklabels=False, title=scanners[i] + " CVEs " + str(per_scanner_vuln_count[i]))
        final_figure.update_yaxes(row=row_col[i][0], col=row_col[i][1], 
        showgrid=False, zeroline=False, showticklabels=False)

    final_figure.layout.template = "custom_dark"

    if borvo_flag:
        title_text = "{} Vulerabilities<br>Original CVE Total {} <br>Updated CVE Total {}".format(container_image,vuln_count["original_vulns"],vuln_count["updated_vulns"])

        annotations_text="""Open marker == No exploit in Exploit DB || Closed marker == Exploit found in Exploit DB<br>Orignal Image - Critical: {original_crit}
            High: {original_high}
            Medium: {original_med}
            Low: {original_low}
            Negligible: {original_neg}
            Unknown: {original_unknown}<br>Updated Image - Critical: {updated_crit}
            High: {updated_high}
            Medium: {updated_med}
            Low: {updated_low}
            Negligible: {updated_neg}
            Unknown: {updated_unknown}""".format(**vuln_count)
    
    else:
        title_text = " {} Vulerabilities<br>Total {}".format(container_image,sum(per_scanner_vuln_count))

        annotations_text="""Open marker == No exploit in Exploit DB<br>Closed marker == Exploit found in Exploit DB<br>Critical: {crit}
            High: {high}
            Medium: {med}
            Low: {low}
            Negligible: {neg}
            Unknown: {unknown}""".format(**vuln_count)

    final_figure.update_layout(
        legend=dict(
            x=-0.1,
            y=1.1,
            title_font_family="Times New Roman",
            font=dict(
                family="Courier",
                size=12,
                color="black"
            ),
            bgcolor="LightBlue",
            bordercolor="Black",
            borderwidth=1,
            # itemwidth=10000
        ),
        title=dict(
                text=title_text,
                x=0.5,
                y=0.95,
                xanchor="center",
                yanchor="top"
            ),
        titlefont_size=16,
        showlegend=False,
        hovermode="closest",
        #margin=dict(b=20,l=5,r=5,t=40),
        annotations=[ dict(
            text=annotations_text,
            showarrow=False,
            xref="paper", yref="paper",
            x=-0.1, y=-0.1,
            font=dict(
                size=11
             ) ) ]
    )
    
    final_figure.update_layout(showlegend=True)
    final_figure.update_coloraxes(showscale=False)
    final_figure.update(layout_coloraxis_showscale=False)

    sub_plot_output = os.path.join(vis_output_path,"sub_plots")

    if not os.path.isdir(sub_plot_output):
        os.makedirs(sub_plot_output)

    final_figure.write_html("{}/{}.html".format(sub_plot_output,container_image))

    final_figure.show()
