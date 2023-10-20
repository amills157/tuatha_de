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

def node_data(container_image, scanner,node_edge_file_path,nofix_show,borvo_flag):

    count = 1

    last_line = ""

    node_input = []
    edge_input = []


    print(scanner)

    if scanner != "all":
        with open("{}/{}/{}_nodes.txt".format(node_edge_file_path,scanner,container_image)) as f:
            node_input = f.read().splitlines()

            last_line = node_input[-1]

        with open("{}/{}/{}_edges.txt".format(node_edge_file_path,scanner,container_image)) as f:
            edge_input = f.read().splitlines()
    
    else:
        for root, dirs, files in os.walk(node_edge_file_path):
            for file in files:
                if container_image in file:
                    full_path = os.path.join(root,file)
                    if "updated" in file and not borvo_flag:
                        continue              

                    if file.replace("_nodes.txt","").replace("_edges.txt","") != container_image:
                        continue

                    if "nodes" in file:
                        with open(full_path) as f:
                            temp = f.read().splitlines()

                            node_input += temp

                        if last_line == "":
                            last_line = node_input[-1]

                        count += 1

                    if "edges" in file:
                        with open(os.path.join(root,file)) as f:
                            temp = f.read().splitlines()

                            edge_input += temp

    parsed_node_input, parsed_edge_input = node_data_parse(node_input, edge_input,nofix_show)

    return parsed_node_input, parsed_edge_input, count, last_line,
    


def node_data_parse(node_input,edge_input,nofix_show):

    nofixes = list(filter(lambda x: "NOFIX" in x, node_input))

    for node in node_input:
        if "CVE" in node:
            cve = node.split("_")[0]

            cve_idx = [i for i, x in enumerate(node_input) if x.split("_")[0] == cve]
            cve_items = [x for i, x in enumerate(node_input) if x.split("_")[0] == cve]
            cve_sevs = [x.split("_")[1] for i, x in enumerate(cve_items)]

            r = re.compile(r"(CVE).\w.*")

            fix = ""
            cve_sev = "Unknown"

            if any(cve in sub for sub in nofixes):
                fix="_NOFIX"

            # Handling different severity cases for CVEs
            # We default to the highest severity so work top down
            if "Critical" in cve_sevs:
                cve_sev = "Critical"
            elif "High" in cve_sevs:
                cve_sev = "High"
            elif "Medium" in cve_sevs:
                cve_sev = "Medium"
            elif "Low" in cve_sevs:
                cve_sev = "Low"
            elif "Negligible" in cve_sevs:
                cve_sev = "Negligible"

            for idx in cve_idx:
                node_input[idx] = cve + "_{}{}".format(cve_sev,fix)

    parsed_edge_input = []

    for edge in edge_input:
        
        if "CVE" in edge:
            match = re.search(r"(CVE).\w.*", edge)
            if match:
                cve = match.group()
                if cve in node_input:
                    parsed_edge_input.append(edge)
                else:
                    cve_items = [x for i, x in enumerate(node_input) if x.split("_")[0] == cve.split("_")[0]]
                    test = re.sub(r, cve_items[0], edge)
                    parsed_edge_input.append(test)
        else:
            parsed_edge_input.append(edge)

    if nofix_show == "None":
        node_input = [ x for x in node_input if "_NOFIX" not in x ]
        parsed_edge_input = [ x for x in parsed_edge_input if "_NOFIX" not in x ]

        #TODO - Remove pkgs which are now dangling(?)
       

    return node_input, parsed_edge_input

def node_link_create_traces(node_input, edge_input, count, scanner, container):

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

    for x in range(1,count):
        
        size = (x * 2)
        
        new_trace = go.Scatter(
            x=[-1], y=[-1],
            mode='markers',
            name="Pkg / CVE<br>in " + str(x) + " scanner",
            marker=dict(
                color="white",
                size=size,
                symbol="circle",
                line_width=2),
            visible = "legendonly")

        blind_traces.append(new_trace)

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
    vuln_count = dict(
        crit=0,
        high=0,
        med=0,
        low=0,
        neg=0,
        unknown=0
    )

    package_node_x = []
    package_node_y = []
    package_node_size =[]
    package_node_opacity = []
    package_node_colour = []

    central_pos = []

    conn = sqlite3.connect("{}/.config/cvedb/cvedb.sqlite".format(str(Path.home())))

    legend_items = {}

    print("Processing Node data - Single Plot")
    for node in tqdm(my_graph.nodes()):
    #for node in my_graph.nodes():

        node_size = (node_input.count(node) * 10)
        
        x, y = pos[node]
        if any(map(str(node).__contains__, vuln_types)):
            if "Critical" in str(node):
                vuln_colour = ("red")
                vuln_count["crit"] = vuln_count["crit"]+1
            elif "High" in str(node):
                vuln_colour = ("orange")
                vuln_count["high"] = vuln_count["high"]+1
            elif "Medium" in str(node):
                vuln_colour = ("yellow")
                vuln_count["med"] = vuln_count["med"]+1
            elif "Low" in str(node):
                vuln_colour = ("yellowgreen")
                vuln_count["low"] = vuln_count["low"]+1
            else:
                vuln_colour = ("grey")
                if "Unknown" in str(node):
                    vuln_count["unknown"] = vuln_count["unknown"]+1
                else:
                    vuln_count["neg"] = vuln_count["neg"] +1

        if "CVE" in str(node):
            
            cve_assignment = str(node).split('_')[0]
                                    
            exploit_check = CS.edbid_from_cve(cve_assignment)

            marker = "-open"

            exploits = ""

            if len(exploit_check) >=1 :
                marker = ""
                exploits = " EBID(s): " + str(exploit_check)[1:-1]

            if "NOFIX" in str(node):
                 marker += "-dot"    

            av_regex=r"(?<=\bAV:).{1}"

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
                package_node_colour.append("white")
            package_node_x.append(x)
            package_node_y.append(y)
            

    conn.close()

    visible_traces = []

    for item in vuln_trace_types:

        visible_traces.append(create_vuln_trace(item,vuln_node))
    
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
            line_width=2),)

    package_node_adjacencies = []
    package_node_text = []

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


def node_link_plot(fig, container_image, scanner, vuln_count,vis_output_path):

    fig.layout.template = "custom_dark"

    text = "{} CVEs {} <br>Total {}".format(container_image, scanner, sum(vuln_count.values()))
        
    fig.update_layout(
        legend=dict(
            x=0,
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
            # itemwidth=30
        ),
        title=dict(
            text=text,
            x=0.5,
            y=0.95,
            xanchor="center",
            yanchor="top"
        ),
        titlefont_size=16,
        showlegend=True,
        hovermode="closest",
        margin=dict(b=20,l=5,r=5,t=40),
        annotations=[ dict(
            text="""Open marker == No exploit in Exploit DB<br>Closed marker == Exploit found in Exploit DB<br>Critical: {crit}
            High: {high}
            Medium: {med}
            Low: {low}
            Negligible: {neg}
            Unknown: {unknown}""".format(**vuln_count),
            showarrow=False,
            xref="paper", yref="paper",
            x=0.005, y=-0.002 ) ],
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )

    #fig.update_layout(showlegend=True)
    fig.update_coloraxes(showscale=False)
    fig.update(layout_coloraxis_showscale=False)

    single_plot_output = os.path.join(vis_output_path,"single_plots")

    if not os.path.isdir(single_plot_output):
        os.makedirs(single_plot_output)

    fig.write_html("{}/{}.html".format(single_plot_output,container_image))

    fig.show()