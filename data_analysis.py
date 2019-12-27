import copy
import csv
import errno
import json
import os
from os.path import isfile, join

ATTACK_FILE_DIR = 'info_stealer_attacks/'
NODE_FILE_DIR = ''
ATTACK_NAME_SPLITTER = '_('

enterprise_tactics = {
    0: {
        'id': 'TA0001',
        'name': 'Initial Access',
        'description': 'The adversary is trying to get into your network.'
    },
    1: {
        'id': 'TA0001',
        'name': 'Initial Access',
        'description': 'The adversary is trying to get into your network.'
    },

}

tactics_list = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion',
                'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control',
                'exfiltration', 'impact']

# global_techniques_list_sorted_on_tactics = {
#     'initial-access': [],
#     'execution': [],
#     'persistence': [],
#     'privilege-escalation': [],
#     'defense-evasion': [],
#     'credential-access': [],
#     'discovery': [],
#     'lateral-movement': [],
#     'collection': [],
#     'command-and-control': [],
#     'exfiltration': [],
#     'impact': []
# }

global_techniques_list_sorted_on_tactics = {
    'initial-access': [],
    # 'execution': [],
    # 'persistence': [],
    # 'privilege-escalation': [],
    'exe_per_prev': [],
    'defense-evasion': [],
    'credential-access': [],
    'discovery': [],
    'lateral-movement': [],
    'collection': [],
    'command-and-control': [],
    'exfiltration': [],
    'impact': []
}

apt19 = {
    "name": "APT19 (G0073)",
    "version": "2.2",
    "domain": "mitre-enterprise",
    "description": "Enterprise techniques used by APT19, ATT&CK group G0073 v1.2",
    "filters": {
        "stages": [
            "act"
        ],
        "platforms": [
            "Windows",
            "Linux",
            "macOS"
        ]
    },
    "sorting": 3,
    "viewMode": 0,
    "hideDisabled": False,
    "techniques": [
        {
            "techniqueID": "T1043",
            "tactic": "command-and-control",
            "score": 1,
            "color": "",
            "comment": "APT19 used TCP port 80 for C2.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1132",
            "tactic": "command-and-control",
            "score": 1,
            "color": "",
            "comment": "An APT19 HTTP malware variant used Base64 to encode communications to the C2 server.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1140",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "An APT19 HTTP malware variant decrypts strings using single-byte XOR keys.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1073",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 launched an HTTP malware variant and a Port 22 malware variant using a legitimate executable that loaded the malicious DLL.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1189",
            "tactic": "initial-access",
            "score": 1,
            "color": "",
            "comment": "APT19 performed a watering hole attack on forbes.com in 2014 to compromise targets.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1143",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 used -W Hidden to conceal PowerShell windows by setting the WindowStyle parameter to hidden.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1031",
            "tactic": "persistence",
            "score": 1,
            "color": "",
            "comment": "An APT19 Port 22 malware variant registers itself as a service.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1112",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 uses a Port 22 malware variant to modify several Registry keys.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1027",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 used Base64 to obfuscate commands and the payload.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1086",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "APT19 used PowerShell commands to execute payloads.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1060",
            "tactic": "persistence",
            "score": 1,
            "color": "",
            "comment": "An APT19 HTTP malware variant establishes persistence by setting the Registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Windows Debug Tools-%LOCALAPPDATA%\\.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1117",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 used Regsvr32 to bypass application whitelisting techniques.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1117",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "APT19 used Regsvr32 to bypass application whitelisting techniques.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1085",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 configured its payload to inject into the rundll32.exe.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1085",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "APT19 configured its payload to inject into the rundll32.exe.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1064",
            "tactic": "defense-evasion",
            "score": 1,
            "color": "",
            "comment": "APT19 downloaded and launched code within a SCT file.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1064",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "APT19 downloaded and launched code within a SCT file.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1193",
            "tactic": "initial-access",
            "score": 1,
            "color": "",
            "comment": "APT19 sent spearphishing emails with malicious attachments in RTF and XLSM formats to deliver initial exploits.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1071",
            "tactic": "command-and-control",
            "score": 1,
            "color": "",
            "comment": "APT19 used HTTP for C2 communications. APT19 also used an HTTP malware variant to communicate over HTTP for C2.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1082",
            "tactic": "discovery",
            "score": 1,
            "color": "",
            "comment": "APT19 collected system architecture information. APT19 used an HTTP malware variant and a Port 22 malware variant to gather the hostname and CPU information from the victim’s machine.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1016",
            "tactic": "discovery",
            "score": 1,
            "color": "",
            "comment": "APT19 used an HTTP malware variant and a Port 22 malware variant to collect the MAC address and IP address from the victim’s machine.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1033",
            "tactic": "discovery",
            "score": 1,
            "color": "",
            "comment": "APT19 used an HTTP malware variant and a Port 22 malware variant to collect the victim’s username.",
            "enabled": True,
            "metadata": []
        },
        {
            "techniqueID": "T1204",
            "tactic": "execution",
            "score": 1,
            "color": "",
            "comment": "APT19 attempted to get users to launch malicious attachments delivered via spearphishing emails.",
            "enabled": True,
            "metadata": []
        }
    ],
    "gradient": {
        "colors": [
            "#ffffff",
            "#66b1ff"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "color": "#66b1ff",
            "label": "used by APT19"
        }
    ],
    "metadata": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True
}

node_color = {
    'Attack': '255,0,0',  # red
    'Initial Access': '0,128,0',  # green
    'Execution': '192,192,192',  # silver
    'Persistence': '65,105,225',
    'Privilege Escalation': '0,0,255',
    'Defense Evasion': '0,0,205',
    'Credential Access': '210,180,140',
    'Discovery': '0,255,255',
    'Lateral Movement': '255,20,147',
    'Collection': '255,255,0',
    'Command and Control': '47,79,79',
    'Exfiltration': '173,255,47',
    'Impact': '199,21,133',
}


# def tactic_based_sorting(mitre_techniques):
#     global global_techniques_list_sorted_on_tactics
#     techniques_list_sorted_on_tactics = copy.deepcopy(global_techniques_list_sorted_on_tactics)
#     for each_technique in mitre_techniques:
#         tactic_name = each_technique['tactic']
#         technique_list = techniques_list_sorted_on_tactics[tactic_name]
#         technique_list.append(each_technique)
#
#     for tactic in list(techniques_list_sorted_on_tactics.keys()):
#         techniques = techniques_list_sorted_on_tactics[tactic]
#         if len(techniques) == 0:
#             del techniques_list_sorted_on_tactics[tactic]
#     return techniques_list_sorted_on_tactics
def tactic_based_sorting(mitre_techniques):
    global global_techniques_list_sorted_on_tactics
    techniques_list_sorted_on_tactics = copy.deepcopy(global_techniques_list_sorted_on_tactics)
    for each_technique in mitre_techniques:
        tactic_name = each_technique['tactic']
        if tactic_name == 'execution' or tactic_name == 'persistence' or tactic_name == 'privilege-escalation':
            technique_list = techniques_list_sorted_on_tactics['exe_per_prev']
        else:
            technique_list = techniques_list_sorted_on_tactics[tactic_name]
        technique_list.append(each_technique)

    for tactic in list(techniques_list_sorted_on_tactics.keys()):
        techniques = techniques_list_sorted_on_tactics[tactic]
        if len(techniques) == 0:
            del techniques_list_sorted_on_tactics[tactic]
    return techniques_list_sorted_on_tactics


def files_from_directory():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    mypath = join(dir_path, ATTACK_FILE_DIR)
    onlyfiles = [f for f in os.listdir(mypath) if f.endswith('.json') if isfile(join(mypath, f))]
    # absfiles = [join(mypath, f) for f in os.listdir(mypath) if f.endswith('.json') if isfile(join(mypath, f))]
    return onlyfiles


def read_each_attack_json(file_name):
    with open(file_name, 'r') as myfile:
        data = myfile.read()

    # parse file
    obj = json.loads(data)
    return obj


def generate_gdf_nodes():
    mitre_node_file_name = 'data/mitre_technique_nodes.csv'
    out_nodes_file_name = 'output/gdf_nodes.gdf'

    if not os.path.exists(os.path.dirname(out_nodes_file_name)):
        try:
            os.makedirs(os.path.dirname(out_nodes_file_name))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    with open(out_nodes_file_name, 'w') as f:
        f.write('nodedef>name VARCHAR, label VARCHAR, category VARCHAR, color VARCHAR\n')
        onlyfiles = files_from_directory()
        for attack_file_name in onlyfiles:
            attack_name = attack_file_name.split(ATTACK_NAME_SPLITTER)[0]
            f.write("%s,%s,Attack,'%s'\n" % (attack_name, attack_name, node_color['Attack']))

    with open(mitre_node_file_name, "r") as f:
        reader = csv.reader(f, delimiter=",")
        header = next(reader)

        with open(out_nodes_file_name, 'a') as f:
            for _, line in enumerate(reader):
                f.write("%s,%s,%s,'%s'\n" % (line[1], line[3], line[2], node_color[line[2]]))

                # if i != 0:
                #     f.write(line[1])
                #     f.write(',')
                #     f.write(line[3])
                #     f.write(',')
                #     f.write(line[2])
                #     f.write('\n')


def start_parsing(count=None):
    files_list = files_from_directory()
    all_attacks_list = []

    for each_file in files_list:
        obj = read_each_attack_json(ATTACK_FILE_DIR + each_file)
        # obj = read_each_attack_json(each_file)
        sorted_techniques = tactic_based_sorting(obj['techniques'])
        # attack_dict = {each_file.split('.')[0]: sorted_techniques}
        attack_dict = {'attack_name': each_file.split(ATTACK_NAME_SPLITTER)[0], 'sorted_techniques': sorted_techniques}
        all_attacks_list.append(attack_dict)
        if count:
            count = count - 1
            if count <= 0:
                break
    return all_attacks_list


def is_current_technique_is_bigger_than_prev(current_technique_list, prev_techniques_list):
    if len(current_technique_list) >= len(prev_techniques_list):
        return True
    else:
        return False


# TODO think about ordered dict of sorted_techniques, perhaps its not ordered
# TODO therefore need to do something like loop through the tactic list and search for tactic into the sorted_techniques
# TODO and if technique found, then build edges between them
def generate_gdf_edges(all_attacks_list):
    out_edges_file_name = 'output/gdf_edges_undirected.gdf'
    with open(out_edges_file_name, 'w') as f:
        f.write('edgedef>node1 VARCHAR,node2 VARCHAR,directed BOOLEAN, attack VARCHAR\n')
        edge_color_for_individual_attack = 0
        for each_attack in all_attacks_list:
            prev_techniques_list = each_attack['attack_name']
            sorted_techniques = each_attack['sorted_techniques']
            for tactic, technique_list in sorted_techniques.items():
                if type(prev_techniques_list) is str:
                    for technique in technique_list:
                        f.write('%s, %s, false, %s\n' % (
                            prev_techniques_list, technique['techniqueID'], str(edge_color_for_individual_attack)))
                else:
                    if is_current_technique_is_bigger_than_prev(technique_list, prev_techniques_list):
                        bigger_list = technique_list
                        smaller_list = prev_techniques_list
                    else:
                        bigger_list = prev_techniques_list
                        smaller_list = technique_list
                    for i, _ in enumerate(bigger_list):
                        index_for_smaller_list = i
                        index_for_smaller_list = index_for_smaller_list % len(smaller_list)
                        src_technique_id = bigger_list[i]['techniqueID']
                        dst_technique_id = smaller_list[index_for_smaller_list]['techniqueID']
                        if src_technique_id != dst_technique_id:
                            f.write('%s, %s, false, %s\n' % (
                                src_technique_id, dst_technique_id, str(edge_color_for_individual_attack)))

                prev_techniques_list = technique_list
            edge_color_for_individual_attack = edge_color_for_individual_attack + 1


# TODO think about ordered dict of sorted_techniques, perhaps its not ordered
# TODO therefore need to do something like loop through the tactic list and search for tactic into the sorted_techniques
# TODO and if technique found, then build edges between them
def generate_gdf_directed_edges(all_attacks_list):
    out_edges_file_name = 'output/gdf_edges_directed.gdf'
    with open(out_edges_file_name, 'w') as f:
        f.write('edgedef>node1 VARCHAR,node2 VARCHAR,directed BOOLEAN, attack VARCHAR\n')
        edge_color_for_individual_attack = 0
        for each_attack in all_attacks_list:
            prev_techniques_list = each_attack['attack_name']
            sorted_techniques = each_attack['sorted_techniques']
            for tactic, technique_list in sorted_techniques.items():
                if type(prev_techniques_list) is str:
                    for technique in technique_list:
                        f.write('%s, %s, true, %s\n' % (
                            prev_techniques_list, technique['techniqueID'], str(edge_color_for_individual_attack)))
                else:
                    if is_current_technique_is_bigger_than_prev(technique_list, prev_techniques_list):
                        bigger_list = technique_list
                        smaller_list = prev_techniques_list
                        edge_direction_bigger_to_smaller = False
                    else:
                        bigger_list = prev_techniques_list
                        smaller_list = technique_list
                        edge_direction_bigger_to_smaller = True
                    for i, _ in enumerate(bigger_list):
                        index_for_smaller_list = i
                        index_for_smaller_list = index_for_smaller_list % len(smaller_list)
                        bigger_list_technique_id = bigger_list[i]['techniqueID']
                        smaller_list_technique_id = smaller_list[index_for_smaller_list]['techniqueID']
                        if bigger_list_technique_id != smaller_list_technique_id:
                            if edge_direction_bigger_to_smaller:
                                f.write('%s, %s, true, %s\n' % (bigger_list_technique_id, smaller_list_technique_id,
                                                                str(edge_color_for_individual_attack)))
                            else:
                                f.write('%s, %s, true, %s\n' % (smaller_list_technique_id, bigger_list_technique_id,
                                                                str(edge_color_for_individual_attack)))

                prev_techniques_list = technique_list
            edge_color_for_individual_attack = edge_color_for_individual_attack + 1


def final_gdf():
    filenames = ['output/gdf_nodes.gdf', 'output/gdf_edges_directed.gdf']
    with open('output/final_output.gdf', 'w') as outfile:
        for fname in filenames:
            with open(fname) as infile:
                for line in infile:
                    outfile.write(line)


if __name__ == '__main__':
    # tactic_based_sorting(apt19['techniques'])
    generate_gdf_nodes()
    all_attacks_list = start_parsing()
    # generate_gdf_edges(all_attacks_list)
    generate_gdf_directed_edges(all_attacks_list)
    final_gdf()
