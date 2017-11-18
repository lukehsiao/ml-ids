
import sys, os, re, json
from time_functions import *
from pcap_parser import * 
import numpy as np
from multiprocessing import Pool, cpu_count

def make_label_data():
    proj_dir = os.path.expandvars('$ML_IDS_DIR')
    test_data_dir = os.path.join(proj_dir, 'data/testing')
    pcaps = [
        'week4_monday_inside',
        'week4_wednesday_inside',
        'week4_thursday_inside',
        'week4_friday_inside',
        'week5_monday_inside',
        'week5_tuesday_inside',
        'week5_wednesday_inside',
        'week5_thursday_inside',
        'week5_friday_inside',
    ]
    pcap_paths = [os.path.join(test_data_dir, pcap) for pcap in pcaps]
    attack_files = [os.path.join(proj_dir, 'data/master-listfile-condensed.txt')]*len(pcap_paths)
#    attack_files = [os.path.join(proj_dir, 'data/master-listfile-testing.txt')]*len(pcap_paths)
    input_data = zip(pcap_paths, attack_files)
    # launch parallel processes that reads both the pcap and the attacks file and writes the label data
    p = Pool(cpu_count())
    result = p.map(label_packets, input_data)

#def label_attacks(attack_file, pcap_file):
#    """
#    Inputs:
#      - attack_file: the master-listfile-condensed.txt file
#      - data_list: a list of tuples of the form (design_matrix, time_vector)
#
#       Returns:
#         - a list of column vectors whose entries are wither 1 or 0 indicating
#           whether or not the packet was involved in an attack according to the
#           provided attack_file
#    """
#    attacks = read_attack_file(attack_file)
#    input_data = [(packets, times, attacks) for (packets, times) in data_list]
#    p = Pool(cpu_count())
#    result = p.map(label_packets, input_data)
##    result = []
##    for data in input_data:
##        result.append(label_packets(data))
#    return result

def read_attack_file(filename):
    label_fmat = r'(?P<ID>[\d]+\.\d{6})(?P<date>\d{2}/\d{2}/\d{4}) (?P<time>\d{2}:\d{2}:\d{2})  (?P<duration>\d{2}:\d{2}:\d{2}) (?P<dstIP>\d{3}\.\d{3}\.\d{3}\.\d{3})(?P<name>.{10}) (?P<insider>.{8}) (?P<manual>.{7}) (?P<console>.{7}) (?P<success>.{8}) (?P<aDump>.{6}) (?P<oDump>.{5}) (?P<iDumpBSM>.{9}) (?P<SysLogs>.{7}) (?P<FSListing>.{9}) (?P<StealthyNew>.{12}) (?P<Category>.*$)'
    with open(filename) as f:
        contents = f.read()
    matches = re.finditer(label_fmat, contents, re.M)
    attack_list = make_attack_list(matches)
    return attack_list
    

def label_packets(input_tuple):
    pcap_file, attack_file = input_tuple
    # read pcap file
    packets, times = np_parse_pcap_worker(pcap_file)
    # read attack_file
    attacks = read_attack_file(attack_file)

#    packets, times, attacks = input_tuple
    num_pkts, num_features = packets.shape
    labels = np.zeros((num_pkts, 1))
    attack_ids = {}
    dstIP_indicator = np.zeros((num_features,1), dtype=int)
    dstIP_indicator[features.index('IPv4_dst')] = 1
    for dic in attacks:
#        time_elems = np.in1d(times, range(dic['range'][0], dic['range'][1]+1))
        time_low_elems = np.greater_equal(times, dic['range'][0])
        time_high_elems = np.less_equal(times, dic['range'][0])
        time_elems = np.logical_and(time_low_elems, time_high_elems)
        dstIPs = np.dot(packets, dstIP_indicator)
        dstIP_elems = np.equal(dstIPs, dic['dstIP'])
        # array of bools indicating which packets are involved in the attack
        attack_elems = np.logical_and(time_elems, dstIP_elems)
        # include these attack elements in the labels
        labels = np.logical_or(labels, attack_elems)
        # record attack IDs for each packet in the attack
        for elem, i in zip(attack_elems, range(num_pkts)):
            if elem == 1:
                attack_ids[i] = dic['ID'] 

    # create data/testing/labels dir if it does not exist
    outDir = os.path.expandvars('$ML_IDS_DIR/data/testing/labels')
    if not os.path.exists(outDir):
        os.makedirs(outDir)

    labels_prefix = os.path.join(outDir, 'labels')
    attackIDs_prefix = os.path.join(outDir, 'attackIDs')
    pcap = os.path.basename(pcap_file)
    np.save(labels_prefix + '_' + pcap, labels)
    with open(attackIDs_prefix + '_' + pcap, 'w') as f:
        json.dump(attack_ids, f)
    return None
 

#def check_attack(pkt, time, attacks):
#    dstIP_index = features.index('IPv4_dst')
#    dstIP = pkt[dstIP_index]
#    for dic in attacks:
#        if dic['range'][0] <= time and time <= dic['range'][1] and dstIP == dic['dstIP']:
#            return 1
#    return 0

def make_attack_list(matches):
    result = []
    for m in matches:
        attack = {}
        startTime = datetime_to_tstamp(m.group('date'), m.group('time'))
        endTime = startTime + dur_to_sec(m.group('duration'))
        attack['range'] = (startTime, endTime)
        attack['dstIP'] = ip2int(m.group('dstIP'))
        attack['ID'] = m.group('ID')
        result.append(attack)
    return result










