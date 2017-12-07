
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

def read_attack_file(filename):
#    label_fmat = r'(?P<ID>[\d]+\.\d{6})(?P<date>\d{2}/\d{2}/\d{4}) (?P<time>\d{2}:\d{2}:\d{2})  (?P<duration>\d{2}:\d{2}:\d{2}) (?P<dstIP>\d{3}\.\d{3}\.\d{3}\.\d{3})(?P<name>.{10}) (?P<insider>.{8}) (?P<manual>.{7}) (?P<console>.{7}) (?P<success>.{8}) (?P<aDump>.{6}) (?P<oDump>.{5}) (?P<iDumpBSM>.{9}) (?P<SysLogs>.{7}) (?P<FSListing>.{9}) (?P<StealthyNew>.{12}) (?P<Category>.*$)'
    label_fmat = r'(?P<ID>[\d]+\.\d{6})(?P<date>\d{2}/\d{2}/\d{4}) (?P<time>\d{2}:\d{2}:\d{2})  (?P<duration>\d{2}:\d{2}:\d{2}) (?P<dstIP>\d*\.\d*\.\d*\.[\d\*]*)(?P<name>[^ ]*) .*'
    with open(filename) as f:
        contents = f.read()
    matches = re.finditer(label_fmat, contents, re.M)
    attack_list, num_unique_attacks = make_attack_list(matches)
    return attack_list, num_unique_attacks
    

def label_packets(input_tuple):
    pcap_file, attack_file = input_tuple
    # read pcap file
    packets, times = np_parse_pcap_worker(pcap_file)
    # read attack_file
    attacks, num_unique_attacks = read_attack_file(attack_file)

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
        #TODO: need to fix this because dic['dstIP'] is now a string not int and may be wildcard
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

def make_attack_list(matches):
    result = []
    attackIDs = []
    attackNames = []
    for m in matches:
        attack = {}
        startTime = datetime_to_tstamp(m.group('date'), m.group('time'))
        endTime = startTime + dur_to_sec(m.group('duration'))
        attack['range'] = (startTime, endTime)
        attack['dstIP'] = m.group('dstIP')
        attack['name'] = m.group('name')
        attack['ID'] = m.group('ID')
        result.append(attack)
        if m.group('ID') not in attackIDs:
            attackIDs.append(m.group('ID'))
        if m.group('name') not in attackNames:
            attackNames.append(m.group('name'))

    return result, len(attackIDs)


def ip2int(addr):
    nums = addr.split('.')
    nums = map(int, nums)
    nums = map(str, nums)
    new_addr = '.'.join(nums)
    return struct.unpack("!I", socket.inet_aton(new_addr))[0] 

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def checkIPsEqual(ip1, ip2):
    """Check if two IP addresses are equal, may be wildcard for last byte
    Inputs:
      - ip1 and ip2 : two IP addresses as strings
    """
    ip1_vals = ip1.split('.')    
    ip2_vals = ip2.split('.')    
    if (len(ip1_vals) != 4 and len(ip2_vals) != 4):
        print >> sys.stderr, "ERROR: checkIPsEqual: invalid IP address"
        sys.exit(1)
    if ip1_vals[3] == '*' or ip2_vals[3] == '*':
        ip1_vals = map(int, ip1_vals[0:3])
        ip2_vals = map(int, ip2_vals[0:3])
    else:
        ip1_vals = map(int, ip1_vals)
        ip2_vals = map(int, ip2_vals)
    return ip1_vals == ip2_vals



