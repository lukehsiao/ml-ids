#!/usr/bin/env python

import sys, os, re
import argparse
from labeler import read_attack_file, ip2int, int2ip, checkIPsEqual
from time_functions import datetime_to_tstamp
import numpy as np
import matplotlib
import matplotlib.pyplot as plt

def check_results(results_file, attacks_file, threshold, make_plots):
    threshold_vals = parse_threshold(threshold)
    print "Using threshold = {}".format(threshold_vals)
    attack_list, num_unique_attacks = read_attack_file(attacks_file)
    raw_results = read_results(results_file)
    final_results = get_final_results(raw_results, attack_list)
    pc_attacks_detected = []
    num_TP_per_day = []
    num_FP = []
    num_FP_per_day = []
    for thresh in threshold_vals:
        total_unique_TP, total_TP_per_day, total_FP, total_FP_per_day = classify_results(final_results, thresh)
        print "total_unique_TP = {}".format(total_unique_TP)
        pc_attacks_detected.append(float(total_unique_TP)/float(num_unique_attacks)*100)
        num_FP.append(total_FP)
        num_FP_per_day.append(total_FP_per_day)
        num_TP_per_day.append(total_TP_per_day)

    data = {}
    data['threshold_vals'] = threshold_vals
    data['pc_attacks_detected'] = pc_attacks_detected
    data['num_FP'] = num_FP
    data['num_FP_per_day'] = num_FP_per_day
    data['num_TP_per_day'] = num_TP_per_day

    if make_plots:
        plot_results(data)
    else:
        print_results(final_results, data)

def plot_results(data):
    # plot the pc_attacks_detected vs threshold_vals
    plt.figure()
    plt.plot(data['threshold_vals'], data['pc_attacks_detected'], marker='o')
    plt.xlabel('Threshold Values')
    plt.ylabel('% of Total Attacks Detected')
    plt.title('% Total Attacks Detected vs. Threshold Value')

    # plot the total # false positives vs threshold values
    plt.figure()
    plt.semilogy(data['threshold_vals'], data['num_FP'], marker='o')
    plt.xlabel('Threshold Values')
    plt.ylabel('Total # False Positives')
    plt.title('Total # False Positives vs. Threshold Value')

    font = {'family' : 'normal',
            'weight' : 'bold',
            'size'   : 22}
    matplotlib.rc('font', **font)

    plt.show()


def parse_threshold(threshold):
    """
    Inputs:
      - threshold string of the form: start:stop:num_points
    Returns:
      - numpy array of threshold values
    """
    threshold_fmat = r'(?P<start>[\d\.]*):(?P<stop>[\d\.]*):(?P<num_points>\d*)$'
    match = re.search(threshold_fmat, threshold)
    if match is None:
        print >> sys.stderr, "ERROR: invalid threshold specified"
        sys.exit(1)
    try:
        start = float(match.group('start'))
        stop = float(match.group('stop'))
        num_points = int(match.group('num_points'))
    except ValueError as e:
        print >> sys.stderr, "ERROR: invalid threshold specified"
        sys.exit(1)
    return np.linspace(start, stop, num_points)

def get_final_results(raw_results, attack_list):
    """
    Inputs:
      - raw_results : list of dictionaries from reading results.csv file
      - attack_list : list of dictionaries of all attacks from attack file

    Outputs:
      - final_results : raw_results appended with attack info and pruned so that
          results that detect duplicate attacks are removed
    """
    detected_attackIDs = []
    final_results = []
    # sort the raw_results by score from high to low so that only the
    # highest scoring of any duplicate attacks will appear in the final_results
    raw_results = sorted(raw_results, key=getScoreVal)
    for result in raw_results:
        isAttack, attackID, attackName = get_attack_info(result, attack_list)
        result['attackID'] = attackID
        result['isAttack'] = isAttack
        result['attack_name'] = attackName
        if isAttack and attackID not in detected_attackIDs:
            # record this attack ID so that we know we've seen it before
            detected_attackIDs.append(attackID)
            # don't include any duplicate attack detections in the final results
            final_results.append(result)
        elif not isAttack:
            # include all results that do not detect an attack in the final results
            final_results.append(result)
    return final_results

def classify_results(final_results, threshold):
    """
    Inputs:
      - final_results : list of dictionaries of results, that contain info as to whether or not
          this is an actual attack

    Returns:
      - total_unique_TP : total number unique attacks classified as attacks
      - total_FP : total number of false positives
    """
    total_unique_TP = 0
    total_TP_per_day = {}
    total_FP = 0
    total_FP_per_day = {}
    for result in final_results:
        if result['score'] > threshold:
            if result['isAttack']:
                total_unique_TP += 1
                if result['date'] not in total_TP_per_day.keys():
                    total_TP_per_day[result['date']] = 1
                else:
                    total_TP_per_day[result['date']] += 1
            else:
                total_FP += 1
                if result['date'] not in total_FP_per_day.keys():
                    total_FP_per_day[result['date']] = 1
                else:
                    total_FP_per_day[result['date']] += 1
    return total_unique_TP, total_TP_per_day, total_FP, total_FP_per_day

def get_attack_info(result_dic, attack_list, leeway=60):
    """
    Inputs:
      - result_dic : dictionary of one result
      - attack_list : list of attacks

    Returns:
      - isAttack - True if the result corresponds to an actual attack 
      - attackID - string of attack ID, '' if not attack
      - attackName - string of attack name, '' if not an attack
    """
    isAttack = False
    attackID = ''
    attackName = ''
    tstamp = result_dic['timestamp'] 
    dstIP = result_dic['dstIP']
    for attack in attack_list:
        if tstamp >= (attack['range'][0] - leeway) and tstamp <= (attack['range'][1] + leeway) and checkIPsEqual(dstIP, attack['dstIP']):
            isAttack = True
            attackID = attack['ID']
            attackName = attack['name']
            return isAttack, attackID, attackName
    return isAttack, attackID, attackName

def getScoreVal(item):
    return -item['score']

def print_results(final_results, data, pthresh=0.5):

    threshold_vals = data['threshold_vals']
    pc_attacks_detected = data['pc_attacks_detected']
    num_FP = data['num_FP']
    num_FP_per_day = data['num_FP_per_day']
    num_TP_per_day = data['num_TP_per_day']
    title_fmat = '{: >12} {: >10} {: >18}  {: >6} {: >6} {: >25} {: >25}'
    line_fmat = '{: >12} {: >10} {: >18}  {:.6f} {: >4} {: >25} {: >25}'
    count = 0
    print "For threshold = {}".format(pthresh)
    print "Top 20 scores: "
    print title_fmat.format('Date', 'Time', 'Dest IP Addr', 'Score', 'Det', 'Attack Name', 'Most Anom Field')
    for res in final_results:
        if res['isAttack'] and res['score'] >= pthresh:
            class_type = 'TP'
        elif not res['isAttack'] and res['score'] >= pthresh:
            class_type = 'FP'
        else:
            class_type = 'N'
        if count < 20:
            print line_fmat.format(res['date'], res['time'], res['dstIP'], res['score'], class_type, res['attack_name'], res['anom_field'] + ' ' + str(int(float(res['anom_field_pc'])*100)) + '%')
            count += 1
    print "Detection Results:"
    print "------------------"
    line_fmat = "{: >25} {: >25} {: >25}"
    print line_fmat.format('threshold val', '% attacks detected', 'Total Num FP')
    for thresh, pc_detect, fp in zip(threshold_vals, pc_attacks_detected, num_FP):
        print line_fmat.format(thresh, pc_detect, fp)

    for thresh, fp_per_day_dic, tp_per_day_dic in zip(threshold_vals, num_FP_per_day, num_TP_per_day):
        print "threshold = {}, False Positives = {}".format(thresh, fp_per_day_dic)
        print "threshold = {}, True Positives = {}".format(thresh, tp_per_day_dic)


def read_results(results_file):
    result_fmat = r'(?P<date>.*),(?P<time>.*),(?P<dstIP>.*),(?P<score>.*),(?P<anom_field>.*),(?P<anom_field_pc>[\d\.]*)[\r\n$]'
    with open(results_file) as f:
        contents = f.read()
    matches = re.finditer(result_fmat, contents, re.M)
    results = [m.groupdict() for m in matches]
    for dic in results:
        dic['timestamp'] = datetime_to_tstamp(dic['date'], dic['time'])
        dic['score'] = float(dic['score'])
    return results

def get_attack_info(result_dic, attack_list, threshold=0.5, leeway=60):
    if result_dic['score'] <= threshold:
        return '', '', 'N'
    tstamp = result_dic['timestamp']
    dstIP = result_dic['dstIP']
    for attack in attack_list:
        if tstamp >= (attack['range'][0] - leeway) and tstamp <= (attack['range'][1] + leeway) and checkIPsEqual(dstIP, attack['dstIP']):
            return attack['ID'], attack['name'], 'TP'
    return '', '', 'FP'


def main():
    """Check the resulting csv file of packet classifications to see if actual attacks were detected"""
    parser = argparse.ArgumentParser()
    parser.add_argument('results_file', type=str, help="the results.csv file")
    parser.add_argument('attacks_file', type=str, help="the actual attacks file")
    parser.add_argument('--thresh', type=str, default='0.5:0.5:1', help="range of thresholds to try. Format: start:stop:num_points, default: 0.5:0.5:1")
    parser.add_argument('--plot', action='store_true', help="make plots")
    args = parser.parse_args()

    check_results(args.results_file, args.attacks_file, args.thresh, args.plot)


if __name__ == '__main__':
    main()

