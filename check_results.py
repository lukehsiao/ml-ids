#!/usr/bin/env python

import sys, os, re
import argparse
from labeler import read_attack_file, ip2int, int2ip
from time_functions import datetime_to_tstamp

def check_results(results_file, attacks_file, threshold=0.5):
    print "Using threshold = {}".format(threshold)
    attack_list = read_attack_file(attacks_file)
    result_list = read_results(results_file)
    result_list = sorted(result_list, key=getScoreVal)
    attack_info = []
    for result in result_list:
        data = get_attack_info(result, attack_list, threshold)
        attack_info.append(data)
    print_results(result_list, attack_info)

def getScoreVal(item):
    return -item['score']

def print_results(result_list, attack_info):
    num_FP = 0
    num_TP = 0
    title_fmat = '{: >12} {: >10} {: >18}  {: >6} {: >6} {: >25} {: >25}'
    line_fmat = '{: >12} {: >10} {: >18}  {:.6f} {: >4} {: >25} {: >25}'
    count = 0
    print title_fmat.format('Date', 'Time', 'Dest IP Addr', 'Score', 'Det', 'Attack Name', 'Most Anom Field')
    for res, (attack_id, attack_name, class_type) in zip(result_list, attack_info):
        if count < 20:
            print line_fmat.format(res['date'], res['time'], int2ip(res['dstIP']), res['score'], class_type, attack_name, res['anom_field'] + ' ' + str(int(float(res['anom_field_pc'])*100)) + '%')
            count += 1
        if class_type == 'FP':
            num_FP += 1
        elif class_type == 'TP':
            num_TP += 1
    print "Total FP = {}".format(num_FP)
    print "Total TP = {}".format(num_TP)
    print "Total = {}".format(len(result_list))



def read_results(results_file):
    result_fmat = r'(?P<date>.*),(?P<time>.*),(?P<dstIP>.*),(?P<score>.*),(?P<anom_field>.*),(?P<anom_field_pc>[\d\.]*)[\r\n$]'
    with open(results_file) as f:
        contents = f.read()
    matches = re.finditer(result_fmat, contents, re.M)
    results = [m.groupdict() for m in matches] 
    for dic in results:
        dic['dstIP'] = ip2int(dic['dstIP'])
        dic['timestamp'] = datetime_to_tstamp(dic['date'], dic['time'])
        dic['score'] = float(dic['score'])
    return results

def get_attack_info(result_dic, attack_list, threshold=0.5, leeway=60):
    if result_dic['score'] <= threshold:
        return '', '', 'N'
    tstamp = result_dic['timestamp'] 
    dstIP = result_dic['dstIP']
    for attack in attack_list:
        if tstamp >= (attack['range'][0] - leeway) and tstamp <= (attack['range'][1] + leeway) and dstIP == attack['dstIP']:
            return attack['ID'], attack['name'], 'TP'
    return '', '', 'FP'


def main():
    """Check the resulting csv file of packet classifications to see if actual attacks were detected"""
    parser = argparse.ArgumentParser()
    parser.add_argument('results_file', type=str, help="the results.csv file")
    parser.add_argument('attacks_file', type=str, help="the actual attacks file")
    parser.add_argument('--thresh', type=float, default=0.5, help="threshold to use")
    args = parser.parse_args()

    check_results(args.results_file, args.attacks_file, args.thresh)


if __name__ == '__main__':
    main()

