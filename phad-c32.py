#! /usr/bin/python
"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
import numpy as np
from pprint import pprint
from utils import Clusterer
from utils.parser import np_parse_pcap


def _clusterAndScore(days):
    print("Clustering the header fields...")

    feature_keys = ['Ethernet_size', 'Ethernet_dstHi', 'Ethernet_dstLow',
                    'Ethernet_srcHi', 'Ethernet_srcLow', 'Ethernet_type',
                    'IPv4_ihl', 'IPv4_tos', 'IPv4_length', 'IPv4_id',
                    'IPv4_offset', 'IPv4_ttl', 'IPv4_proto', 'IPv4_chksum',
                    'IPv4_src', 'IPv4_dst', 'ICMP_type', 'ICMP_code',
                    'ICMP_chksum', 'TCP_sport', 'TCP_dport', 'TCP_seqNo',
                    'TCP_ackNo', 'TCP_dataOffset', 'TCP_flags', 'TCP_window',
                    'TCP_chksum', 'TCP_urgPtr', 'TCP_options', 'UDP_sport',
                    'UDP_dport', 'UDP_length', 'UDP_chksum']
    features = {key: Clusterer() for key in feature_keys}

    for day in days:
        for packet_hdrs in day[0]:
            # Iterate over feature_keys so indexes are the correct order
            for i, feature in enumerate(feature_keys):
                if packet_hdrs[i] != -1:
                    # NOTE(lwhsiao): Right now we're just doing this all
                    # together. One potential way to parallelize is to instead
                    # update each Clusterer in parallel, providing a single
                    # column of packet headers to each, rather than processing
                    # them all together.
                    features[feature].add(packet_hdrs[i])

    model = {}
    for feature in features:
        model[feature] = (features[feature].getDistinct(),
                          features[feature].getTotal())
    pprint(model)


def _parseTrainingData():
    """Parse the week 3 training data."""
    try:
        week3_data = np.load(open("data/week3_data.npy", "rb"))
        print("Loaded pre-parsed training data...")
    except IOError:
        print("Parsing the training data...")
        # Parse the Training Data
        trainingFiles = [
            "./data/training/week3_monday_inside",
            "./data/training/week3_monday_extra_inside",
            "./data/training/week3_tuesday_inside",
            "./data/training/week3_tuesday_extra_inside",
            "./data/training/week3_wednesday_inside",
            "./data/training/week3_wednesday_extra_inside",
            "./data/training/week3_thursday_inside",
            "./data/training/week3_friday_inside"
        ]
        week3_data = np_parse_pcap(trainingFiles)

        np.save(open("data/week3_data.npy", "wb"), week3_data)

    return week3_data

def main():
    """Run the PHAD-C32 experiment."""
    week3_data = _parseTrainingData()

    # Clust ering header data
    _clusterAndScore(week3_data)

    return

if __name__ == '__main__':
    main()
