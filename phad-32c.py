#! /usr/bin/python
"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
from utils.parser import np_parse_pcap

def main():
    """Run the PHAD-C32 experiment."""
    data = np_parse_pcap("./data/training/week1_friday_inside")
    import pdb; pdb.set_trace()
    return

if __name__ == '__main__':
    main()
