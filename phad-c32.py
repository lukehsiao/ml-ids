#! /usr/bin/python
"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
from utils.parser import np_parse_pcap
from utils import Clusterer


def _clusterAndScore(days):
    etherSize    = Clusterer()
    etherDestHi  = Clusterer()
    etherDestLo  = Clusterer()
    etherSrcHi   = Clusterer()
    etherSrcLo   = Clusterer()
    etherProto   = Clusterer()
    IPHdrLen     = Clusterer()
    IPTOS        = Clusterer()
    IPLen        = Clusterer()
    IPFragID     = Clusterer()
    IPFragPtr    = Clusterer()
    IPTTL        = Clusterer()
    IPProto      = Clusterer()
    IPCksm       = Clusterer()
    IPSrc        = Clusterer()
    IPDest       = Clusterer()
    TCPSrcPort   = Clusterer()
    TCPDestPort  = Clusterer()
    TCPSeq       = Clusterer()
    TCPAck       = Clusterer()
    TCPHdrLen    = Clusterer()
    TCPFlags     = Clusterer()
    TCPWndSz     = Clusterer()
    TCPCksm      = Clusterer()
    TCPUrgPtr    = Clusterer()
    TCPOption    = Clusterer()
    UDPSrcPort   = Clusterer()
    UDPDestPort  = Clusterer()
    UDPLen       = Clusterer()
    UDPCksm      = Clusterer()
    ICMPType     = Clusterer()
    ICMPCode     = Clusterer()
    ICMPCksm     = Clusterer()

    for day in days:
        for ether_size in day[0][:, 0]:
            cluster.add(ether_size)

    print(str(cluster.getDistinct()) + "/" + str(cluster.getTotal()))
    print(cluster.getClusters())

def _parseTrainingData():
    """Parse the week 3 training data."""
    # Parse the Training Data
    w3_m = np_parse_pcap("./data/training/week3_monday_inside")
    w3_me = np_parse_pcap("./data/training/week3_monday_extra_inside")
    w3_t = np_parse_pcap("./data/training/week3_tuesday_inside")
    w3_te = np_parse_pcap("./data/training/week3_tuesday_extra_inside")
    w3_w = np_parse_pcap("./data/training/week3_wednesday_inside")
    w3_we = np_parse_pcap("./data/training/week3_wednesday_extra_inside")
    w3_th = np_parse_pcap("./data/training/week3_thursday_inside")
    w3_f = np_parse_pcap("./data/training/week3_friday_inside")

    return (w3_m, w3_me, w3_t, w3_te, w3_w, w3_we, w3_th, w3_f)

def main():
    """Run the PHAD-C32 experiment."""
    week3_data = _parseTrainingData()

    # Clustering header data
    _clusterAndScore(week3_data)

    return

if __name__ == '__main__':
    main()
