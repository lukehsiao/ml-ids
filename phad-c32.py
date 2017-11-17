#! /usr/bin/python
"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
from pprint import pprint
from utils.parser import np_parse_pcap
from utils import Clusterer


def _clusterAndScore(days):
    NUM_FIELDS = 33
    (
        etherSize,
        etherDestHi,
        etherDestLo,
        etherSrcHi,
        etherSrcLo,
        etherProto,
        IPHdrLen,
        IPTOS,
        IPLen,
        IPFragID,
        IPFragPtr,
        IPTTL,
        IPProto,
        IPCksm,
        IPSrc,
        IPDest,
        TCPSrcPort,
        TCPDestPort,
        TCPSeq,
        TCPAck,
        TCPHdrLen,
        TCPFlags,
        TCPWndSz,
        TCPCksm,
        TCPUrgPtr,
        TCPOption,
        UDPSrcPort,
        UDPDestPort,
        UDPLen,
        UDPCksm,
        ICMPType,
        ICMPCode,
        ICMPCksm
    ) = (Clusterer() for i in range(NUM_FIELDS))
    Clusters = (etherSize, etherDestHi, etherDestLo, etherSrcHi, etherSrcLo,
                etherProto, IPHdrLen, IPTOS, IPLen, IPFragID, IPFragPtr, IPTTL,
                IPProto, IPCksm, IPSrc, IPDest, TCPSrcPort, TCPDestPort,
                TCPSeq, TCPAck, TCPHdrLen, TCPFlags, TCPWndSz, TCPCksm,
                TCPUrgPtr, TCPOption, UDPSrcPort, UDPDestPort, UDPLen, UDPCksm,
                ICMPType, ICMPCode, ICMPCksm)

    for day in days:
        for packet_hdrs in day[0]:
            for i in xrange(NUM_FIELDS):
                if packet_hdrs[i] != -1:
                    Clusters[i].add(packet_hdrs[i])

    for i in xrange(NUM_FIELDS):
        pprint(str(Clusters[i].getDistinct()) + "/" +
               str(Clusters[i].getTotal()))
        #  pprint(Clusters[i].getClusters())


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
