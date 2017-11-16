
import sys, os
from scapy.all import *

# this is the utils from the scapy installation directory
from utils import *

@conf.commands.register
def rdpcap_raw(filename, count=-1):
    """Read a pcap file and return a packet list
count: read only <count> packets"""
    return RawPcapReader(filename).read_all(count)

