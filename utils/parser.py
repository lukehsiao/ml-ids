
import sys, os
from scapy_patch import *
import re, csv, struct, socket

TYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

"""
Inputs:
  - filename : a pcap file that contains packets to parse

Returns:
  - a list of dictionaries representing the parsed packets
"""
def parse_pcap(filename):
    pkts = rdpcap_raw(filename)
    # extract just the packet bytes
    pkt_bytes = [p[0] for p in pkts]
    pkts = []
    for p_bytes in pkt_bytes:
        pkt = parse_pkt(p_bytes)
        pkts.append(pkt)
    return pkts

"""
Parse the given packet byte string into a dictionary
"""
def parse_pkt(pkt_bytes):
    pkt = {}
    pkt['Ethernet'], pkt_bytes = parse_ethernet(pkt_bytes)
    if pkt['Ethernet']['type'] == TYPE_IPV4:
        pkt['IPv4'], pkt_bytes = parse_ipv4(pkt_bytes)
        if pkt['IPv4']['proto'] == PROTO_ICMP:
            pkt['ICMP'], pkt_bytes = parse_icmp(pkt_bytes)
        elif pkt['IPv4']['proto'] == PROTO_TCP:
            pkt['TCP'], pkt_bytes = parse_tcp(pkt_bytes)
        elif pkt['IPv4']['proto'] == PROTO_UDP:
            pkt['UDP'], pkt_bytes = parse_udp(pkt_bytes)
    return pkt

"""
Parse the Ethernet header out of the given bytes
"""
def parse_ethernet(pkt_bytes):
    total_len = 14
    eth = {} 
    if len(pkt_bytes) < total_len:
        print >> sys.stderr, "ERROR: not enough bytes to parse Ethernet header"
        return eth, pkt_bytes
    eth['dst_hi'] = struct.unpack(">L", '\x00' + pkt_bytes[0:3])[0]
    eth['dst_low'] = struct.unpack(">L", '\x00' + pkt_bytes[3:6])[0]
    eth['src_hi'] = struct.unpack(">L", '\x00' + pkt_bytes[6:9])[0]
    eth['src_low'] = struct.unpack(">L", '\x00' + pkt_bytes[9:12])[0]
    eth['type'] = struct.unpack(">H", pkt_bytes[12:14])[0]
    return eth, pkt_bytes[total_len:]


def parse_ipv4(pkt_bytes):
    total_len = 20
    ipv4 = {} 
    if len(pkt_bytes) < total_len:
        print >> sys.stderr, "ERROR: not enough bytes to parse IPv4 header"
        return ipv4, pkt_bytes
    ipv4['ihl'] = struct.unpack(">B", pkt_bytes[0:1])[0] & 0b00001111 # only want least significant bits
    if (ipv4['ihl'] > 5):
        print >> sys.stderr, "WARNING: did not parse ipv4 options from packet"
    ipv4['tos'] = struct.unpack(">B", pkt_bytes[1:2])[0]
    ipv4['length'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    ipv4['id'] = struct.unpack(">H", pkt_bytes[4:6])[0]
    ipv4['flags'] = struct.unpack(">B", pkt_bytes[6:7])[0] >> 5 # only want 3 most significant bits
    ipv4['offset'] = struct.unpack(">H", pkt_bytes[6:8])[0] & 0b0001111111111111 # get rid of most significant 3 bits
    ipv4['ttl'] = struct.unpack(">B", pkt_bytes[8:9])[0]
    ipv4['proto'] = struct.unpack(">B", pkt_bytes[9:10])[0]
    ipv4['chksum'] = struct.unpack(">H", pkt_bytes[10:12])[0]
    ipv4['src'] = struct.unpack(">L", pkt_bytes[12:16])[0]
    ipv4['dst'] = struct.unpack(">L", pkt_bytes[16:20])[0]
    return ipv4, pkt_bytes[total_len:]    


def parse_icmp(pkt_bytes):
    total_len = 4
    icmp = {} 
    if len(pkt_bytes) < total_len:
        print >> sys.stderr, "ERROR: not enough bytes to parse ICMP header"
        return icmp, pkt_bytes
    icmp['type'] = struct.unpack(">B", pkt_bytes[0:1])[0]
    icmp['code'] = struct.unpack(">B", pkt_bytes[1:2])[0]
    icmp['chksum'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    return icmp, pkt_bytes[total_len:]


def parse_tcp(pkt_bytes):
    total_len = 20
    tcp = {} 
    if len(pkt_bytes) < total_len:
        print >> sys.stderr, "ERROR: not enough bytes to parse TCP header"
        return tcp, pkt_bytes
    tcp['sport'] = struct.unpack(">H", pkt_bytes[0:2])[0]
    tcp['dport'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    tcp['seqNo'] = struct.unpack(">L", pkt_bytes[4:8])[0]
    tcp['ackNo'] = struct.unpack(">L", pkt_bytes[8:12])[0]
    tcp['dataOffset'] = struct.unpack(">B", pkt_bytes[12:13])[0] >> 4 # just the 4 most significant bits
#    if (tcp['dataOffset'] > 5):
#        print >> sys.stderr, "WARNING: did not parse tcp options from packet"
    tcp['flags'] = struct.unpack(">B", pkt_bytes[13:14])[0]   # & 0b11000000 # dont care about 2 most signifiant bits
    tcp['window'] = struct.unpack(">H", pkt_bytes[14:16])[0]
    tcp['chksum'] = struct.unpack(">H", pkt_bytes[16:18])[0]
    tcp['urgPtr'] = struct.unpack(">H", pkt_bytes[18:20])[0]
    return tcp, pkt_bytes[total_len:]

def parse_udp(pkt_bytes):
    total_len = 8
    udp = {} 
    if len(pkt_bytes) < total_len:
        print >> sys.stderr, "ERROR: not enough bytes to parse UDP header"
        return udp, pkt_bytes
    udp['sport'] = struct.unpack(">H", pkt_bytes[0:2])[0]
    udp['dport'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    udp['length'] = struct.unpack(">H", pkt_bytes[4:6])[0]
    udp['chksum'] = struct.unpack(">H", pkt_bytes[6:8])[0]
    return udp, pkt_bytes[total_len:]



