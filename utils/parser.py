from __future__ import print_function
import sys, os
from scapy_patch import *
import re, csv, struct, socket
import numpy as np

TYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


def eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def parse_pcap(filename):
    """Parse a pcap file into a list of packets.

    Inputs:
      - filename : a pcap file that contains packets to parse

    Returns:
      - a list of dictionaries representing the parsed packets
    """
    pkts = rdpcap_raw(filename)
    plist = []
    for p_bytes, _ in pkts:
        pkt = parse_pkt(p_bytes)
        pkts.append(pkt)
    return plist


def np_parse_pcap(filename):
    """Parse a pcap file into a numpy matrix.
    Inputs:
      - filename : a pcap file that contains packets to parse

    Returns:
      - a numpy matrix where each row is a packet and each column is a
        different field
      - a numpy column array containing the corresponding time of each packet
    """
    features = [
        'Ethernet_size',
        'Ethernet_dstHi',
        'Ethernet_dstLow',
        'Ethernet_srcHi',
        'Ethernet_srcLow',
        'Ethernet_type',
        'IPv4_ihl',
        'IPv4_tos',
        'IPv4_length',
        'IPv4_id',
        'IPv4_offset',
        'IPv4_ttl',
        'IPv4_proto',
        'IPv4_chksum',
        'IPv4_src',
        'IPv4_dst',
        'ICMP_type',
        'ICMP_code',
        'ICMP_chksum',
        'TCP_sport',
        'TCP_dport',
        'TCP_seqNo',
        'TCP_ackNo',
        'TCP_dataOffset',
        'TCP_flags',
        'TCP_window',
        'TCP_chksum',
        'TCP_urgPtr',
        'TCP_options',
        'UDP_sport',
        'UDP_dport',
        'UDP_length',
        'UDP_chksum',
    ]
    pkts = rdpcap_raw(filename)
    design_mat = -1*np.ones((len(pkts), len(features)), dtype=int)
    time_arr = np.zeros((len(pkts), 1))
    count = 0
    for pkt_bytes, (sec, usec, wirelen) in pkts:
        time_arr[count] = float(sec) + float(usec)*1e-6
        ind = features.index('Ethernet_size')
        design_mat[count, ind] = wirelen
        pkt = parse_pkt(pkt_bytes)
        for header in pkt.keys():
            for field in pkt[header].keys():
                key = header + '_' + field
                ind = features.index(key)
                design_mat[count, ind] = pkt[header][field]
        count += 1
    return design_mat, time_arr


def parse_pkt(pkt_bytes):
    """Parse the given packet byte string into a dictionary."""
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


def parse_ethernet(pkt_bytes):
    """Parse the Ethernet header out of the given bytes."""
    total_len = 14
    eth = {}
    if len(pkt_bytes) < total_len:
        eprint("ERROR: not enough bytes to parse Ethernet header")
        return eth, pkt_bytes
    eth['dstHi'] = struct.unpack(">L", '\x00' + pkt_bytes[0:3])[0]
    eth['dstLow'] = struct.unpack(">L", '\x00' + pkt_bytes[3:6])[0]
    eth['srcHi'] = struct.unpack(">L", '\x00' + pkt_bytes[6:9])[0]
    eth['srcLow'] = struct.unpack(">L", '\x00' + pkt_bytes[9:12])[0]
    eth['type'] = struct.unpack(">H", pkt_bytes[12:14])[0]
    return eth, pkt_bytes[total_len:]


def parse_ipv4(pkt_bytes):
    total_len = 20
    ipv4 = {}
    if len(pkt_bytes) < total_len:
        eprint("ERROR: not enough bytes to parse IPv4 header")
        return ipv4, pkt_bytes
    # only want least significant bits
    ipv4['ihl'] = struct.unpack(">B", pkt_bytes[0:1])[0] & 0b00001111
    if (ipv4['ihl'] > 5):
        eprint("WARNING: did not parse ipv4 options from packet")
    ipv4['tos'] = struct.unpack(">B", pkt_bytes[1:2])[0]
    ipv4['length'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    ipv4['id'] = struct.unpack(">H", pkt_bytes[4:6])[0]
    ## only want 3 most significant bits
    #ipv4['flags'] = struct.unpack(">B", pkt_bytes[6:7])[0] >> 5
    # get rid of most significant 3 bits
    ipv4['offset'] = struct.unpack(">H", pkt_bytes[6:8])[0] & 0b0001111111111111
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
        eprint("ERROR: not enough bytes to parse ICMP header")
        return icmp, pkt_bytes
    icmp['type'] = struct.unpack(">B", pkt_bytes[0:1])[0]
    icmp['code'] = struct.unpack(">B", pkt_bytes[1:2])[0]
    icmp['chksum'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    return icmp, pkt_bytes[total_len:]


def parse_tcp(pkt_bytes):
    total_len = 20
    tcp = {}
    if len(pkt_bytes) < total_len:
        eprint("ERROR: not enough bytes to parse TCP header")
        return tcp, pkt_bytes
    tcp['sport'] = struct.unpack(">H", pkt_bytes[0:2])[0]
    tcp['dport'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    tcp['seqNo'] = struct.unpack(">L", pkt_bytes[4:8])[0]
    tcp['ackNo'] = struct.unpack(">L", pkt_bytes[8:12])[0]
    # just the 4 most significant bits
    tcp['dataOffset'] = struct.unpack(">B", pkt_bytes[12:13])[0] >> 4
    # & 0b11000000 # dont care about 2 most signifiant bits
    tcp['flags'] = struct.unpack(">B", pkt_bytes[13:14])[0]
    tcp['window'] = struct.unpack(">H", pkt_bytes[14:16])[0]
    tcp['chksum'] = struct.unpack(">H", pkt_bytes[16:18])[0]
    tcp['urgPtr'] = struct.unpack(">H", pkt_bytes[18:20])[0]
    if (tcp['dataOffset'] > 5):
        tcp['options'] = struct.unpack(">L", pkt_bytes[20:24])[0]
        total_len += 4
    return tcp, pkt_bytes[total_len:]


def parse_udp(pkt_bytes):
    total_len = 8
    udp = {}
    if len(pkt_bytes) < total_len:
        eprint("ERROR: not enough bytes to parse UDP header")
        return udp, pkt_bytes
    udp['sport'] = struct.unpack(">H", pkt_bytes[0:2])[0]
    udp['dport'] = struct.unpack(">H", pkt_bytes[2:4])[0]
    udp['length'] = struct.unpack(">H", pkt_bytes[4:6])[0]
    udp['chksum'] = struct.unpack(">H", pkt_bytes[6:8])[0]
    return udp, pkt_bytes[total_len:]
