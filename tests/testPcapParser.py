import unittest
from utils.parser import np_parse_pcap


class TestPcapParser(unittest.TestCase):

    def setUp(self):
        self.data = np_parse_pcap(["tests/http.cap"])

    def test_basic_tcp(self):
        packets = self.data[0][0]
        self.assertEqual(packets[0][0], 62)           # Ethernet Size
        self.assertEqual(packets[0][1], 0xFEFF20)     # Ethernet Dest Hi
        self.assertEqual(packets[0][2], 0x000100)     # Ethernet Dest Lo
        self.assertEqual(packets[0][3], 0x000001)     # Ethernet Src Hi
        self.assertEqual(packets[0][4], 0x000000)     # Ethernet Src Lo
        self.assertEqual(packets[0][5], 0x0800)       # Ethernet Type
        self.assertEqual(packets[0][6], 0x5)          # IPv4 Header Len
        self.assertEqual(packets[0][7], 0x0)          # IPv4 TOS
        self.assertEqual(packets[0][8], 48)           # IPv4 Length
        self.assertEqual(packets[0][9], 0x0F41)       # IPv4 ID
        self.assertEqual(packets[0][10], 0x0)         # IPv4 Offset
        self.assertEqual(packets[0][11], 128)         # IPv4 TTL
        self.assertEqual(packets[0][12], 6)           # IPv4 Protocol
        self.assertEqual(packets[0][13], 0x91EB)      # IPv4 Checksum
        self.assertEqual(packets[0][14], 0x91FEA0ED)  # IPv4 Source
        self.assertEqual(packets[0][15], 0x41D0E4DF)  # IPv4 Dest
        self.assertEqual(packets[0][16], -1)          # ICMP Type
        self.assertEqual(packets[0][17], -1)          # ICMP Code
        self.assertEqual(packets[0][18], -1)          # ICMP Checksum
        self.assertEqual(packets[0][19], 3372)        # TCP Source Port
        self.assertEqual(packets[0][20], 80)          # TCP Dest Port
        self.assertEqual(packets[0][21], 0x38AFFE13)  # TCP SeqNo
        self.assertEqual(packets[0][22], 0)           # TCP AckNo
        self.assertEqual(packets[0][23], 7)           # TCP Data Offset
        self.assertEqual(packets[0][24], 0x2)         # TCP Flags
        self.assertEqual(packets[0][25], 8760)        # TCP Window
        self.assertEqual(packets[0][26], 0xC30C)      # TCP Checksum
        self.assertEqual(packets[0][27], 0)           # TCP Urg Ptr
        self.assertEqual(packets[0][28], 0x020405B4)  # TCP Opts
        self.assertEqual(packets[0][29], -1)          # UDP Source Port
        self.assertEqual(packets[0][30], -1)          # UDP Dest Port
        self.assertEqual(packets[0][31], -1)          # UDP Len
        self.assertEqual(packets[0][32], -1)          # UDP Checksum

    def test_basic_dns(self):
        dnsPacket = self.data[0][0][12]
        self.assertEqual(dnsPacket[0], 89)           # Ethernet Size
        self.assertEqual(dnsPacket[1], 0xFEFF20)     # Ethernet Dest Hi
        self.assertEqual(dnsPacket[2], 0x000100)     # Ethernet Dest Lo
        self.assertEqual(dnsPacket[3], 0x000001)     # Ethernet Src Hi
        self.assertEqual(dnsPacket[4], 0x000000)     # Ethernet Src Lo
        self.assertEqual(dnsPacket[5], 0x0800)       # Ethernet Type
        self.assertEqual(dnsPacket[6], 0x5)          # IPv4 Header Len
        self.assertEqual(dnsPacket[7], 0x0)          # IPv4 TOS
        self.assertEqual(dnsPacket[8], 75)           # IPv4 Length
        self.assertEqual(dnsPacket[9], 0x0F49)       # IPv4 ID
        self.assertEqual(dnsPacket[10], 0x0)         # IPv4 Offset
        self.assertEqual(dnsPacket[11], 128)         # IPv4 TTL
        self.assertEqual(dnsPacket[12], 17)          # IPv4 Protocol
        self.assertEqual(dnsPacket[13], 0x63A5)      # IPv4 Checksum
        self.assertEqual(dnsPacket[14], 0x91FEA0ED)  # IPv4 Source
        self.assertEqual(dnsPacket[15], 0x91FD02CB)  # IPv4 Dest
        self.assertEqual(dnsPacket[16], -1)          # ICMP Type
        self.assertEqual(dnsPacket[17], -1)          # ICMP Code
        self.assertEqual(dnsPacket[18], -1)          # ICMP Checksum
        self.assertEqual(dnsPacket[19], -1)          # TCP Source Port
        self.assertEqual(dnsPacket[20], -1)          # TCP Dest Port
        self.assertEqual(dnsPacket[21], -1)          # TCP SeqNo
        self.assertEqual(dnsPacket[22], -1)          # TCP AckNo
        self.assertEqual(dnsPacket[23], -1)          # TCP Data Offset
        self.assertEqual(dnsPacket[24], -1)          # TCP Flags
        self.assertEqual(dnsPacket[25], -1)          # TCP Window
        self.assertEqual(dnsPacket[26], -1)          # TCP Checksum
        self.assertEqual(dnsPacket[27], -1)          # TCP Urg Ptr
        self.assertEqual(dnsPacket[28], -1)          # TCP Opts
        self.assertEqual(dnsPacket[29], 3009)        # UDP Source Port
        self.assertEqual(dnsPacket[30], 53)          # UDP Dest Port
        self.assertEqual(dnsPacket[31], 55)          # UDP Len
        self.assertEqual(dnsPacket[32], 0x10AF)      # UDP Checksum

if __name__ == '__main__':
    unittest.main()
