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

if __name__ == '__main__':
    unittest.main()
