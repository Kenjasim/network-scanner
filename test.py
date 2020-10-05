from struct import pack, unpack
import socket, binascii
import uuid

#TODO Get IP address using some way: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
# Port over to scan
# thread and run


HDWR_TYPE = 0x0001
PROTO = 0x0800
HDWR_LEN = 0x06
PROTO_LEN = 0x04
OP = 0x0001
SND_MAC = [int(("%x" % uuid.getnode())[i:i+2], 16) for i in range(0, 12, 2)]
SND_IP = [192, 168, 1, 69]
TGT_MAC = b'\x00\x00\x00\x00\x00\x00'
TGT_IP = [192, 168, 1, 70]
BRD_MAC = b'\xff\xff\xff\xff\xff\xff'
ETH_TYPE = 0x0806

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

s.bind(("wlp3s0", 0))

ETH_FRAME = [
    BRD_MAC,
    pack('!6B', *SND_MAC),
    pack('!H', ETH_TYPE), # HRD
]

ARP_FRAME = [
    pack('!H', HDWR_TYPE), # HRD
    pack('!H', PROTO), # PRO
    pack('!B', HDWR_LEN), # HLN
    pack('!B', PROTO_LEN), # PLN
    pack('!H', OP), # OP
    pack('!6B', *SND_MAC), # SHA
    pack("!4B", *SND_IP), # SPA
    TGT_MAC, # THA
    pack("!4B", *TGT_IP), # TPA
]

frames = ETH_FRAME + ARP_FRAME
packet = b''.join(frames)
s.send(packet)
packet = s.recv(65565)


eth_head = packet[0:14]
(_, eth_hwsrc, _) = unpack("!6s6s2s", eth_head)

mac = ':'.join(eth_hwsrc.hex()[i:i+2] for i in range(0,12,2))
print(mac)

arp_head = packet[14:42]
(_,_,_,_,_,_,arp_ip,_,_) = unpack('2s2s1s1s2s6s4s6s4s',arp_head)
print (socket.inet_ntoa(arp_ip))
