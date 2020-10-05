from struct import pack
import socket
from pylibpcap import send_packet
from uuid import getnode as get_mac

HDWR_TYPE = 0x0001
PROTO = 0x0800
HDWR_LEN = 0x06
PROTO_LEN = 0x04
OP = 0x0001
SND_MAC = b'\xff\xff\xff\xff\xff\xff'
SND_IP = [int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')]
TGT_MAC = b'\x00\x00\x00\x00\x00\x00'
TGT_IP = [192, 168, 1, 255]

ARP_FRAME = [
    pack('!H', HDWR_TYPE), # HRD
    pack('!H', PROTO), # PRO
    pack('!B', HDWR_LEN), # HLN
    pack('!B', PROTO_LEN), # PLN 
    pack('!H', OP), # OP
    SND_MAC, # SHA
    pack("!4B", *SND_IP), # SPA
    TGT_MAC, # THA
    pack("!4B", *TGT_IP), # TPA
]

packet = b''.join(ARP_FRAME)
send_packet("en0", packet)
