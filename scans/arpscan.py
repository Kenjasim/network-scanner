from struct import pack, unpack
import socket, binascii, uuid, subprocess, os, re, ipaddress, time
from concurrent.futures import ThreadPoolExecutor
    


#TODO Get IP address using some way: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib Port over to scan thread and run

#Constants for the packets
HDWR_TYPE = 0x0001
PROTO = 0x0800
HDWR_LEN = 0x06
PROTO_LEN = 0x04
OP = 0x0001
TGT_MAC = b'\x00\x00\x00\x00\x00\x00'
BRD_MAC = b'\xff\xff\xff\xff\xff\xff'
ETH_TYPE = 0x0806


class ARPScan():
    """
    Send ARP packets to do host detection
    """

    def run(self, ip_net):
        # Get all the interfaces
        self.interfaces = self.get_interfaces()

        # Get the hosts as a list
        ipnetwork = ipaddress.ip_network(ip_net)

        # Get a list of all hosts on the network
        hosts = list(ipnetwork.hosts())

        #Result
        result = []

        # Add a list of threads
        threads = []

        # Itterate over hosts and check which ones are up
        executor = ThreadPoolExecutor(max_workers=5)
        for ip in hosts:
            h1 = executor.submit(self.scan, str(ip), result)
            threads.append(h1)

        # Lock the main thread until they finish running
        for thread in threads:
            thread.result()

        # for ip in hosts:
        #     self.scan(str(ip), result)

        # Return the list
        return result

    def scan(self, ip, output):
        """
        Run one ARP scan on one host

        Keyword Arguments
            ip - ip address
            output - the results 
        """

        # Build the packet
        packet = self.build_packet(ip)

        if packet:
            #Send the packet
            self.send_packet(ip, packet, output)

        
    def build_packet(self, ip):
        """
        Build the packet from the constants and pack it into bytes

        Keyword Args:
            ip = The target ip to send to

        Returns
            ARP Packet
        """
        SND_MAC = [int(("%x" % uuid.getnode())[i:i+2], 16) for i in range(0, 12, 2)]
        SND_IP =  [int(x) for x in self.get_ip().split('.')]
        TGT_IP = [int(i) for i in ip.split(".")]

        # Build the ethernet farme 
        ETH_FRAME = [
            BRD_MAC,
            pack('!6B', *SND_MAC),
            pack('!H', ETH_TYPE), # HRD
        ]

        # Build the ARP frame
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
        return packet

    def send_packet(self,target_ip, packet, output, retry=1):
        """
        Send the ARP packet to the device and collect the response

        Keyword Arguments
            packet - the packet to send
            retry - the amount od times to send packet

        Returns
            ip, mac and hostname in dict
        """

        host_dict = self.send(packet, target_ip)
        
        if host_dict:
            output.append(host_dict)


    def send(self, packet, target_ip, i = 0):

        i = i + 1
    
        for _ in range(0,2):
            try:
                print(target_ip)
                print("_______________________________")
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

                #Get and bind the right interface
                mac_addr = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
                iface = self.interfaces[mac_addr]
                s.bind((iface, 0))
                
                # Send the packet
                s.send(packet)

                #Recieve the packets
                rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                rawSocket.settimeout(0.5)
                rec_packet = rawSocket.recvfrom(2048)

                # Collect the ethernet header
                eth_head = rec_packet[0][0:14]
                (_, eth_hwsrc, eth_type) = unpack("!6s6s2s", eth_head)

                # Collect arp header
                arp_head = rec_packet[0][14:42]
                (_,_,_,_,arp_op,_,arp_ip,_,_) = unpack('2s2s1s1s2s6s4s6s4s',arp_head)
                print(eth_type.hex(), arp_op.hex())
                print("_______________________________________")

                # Check if an arp packet
                if eth_type.hex() == "0806" and arp_op.hex() == "0002":

                    #MAC Address
                    mac = ':'.join(eth_hwsrc.hex()[i:i+2] for i in range(0,12,2))

                    #Convert to ip
                    ip = socket.inet_ntoa(arp_ip)

                    # Check if response is correct
                    if [int(i) for i in ip.split(".")] == [int(i) for i in target_ip.split(".")]:
                        return {"ip": ip, "mac": mac, "hostname": socket.gethostbyaddr(ip)[0]}
                    else: 
                        if i != 15:
                            return(self.send(packet, target_ip, i))
            except Exception:
                continue


    def get_interfaces(self):
        """
        Get all interfaces on a machine

        Returns
            Dictionary of mac:ifaces
        """

        #Get the interfaces on the linux machine
        ifaces = os.listdir('/sys/class/net/')

        iface_dict = {}

        # Get their mac addresses
        for iface in ifaces:
            mac = subprocess.getoutput("cat /sys/class/net/{0}/address".format(iface))
            iface_dict[mac] = iface

        return iface_dict

    def get_ip(self):
        """
        Get the local ip

        Returns
            IP address
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
