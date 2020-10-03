from scapy.all import ARP, Ether, srp
import socket, subprocess

class HostScan():
    
    @staticmethod
    def host_detetction(ip_net):
        """
        Create an ARP scan for a particular IP network

        Keyword Args
            ip_net - IP network to be scanned

        Returns
            dict of network ips and mac addresses
        """
        packet = HostScan.build_packet(ip_net)

        #send the packet
        result = srp(packet, timeout=2, verbose=0, retry=5)

        # Get the answered packets and append to devices
        answered = result[0]

        print("Found {0} up hosts on network {1}".format(len(answered), ip_net))
        devices = []
        for _,recieved in answered:
            d = {}
            d["ip"] = recieved.psrc
            d["hostname"] = HostScan.get_hostname(d["ip"])
            d["mac"] = recieved.hwsrc
            devices.append(d)

        return devices

    @staticmethod
    def build_packet(target_ip):
        """
        Builds the packet ready to be sent

         Keyword Args
            target_ip - IP to be scanned
        """
        # Create the ARP packet with the target IP network
        arp = ARP(pdst=target_ip)
        
        # ff:ff:ff:ff:ff:ff for broadcasting
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        
        # create the packet
        packet = ether/arp

        return packet

    @staticmethod
    def get_hostname(ip):
        """
        Attempts to get the hostname from the IP if it exists

        Keyword Arguments
            ip - ip address to get the host name from

        Returns
            The host name of the IP
        """
        r = socket.gethostbyaddr(ip)
        return r[0]

    

    @staticmethod
    def ping_scan(ip, result):
        """
        Scan the ip address to see if it is up or not

        Keyword Arguments
            ip - The ip address to scan
            result - list to append to
        """

        # Timeout for the processes
        timeout = 0.25
        
        cmd = "timeout " + str(timeout) + "s ping -c 1 " + str(ip) + " 2>&1 >/dev/null"
        response = subprocess.call(cmd, shell=True)

        if response == 0:
            result.append({"ip": str(ip), "hostname": HostScan.get_hostname(str(ip))})
