from scapy.all import ARP, Ether, srp
import socket, argparse
from tabulate import tabulate
import time

class NetworkScanner():
    
    @staticmethod
    def host_detetction(ip_net):
        """
        Create an ARP scan for a particular IP network

        Keyword Args
            ip_net - IP network to be scanned

        Returns
            dict of network ips and mac addresses
        """
        packet = NetworkScanner.build_packet(ip_net)

        #send the packet
        result = srp(packet, timeout=2, verbose=0, retry=5)

        # Get the answered packets and append to devices
        answered = result[0]

        print("Found {0} up hosts on network {1}".format(len(answered), ip_net))
        devices = []
        for _,recieved in answered:
            d = {}
            d["ip"] = recieved.psrc
            d["hostname"] = NetworkScanner.get_hostname(d["ip"])
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
    def create_table(items):
        """
        Create and print a table to the console
        from a dict

        Keyword Arguments:
            items - a dict of items

        Returns
            nicely formatted table string
        """
        header = items[0].keys()
        rows =  [item.values() for item in items]
        return tabulate(rows, header,tablefmt="fancy_grid")


if __name__ == "__main__":
    # Get the start time to see how long the program takes
    start_time = time.time()


    # Create the parser
    arg_parser = argparse.ArgumentParser(description='Execute a host scan on a network')

    # Add the arguments
    arg_parser.add_argument('Network',
                        metavar='network',
                        type=str,
                        help='the network to scan')

    # Execute the parse_args() method
    args = arg_parser.parse_args()

    devices = NetworkScanner.host_detetction(args.Network)
    print("Scan completed in {0} seconds\n".format(round(time.time() - start_time)))
    print("Results")
    print("-------")
    print(NetworkScanner.create_table(devices))