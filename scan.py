import time, argparse, ipaddress
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor

from scans import HostScan, PortScan

class Scans():

    @staticmethod
    def arp_scan(ip_net):
        """
        Run an ARP scan

        Keyword Arguments
            ip_net - the ip network to scan
        """
        
        #ARP Scannner
        devices = HostScan.host_detetction(ip_net)

        # Return the devices found
        return devices

    @staticmethod
    def ping_scan(ip_net):
        """
        Run a threaded ping scan

        Keyword Arguments
            ip_net - ip network to scan

        Returns
            dict of hosts mac addrs and hostnames
        """
        # Get the hosts as a list
        ipnetwork = ipaddress.ip_network(ip_net)

        # Get a list of all hosts on the network
        hosts = list(ipnetwork.hosts())

        # Add a list of threads
        threads = []

        #Result
        result = []

        # Itterate over hosts and check which ones are up
        executor = ThreadPoolExecutor(max_workers=256)
        for ip in hosts:
            h1 = executor.submit(HostScan.ping_scan, ip, result)
            threads.append(h1)

        # Lock the main thread until they finish running
        for thread in threads:
            thread.result()
        
        # Return the list
        print ("Found {0} up hosts on network {1}".format(len(result), ip_net))
        return result
    
    @staticmethod
    def socket_scan(ip):
        """
        Run the scan of ports with threads

        Keyword Arguments
            ip - the ip to scan

        Returns
            Dict of open ports
        """

        # Manage multiple threads
        threads = []

        # List to place the open ports
        output = []

        # Loop through each port and make a thread
        executor = ThreadPoolExecutor(max_workers=100)
        for i in range(10000):
            p1 = executor.submit(PortScan.port_connect, ip, i, output)
            threads.append(p1)

        # Lock the main thread until they finish running
        for thread in threads:
            thread.result()
        
        print ("Found {0} open ports on ip {1}".format(len(output), ip))
        # Return all the open ports
        ports = [{"ip": ip, "port": p} for p in output]
        return ports

    @staticmethod
    def syn_scan(ip):
        """
        Run a SYN port scan

        Keyword Arguments
            ip - the host to scan
        
        Returns
            dict of open ports
        """
        ports = PortScan.syn_scan(ip)
        return ports

    @staticmethod
    def service_scan(ip):
        """
        Run the scan of ports and services with threads

        Keyword Arguments
            ip - the ip to scan

        Returns
            Dict of open ports
        """

        # Manage multiple threads
        threads = []

        # List to place the open ports
        output = []

        # Loop through each port and make a thread
        executor = ThreadPoolExecutor(max_workers=100)
        for i in range(10000):
            p1 = executor.submit(PortScan.service_detetction, ip, i, output)
            threads.append(p1)

        # Lock the main thread until they finish running
        for thread in threads:
            thread.result()
        
        print ("Found {0} open ports on ip {1}".format(len(output), ip))
        # Return all the open ports
        return output
            

    


def create_table(items):
    """
    Create and print a table to the console
    from a dict

    Keyword Arguments:
        items - a dict of items

    Returns
        nicely formatted table string
    """
    print("Results")
    print("-------")
    if len(items) == 0:
        return
    header = items[0].keys()
    rows =  [item.values() for item in items]
    return tabulate(rows, header,tablefmt="fancy_grid")

if __name__ == "__main__":
    # Get the start time to see how long the program takes
    start_time = time.time()

    # Create the parser
    arg_parser = argparse.ArgumentParser(description='Execute a host scan on a network')

    # Create the host scans group
    hostscans = arg_parser.add_argument_group('host scans')

    # Add the arguments
    hostscans.add_argument('-hA',metavar='<ip_network>', type=str, help='Initiate a host ARP scan')
    hostscans.add_argument('-hP',metavar='<ip_network>', type=str, help='Initiate a host ping scan')

    # Create the port scans group
    portscans = arg_parser.add_argument_group('port scans')

    # Add the arguments
    portscans.add_argument('-pC',metavar='<ip_address>', type=str, help='Try to connect to open ports on a host')
    portscans.add_argument('-pS',metavar='<ip_address>', type=str, help='Run a SYN port scan on a host')

    # Create the port scans group
    servicescans = arg_parser.add_argument_group('service scans')

    # Add the arguments
    servicescans.add_argument('-sC',metavar='<ip_address>', type=str, help='Try to connect to open ports on a host and detect application')

    #Responses
    responses = []

    # Execute the parse_args() method
    args = arg_parser.parse_args()

    arguments = vars(args)

    # Run the correct commands from the host detetction
    if arguments['hA']:
        responses = Scans.arp_scan(arguments["hA"])
    elif arguments['hP']:
        responses = Scans.ping_scan(arguments["hP"])
    elif arguments['pC']:
        responses = Scans.socket_scan(arguments["pC"])
    elif arguments['pS']:
        responses = Scans.socket_scan(arguments["pS"])
    elif arguments['sC']:
        responses = Scans.service_scan(arguments["sC"])

    print("Scan completed in {0} seconds\n".format(round(time.time() - start_time)))
    print(create_table(responses))
