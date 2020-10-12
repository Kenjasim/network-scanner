import time, argparse, ipaddress, sys
from tabulate import tabulate

from scans import ARPScan, PingScan, PortScan

class Scans():

    @staticmethod
    def arp_scan(ip_net):
        """
        Run an ARP scan

        Keyword Arguments
            ip_net - the ip network to scan
        """
        #Check if running on linux, if not then error
        if sys.platform != "linux":
            print ("This script requires linux, please use ping scan instead")
            sys.exit(2)
        
        output = ARPScan().run(ip_net)
        if output:
            return output
        else:
            sys.exit(2)

    @staticmethod
    def ping_scan(ip_net):
        """
        Run a threaded ping scan

        Keyword Arguments
            ip_net - ip network to scan

        Returns
            dict of hosts mac addrs and hostnames
        """

        output = PingScan().run(ip_net)
        if output:
            return output
        else:
            sys.exit(2)
        

    @staticmethod
    def socket_scan(ip):
        """
        Run the scan of ports with threads

        Keyword Arguments
            ip - the ip to scan

        Returns
            Dict of open ports
        """
        # Get hosts
        if sys.platform == "linux":
            hosts = ARPScan().run(ip)
        else:
            hosts = PingScan().run(ip)

        # Run the port scanner
        output = PortScan().run(hosts, probe=False)

        return output
        

    @staticmethod
    def service_scan(ip):
        """
        Run the scan of ports and services with threads

        Keyword Arguments
            ip - the ip to scan

        Returns
            Dict of open ports
        """

        # Get hosts
        if sys.platform == "linux":
            hosts = ARPScan().run(ip)
        else:
            hosts = PingScan().run(ip)

        # Run the port scanner
        output = PortScan().run(hosts, probe=True)

        return output


def print_host(host):
    """
    Print host information
    """
    print("\nHost {0} is up".format(host["ip"]))
    print("Hostname: {0} MAC: {1}".format(host["hostname"],host["mac"]))

def print_ports(ports):
    """
    Print port information pertaining to a host
    """
    print ("Found {0} open ports ".format(len(ports)))
    print(create_table(ports))


def create_table(items):
    """
    Create and print a table to the console
    from a dict

    Keyword Arguments:
        items - a dict of items

    Returns
        nicely formatted table string
    """
    if len(items) == 0:
        return

    header = items[0].keys()
    rows =  [item.values() for item in items]
    return tabulate(rows, header,tablefmt="plain")


if __name__ == "__main__":
    # Get the start time to see how long the program takes
    start_time = time.time()

    # Create the parser
    arg_parser = argparse.ArgumentParser(description='Execute a host scan on a network')

    # Create the host scans group
    hostscans = arg_parser.add_argument_group('host scans')

    # Add the arguments
    hostscans.add_argument('-hA',metavar='<ip_network>', type=str, help='Initiate a host ARP scan (Linux only, must be sudo)')
    hostscans.add_argument('-hP',metavar='<ip_network>', type=str, help='Initiate a host ping scan')

    # Create the port scans group
    portscans = arg_parser.add_argument_group('port scans')

    # Add the arguments
    portscans.add_argument('-pC',metavar='<ip_address>', type=str, help='Try to connect to open ports on a host (sudo on linux)')
    # Create the service scans group
    servicescans = arg_parser.add_argument_group('service scans')

    # Add the arguments
    servicescans.add_argument('-sC',metavar='<ip_address>', type=str, help='Try to connect to open ports on a host and detect application (sudo on linux)')

    #Responses
    responses = []

    # Execute the parse_args() method
    args = arg_parser.parse_args()

    arguments = vars(args)

    port_info = False

    # Run the correct commands from the host detetction
    if arguments['hA']:
        hosts = Scans.arp_scan(arguments["hA"]) 
    elif arguments['hP']:
        hosts = Scans.ping_scan(arguments["hP"])
    elif arguments['pC']:
        responses = Scans.socket_scan(arguments["pC"])
        port_info = True
    elif arguments['sC']:
        responses = Scans.service_scan(arguments["sC"])
        port_info = True
    else:
        print("Error: Need to run the command with an option and argument, see the help bellow:")
        arg_parser.print_help()
        sys.exit(2)

    # Print the time and table of responses
    print("Scan completed in {0} seconds".format(round(time.time() - start_time)))

    if not port_info:
        #Print host information
        print("Found {0} up host(s)".format(len(hosts)))
        for host in hosts:
            print_host(host)
    else:
        # Print ampunt of found hosts
        print("Found {0} up host(s)".format(len(responses)))
        
        for response in responses:
            #Print the host information
            print_host(response[0])

            #Print the port info
            print_ports(response[1])
        
