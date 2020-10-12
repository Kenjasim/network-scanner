import ipaddress
"""
Define some common functions which can be 
used across the scanner
"""

def validip(ip_addr):
    """
    Return True if IP address is valid
    """
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except:
        return False

def parse_ip_input(u_input):
    """
    Check if the entered Input id either a valid ip address or network

    Keyword Arguments
        u_input - the user input to check
    """
    hosts = None
    if "/" in u_input:
        # Parse as IP network and return the hosts
        ipnetwork = ipaddress.ip_network(u_input)
        # Get a list of all hosts on the network
        hosts = list(ipnetwork.hosts())
    elif validip(u_input):
        #Check if they have passed a single ip to scan
        hosts = [u_input]
    else:
        print("Please enter a valid IP address or network")
    
    
    return hosts