from scapy.all import IP, TCP, srp
import socket
class PortScan():

    @staticmethod
    def syn_scan(ip):
    
        ports = list(range(10000))
        # Create SYN packets to see if ports are open
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
        
        # Send the packets
        ans, _ = srp(syn, timeout=2, retry=2)
        ports = []

        # Loop thourgh all the recieved packets
        for _, received in ans:
            if received[TCP].flags == "SA":
                ports.append(received[TCP].sport)

        result = [{"ip": ip, "ports": p} for p in ports]
        return result

    @staticmethod
    def port_connect(ip, port, output):
        """
        Tries to connect to a port to see if it is open
        """
        # Create a new socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        try:
            # Try to connect to the port
            s.connect((str(ip), port))
            output.append(port)
        except:
            pass
        finally:
            s.close()

    @staticmethod
    def service_detetction(ip,port, output):
        """
        Do a service port scan

        Keyword Arguments
            ip - ip address of host
            ports - the ports to connect to as a dict
            output - list to append to
        """

        # Create a new socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        # Try to connect to the port
        result = s.connect_ex((str(ip), port))
        s.close()

        # If there has been a successful connection
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Could not detect"

            output.append({"ip": ip, "port": port, "service": service})
            
        
