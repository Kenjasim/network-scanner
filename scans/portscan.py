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
