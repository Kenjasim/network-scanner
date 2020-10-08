import subprocess, socket
from concurrent.futures import ThreadPoolExecutor

from common import parse_ip_input

class PingScan():

    def run(self, ip_net):
        """
        Run a threaded ping scan on hosts

        Keyword Argume
        """
        # parse ip to return hosts
        hosts = parse_ip_input(ip_net)

        # If incorrect then return
        if hosts == None:
            return

        # Add a list of threads
        threads = []

        #Result
        result = []

        # Itterate over hosts and check which ones are up
        executor = ThreadPoolExecutor(max_workers=256)
        for ip in hosts:
            h1 = executor.submit(PingScan.ping_scan, ip, result)
            threads.append(h1)

        # Lock the main thread until they finish running
        for thread in threads:
            thread.result()

        # Return the list
        return result

    @staticmethod
    def ping_scan(ip, result):
        """
        Scan the ip address to see if it is up or not

        Keyword Arguments
            ip - The ip address to scan
            result - list to append to
        """

        # Timeout for the processes
        timeout = 0.5

        cmd = "timeout " + str(timeout) + "s ping -c 1 " + str(ip) + " 2>&1 >/dev/null"
        response = subprocess.call(cmd, shell=True)

        if response == 0:
            result.append({"ip": str(ip), "hostname": socket.gethostbyaddr(str(ip))[0], "mac": "Unknown"})

    
