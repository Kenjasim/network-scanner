# Host scannner

Simple network scanner to detect hosts, ports and services

## Instalation

Clone this repo and eithe with a virtual environment or without one install the requitements

```shell
pip install -r requirements.txt
```

## Usage

First you can run the command with the `-h` flag to get to the help screen

```shell
$ python scan.py -h

usage: scan.py [-h] [-hA <ip_network>] [-hP <ip_network>] [-pC <ip_address>] [-pS <ip_address>]
               [-sC <ip_address>]

Execute a host scan on a network

optional arguments:
  -h, --help        show this help message and exit

host scans:
  -hA <ip_network>  Initiate a host ARP scan
  -hP <ip_network>  Initiate a host ping scan

port scans:
  -pC <ip_address>  Try to connect to open ports on a host
  -pS <ip_address>  Run a SYN port scan on a host

service scans:
  -sC <ip_address>  Try to connect to open ports on a host and detect application

```

From this help message you can see that the scans are split depending on if they are a host, port or service scan. From here you can run any type of scan

## Example: Host Scan

```
python scan.py -hA 192.168.1.0/24
```

This will initatate an ARP scan of the network to detect hosts. The expected output is:

```

Found 10 up hosts on network <network>
Scan completed in 29 seconds

Results
-------
╒═══════════════╤═════════════════════╤═══════════════════╕
│ ip            │ hostname            │ mac               │
╞═══════════════╪═════════════════════╪═══════════════════╡
│ ipadrr        │ name                │ macaddr           │
╘═══════════════╧═════════════════════╧═══════════════════╛

```