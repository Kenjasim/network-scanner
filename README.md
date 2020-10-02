# Host scannner

Simple host scanner which uses scapy to detect up hosts on a network

## Instalation

Clone this repo and eithe with a virtual environment or without one install the requitements

```shell
pip install -r requirements.txt
```

## Usage

To run a simple host scan run the command

```shell
python scan.py <ip-network>
```

The expected output is:

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