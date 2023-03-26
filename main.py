import pyshark
from colorama import Fore, Back, Style

# Load the capture file
capture = pyshark.FileCapture('test4.pcap')


print(Back.GREEN + 'Ethernet Header' + Style.RESET_ALL)
for packet in capture:

    # Extracting from the TCP layer
    tcp_layer = packet['TCP']

    # Extracting from the Ethernet Layer
    ethernet_layer = packet['ETH']
    Edest_addr = ethernet_layer.dst
    Esrc_addr = ethernet_layer.src
    Etype = ethernet_layer.type

    # Print the parsed Ethernet fields
    print(f'{Edest_addr}: Ethernet destination address is {Edest_addr}')
    print(f'{Esrc_addr}: Ethernet source address: {Esrc_addr}')
    print(f'{Etype}: The payload type is IP ({Etype})')
    print("-----------------------------------------------")

    # Extracting from the IP Layer
    ip_layer = packet['IP']
    Isrc_version = ip_layer.version
    Isrc_hdr_len = ip_layer.hdr_len
    print(Back.YELLOW + 'IP Header' + Style.RESET_ALL)
    print(tcp_layer)
    print(f'{Isrc_version}: This is an IP version {Isrc_version} datagram')
    print(f'{Isrc_hdr_len}: The Header length is 5*{Isrc_version} = {Isrc_hdr_len} bytes')
