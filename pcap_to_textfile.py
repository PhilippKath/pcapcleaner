"""
Remove password from pcap file.
"""
import pyshark
from scapy.all import wrpcap, rdpcap
import re

FILENAME = "telnet-raw.pcap"



pw_list = ['test', 'user', '12345']
pcap_as_string = ""

# open the pcap file, filtered for a single TCP stream
cap = pyshark.FileCapture(
    FILENAME,
    display_filter='telnet')


while True:
    try:
        p = cap.next()
    except StopIteration:  # Reached end of capture file.
        break
    try:
        # search for pw lines
        pcap_as_string += p.telnet.data
    except AttributeError:  # Skip the ACKs.Data: \r
        pass

output = open("pw_replace.txt", "w")

for i in pw_list:
    if i in pcap_as_string:
        output.write(re.sub(i, 'XXXX', pcap_as_string))
                


