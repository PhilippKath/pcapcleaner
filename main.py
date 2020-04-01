"""
Remove password from pcap file.

"""
import pyshark
from scapy.all import wrpcap, rdpcap
import re

FILENAME = "telnet-raw.pcap"
TARGET_FILENAME = "output.pcap"
pattern = {"Password", "password", "Enter PASSCODE:"}

PW_Detected = 0
linesWithPasswords = []
# open the pcap file, filtered for a single TCP stream
cap = pyshark.FileCapture(
    FILENAME,
    display_filter='telnet')


def find_pw(data, pattern):
    for p in pattern:
        if re.match(p, data, flags=0):
            return True
    return False


while True:
    try:
        p = cap.next()
    except StopIteration:  # Reached end of capture file.
        break
    try:
        # search for pw lines
        if PW_Detected == 1:
            print(p.number)
            linesWithPasswords.append(int(p.number) - 1)
        if find_pw(p.telnet.data, pattern):
            PW_Detected = 1
        if ord(p.telnet.data[0]) == 92:
            PW_Detected = 0
    except AttributeError:  # Skip the ACKs.Data: \r
        pass

print(linesWithPasswords)
## read and edit file
pkts = rdpcap(FILENAME)
print(pkts)
for i in linesWithPasswords:
    pkts[i]["Raw"].load = "x"

wrpcap("mod.pcap", pkts)
