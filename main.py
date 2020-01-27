"""
Follow a TCP stream with pyshark.

"""
import pyshark
from scapy.all import wrpcap, rdpcap

# Change FILENAME to your pcap file's name.
from pyshark import FileCapture

FILENAME = "telnet-raw.pcap"
TARGET_FILENAME = "telnet-raw.pcap"

# Change STREAM_NUMBER to the stream number you want to follow.
PW_Detected = 0
linesWithPasswords = []
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
        # print data from the selected stream
        if PW_Detected == 1:
            print(p.number)
            linesWithPasswords.append(int(p.number) - 1)
        if p.telnet.data == "Password:":
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
