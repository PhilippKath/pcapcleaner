"""
Follow a TCP stream with pyshark.

"""
import pyshark

# Change FILENAME to your pcap file's name.
FILENAME = "telnet-raw.pcap"
# Change STREAM_NUMBER to the stream number you want to follow.
STREAM_NUMBER = 0
PW_Detected = 0

# open the pcap file, filtered for a single TCP stream 
cap = pyshark.FileCapture(
    FILENAME,
    display_filter='tcp.stream eq %d and telnet' % STREAM_NUMBER)

while True:
    try:
        p = cap.next()
    except StopIteration:  # Reached end of capture file.
        break
    try:
        # print data from the selected stream
         if p.telnet.data == "Password:":
            PW_Detected = 1
         if ord(p.telnet.data[0]) == 92:
            PW_Detected = 0
         if PW_Detected == 1:
            print (p.telnet.data)


    except AttributeError:  # Skip the ACKs.Data: \r
        pass