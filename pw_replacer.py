"""
This script looks for passwords from a list in a pcap file.
If found, the password is replaced with an X and written into a new pcap file.
"""

from scapy.all import wrpcap, rdpcap

FILENAME = "telnet-raw.pcap"
pw_list = ['test', 'user', '12345']

# read pcap file
pkts = rdpcap(FILENAME)

# loop over password list 
for password in pw_list:
    index_list = []
    k = 1
    # loop to find password indices
    for i in range(0, len(pkts)):
        try:
            if password[0] in str(pkts[i].load) and len(pkts[i].load) == 1:
                index_list.append(i)            
                for j in range(1, len(password)):
                    if password[j] in str(pkts[i+j+k].load) and len(pkts[i+j+k].load) == 1:
                        index_list.append(i+j+k)
                        k += 1
                    else:
                        index_list = []
                        k = 1
                if len(index_list) == len(password):
                    print("Password found:", password, "\nTelnet data replaced in packets:", end=' ')
                    for index in index_list:
                        print(index+1, end=' ')
                        pkts[index].load = 'X'
                    wrpcap('mod.pcap', pkts)    
                    print()
                    break
        except AttributeError:
            pass
