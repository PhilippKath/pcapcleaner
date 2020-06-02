from scapy.all import wrpcap, rdpcap

FILENAME = "telnet-raw.pcap"

index_list = []
password = 'user'
k = 1 

## read and edit file
pkts = rdpcap(FILENAME)

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
                break
    except AttributeError:
        pass
    
# replace password per packet
for i in index_list:
    pkts[i].load = 'X'

wrpcap("mod.pcap", pkts)
