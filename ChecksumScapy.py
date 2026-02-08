from scapy.all import *

packets = rdpcap("Checksum.pcapng")

for pkt in packets:
    if IP in pkt:
        original_checksum = pkt[IP].chksum
        
        del pkt[IP].chksum
        new_pkt = IP(bytes(pkt[IP]))
        calculated_checksum = new_pkt.chksum
        
        print("Original checksum:", original_checksum)
        print("Calculated checksum:", calculated_checksum)
        print("Match:", original_checksum == calculated_checksum)
        print("------")
