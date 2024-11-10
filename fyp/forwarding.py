from scapy.all import *

# Replace this with the MAC address of the target access point
target_ap_mac = '60:E3:27:CD:BB:2E'

def forward_packet(packet):
    if packet.haslayer(Dot11):
        # Change the destination MAC address to the target AP's MAC address
        packet.addr1 = target_ap_mac

        # Forward the packet to wlan1
        sendp(packet, iface="wlan1")

# Start sniffing on wlan0mon
sniff(iface="wlan0mon", prn=forward_packet)
