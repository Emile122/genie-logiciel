from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Auth

interface = "wlan0mon"  # Change this to your monitor mode interface
ap_mac = "f4:f2:6d:09:c0:f9"

def handle_auth(packet):
    # Check if it's an 802.11 packet and a Dot11Auth layer is present
    if packet.haslayer(Dot11) and packet.haslayer(Dot11Auth):
        # Check if the packet is an authentication request
        if packet[Dot11].addr1 == ap_mac and packet[Dot11Auth].seqnum == 1:
            print("Received an authentication request from:", packet[Dot11].addr2)
            # Record the time when the request is received
            request_time = datetime.now()

            # Construct the response packet
            radiotap = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna+RXFlags',
                                Rate=2,  # Data Rate: 1.0 Mb/s
                                ChannelFrequency=2457, ChannelFlags=0x00a0,  # Channel frequency and flags
                                dBm_AntSignal=-51, Antenna=1, RXFlags=0x0000)  # Antenna signal and other flags

            dot11 = Dot11(type=0, subtype=11, addr1=packet[Dot11].addr2, addr2=ap_mac, addr3=ap_mac)
            auth = Dot11Auth(algo=0, seqnum=2, status=0)  # Open System Authentication

            # Send the response packet
            response_packet = radiotap / dot11 / auth
            sendp(response_packet, iface=interface, verbose=False)
             # Record the time immediately after sending the response
            response_time = datetime.now()

            # Calculate the time taken for the response
            time_taken = response_time - request_time
            print(f"Time taken for response: {time_taken.total_seconds()} seconds")
            print("Sent authentication response to:", packet[Dot11].addr2)

# Start sniffing for Dot11 packets
sniff(iface=interface, prn=handle_auth)
