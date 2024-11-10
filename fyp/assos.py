from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11AssoResp, Dot11Elt

interface = "wlan0mon"  # Change this to your monitor mode interface
ap_mac = "f4:f2:6d:09:c0:f9"

def handle_assoc_req(packet):
    # Check if it's an 802.11 packet
    if packet.haslayer(Dot11):
        # Check if the packet is an association request
        if packet.type == 0 and packet.subtype == 0x00 and packet.addr1 == ap_mac:
            client_mac = packet.addr2
            print("Received an association request from:", client_mac)
            request_time = datetime.now()

            # Construct the response packet
            radiotap = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna+RXFlags',
                                Rate=2,  # Data Rate: 1.0 Mb/s
                                ChannelFrequency=2457, ChannelFlags=0x00a0,
                                dBm_AntSignal=-53, Antenna=1, RXFlags=0x0000)

            dot11 = Dot11(type=0, subtype=1, addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
            assoc_resp = Dot11AssoResp(cap=0x0401, status=0, AID=0x0001)
            supported_rates = Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18\x24')
            extended_supported_rates = Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')

            # Send the response packet
            response_packet = radiotap / dot11 / assoc_resp / supported_rates / extended_supported_rates
            sendp(response_packet, iface=interface, verbose=False)
            response_time = datetime.now()

            # Calculate the time taken for the response
            time_taken = response_time - request_time
            print(f"Time taken for response: {time_taken.total_seconds()} seconds")
            print("Sent association response to:", client_mac)

# Start sniffing for Dot11 packets
sniff(iface=interface, prn=handle_assoc_req)
