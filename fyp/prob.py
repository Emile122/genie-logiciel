from scapy.all import *
from datetime import datetime  # Import datetime module

interface = "wlan0mon"
ap_mac = "f4:f2:6d:09:c0:f9"

def handle_probe_request(packet):
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet[Dot11Elt].info
        if ssid.decode() == 'Test Access Point':
            # Record the time when the request is received
            request_time = datetime.now()

            # Constructing the probe response frame
            pkt = RadioTap()/ \
                  Dot11(type=0, subtype=5, addr1=packet.addr2, addr2=ap_mac, addr3=ap_mac) / \
                  Dot11ProbeResp(cap='ESS')/ \
                  Dot11Elt(ID='SSID', info=ssid) / \
                  Dot11EltRates()

            # Send the probe response
            sendp(pkt, iface=interface)

            # Record the time immediately after sending the response
            response_time = datetime.now()

            # Calculate the time taken for the response
            time_taken = response_time - request_time

            # Print the time taken for the response
            print(f"Time taken for response: {time_taken.total_seconds()} seconds")

# Start sniffing for probe requests
sniff(iface=interface, prn=handle_probe_request)


