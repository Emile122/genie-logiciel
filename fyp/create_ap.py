from scapy.all import *
interface = "wlan0mon"  # Change this to your monitor mode interface
ap_mac = "f4:f2:6d:09:c0:f9"  # The MAC address for the AP

def create_ap(ssid, iface, mac):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap='ESS')
    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, iface=iface, loop=1)

    
if __name__ == "__main__":
    create_ap("Test Access Point", interface, ap_mac)
