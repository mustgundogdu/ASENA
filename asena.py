#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__="Mustafa GÜNDOĞDU"
print ('''\t\t\t
@b3kc4t
            AAA          SSSSSS    EEEEEEE    NNNN            NAA
           AA AA        SS         EE         NN  NN         NA AA
          AA   AA      SS          EE         NN   NN       NA   AA
         AAAAAAAAA      SSSSSSS    EEEEEEE    NN    NN     NAAAAAAAA
        AA       AA           SS   EE         NN     NN   NA       AA
       AA         AA           SS  EE         NN      NN NA         AA
      AA           AA   SSSSSSSS   EEEEEEE    NN       NNA           AA



''')

from scapy.all import *
import sys
import os
import socket
import argparse

desc = "Asena - Network Analyse Tool"
parser = argparse.ArgumentParser(description=desc)

o_option = parser.add_argument_group('Other option')
parser.add_argument("-i",help="IP address or IP subnet address", type=str,required=False)

parser.add_argument("-s","--scan" ,help="Network Active Machine fixed ,Usage -s/--scan IP_subnet_address",action="store_true")
parser.add_argument("-f","--firewall" ,help="Firewall Fixed on the Port ,Usage -f/--firewall IPv4_address",action="store_true")
parser.add_argument("--pscan",help="Port scaning On the Target Machine ,Usage --pscan IPv4_address ",action="store_true")
o_option.add_argument("-t","--trace",help="Usage -t/--trace ", action="store_true")
o_option.add_argument("-v","--version",help="Version",action="store_true")
o_option.add_argument("-a","--arpspoof",help="Arpspoof Attack ,Usage -a/--arpspof", action="store_true")


args = parser.parse_args()

def packet(sub):
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    c = os.popen("ip -4 route show default").read().split()
    s.connect((c[2],0))
    ipaddr = s.getsockname()[0].split('.')
    
    
    print ("Your Ip address :",ipaddr)
    print ("[+]Starting a arp request in the Network")
    
    try:
        s = raw_input('Do you want continue entered subnet address ?(Y/N)')
        if s == 'Y' or s == 'y':
            target_subnet = sub
            interface = raw_input('[I] Interface Enter :')
    #if subnet is not entered 
        elif s == 'N' or s == 'n':
            iplist = ipaddr[0]+'.'+ipaddr[1]+'.'+ipaddr[2]+'.0'+'/24'
            target_subnet = iplist
            interface = raw_input('Interface enter :')
            print(iplist)
        else:
            sys.exit()
    except KeyboardInterrupt:
        print("Asena is Shutdown...")
        sys.exit()
    frame = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=target_subnet)
    frames = srp(frame,iface = interface,timeout=2)
    print (frames[0].display())
    
    #print(frames[0].show())
def f_Scanner(Ip,port_list):
    dst_ip = Ip
    try:
        for port in range(1, 65535):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((dst_ip, port))
        
            if 0 == result:
                o_port = port
                port_list.append(o_port)
        
        
    except KeyboardInterrupt:
        print ("Asena Shutdowning...")
        sys.exit()

    for i in port_list:
        dst_port = i
        src_port = RandShort()
        a = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port))
        if (str(type(a))=="<type 'NoneType'>"):
            print ("[-]Port is Closed :",i)

        #If Port is Open
        if (a.getlayer(TCP).flags==0x12):
            ack_scan = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=10)
            if (str(type(ack_scan))=="<type 'NoneType'>"):
                print("[+]Firewall Status(Filtered[!]) :",i)
            elif(ack_scan.haslayer(TCP)):
                if (ack_scan.getlayer(TCP).flags==0x4):
                    print("[-]No Firewall :",i)
            elif (ack_scan.haslayer(ICMP)):
                if(int(ack_scan.getlayer(ICMP).type)==3 and int(ack_scan.getlayer(ICMP).code in[1,2,3,9,10,13])):
                    print ("[+]Firewall Status(Filtered[!]) :",i)


def N_Scanner(target_ip,port_list):
    try:
        for port in range(1, 65535):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
        
            if 0 == result:
                o_port = port
                port_list.append(o_port)
        
        for i in port_list:
            print ('[+] %d Numbered Port is Open \n'%i)
    except KeyboardInterrupt:
        print ("Asena Shutdowning...")
        sys.exit()


port_list = []

if args.scan:
    if args.i==None:
        sys.exit()
    else:
        sub = args.i
        packet(sub)
    
elif args.firewall:
    
    if args.i == None:
        sys.exit()
    else:
        Ip=args.i
    
    f_Scanner(Ip, port_list)
elif args.pscan:
    Ipv4 = args.i
    target_ip = Ipv4
    N_Scanner(target_ip,port_list)

elif args.trace:
    try:
        os.system("python3 trace.py")
    except KeyboardInterrupt:
        print("Asena Shutdowning...\n")
        sys.exit()
elif args.arpspoof:
    try:
        os.system("python arpspoof.py")
    except KeyboardInterrupt:
        print("Asena Shutdowning...\n")
        sys.exit()
elif args.version:
    print("Asena 1.1")
