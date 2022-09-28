# -*- coding: utf-8 -*-

__author__ = "Mustafa GÜNDOĞDU"

from colorama import Fore, Back, Style, init

print(Fore.RED+'''
                            *
                           ***
                        __*****__'''+Fore.BLUE+'''
                          \[*]/ 
     ___ ___ ___ ___ ___   [+]  {3.0.0}
    | .'|_ -| ._|   | .'|  [-]
    |__,|___|__/|_|_|__,|  [?]
                       '''+Fore.YELLOW+'''__@b3kc4t__
                              
                                        
                      
                      ''') 

from scapy.all import *
import sys
import os
import socket
import argparse
import subprocess
import ipcalc



#ACTIVE MACHINE DETECT CLASS
class Active_Machine:

    #Arp packets create and check
    def arp_packet_create(self, sub, i_face):
        try:
            print(Fore.GREEN+" "*20+"[*]STARTING ARP REQUEST IN THE NETWORK[*]")

            #Assegment values from received
            target_subnet = sub
            interface = i_face

            #Create mac list
            mac_list = []
            #Create list for Found machine
            found_machine = []

            #MAC BROADCAST WITH FRAME
            frame = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=target_subnet)
            #Check srp function process
            try:
                #Broadcast result on layer 2
                res = srp(frame, iface = interface, timeout=2, verbose=0)[0]
            except:
                print(Fore.RED+"[-]WRONG PROBLEM ACTIVE MACHINE DETECT[-]")
                #success exit
                sys.exit(0)
            #if find result filter mac and ip
            for sent, received in res:
                #found_machine list append result value
                found_machine.append({'ip': received.psrc, 'mac': received.hwsrc})
                mac_list.append(received.hwsrc)

            #Create result list
            result = []
            #Create command_result_last list
            command_result_last = []
            #Create last_c
            last_c = []
            #Create command_result_list list
            command_result_list = []
            #Create newList
            newList = []

            #Check filter LINUX OS 
            try:

                for i in mac_list:

                    for j in range(1,4):
                        #Linux tool filter command
                        command = 'echo %s | cut -d ":" -f %s'%(i, j)
                        #Check shell process
                        try:
                            #Result command
                            result_command = subprocess.check_output(command, shell=True)
                        except:
                            print(Fore.Red+"[-]LINUX ECHO OR CUT TOOL ERROR[-]")
                            #success exit
                            sys.exit(0)
                        #Append value in command_result_list
                        command_result_list.append(result_command.split('\n')[0])
                    command_result_last.append(command_result_list[0]+command_result_list[1]+command_result_list[2])

                #LINUX GREP FILTER RESULT 
                for filter_grep in command_result_last:
                    filter_command = 'grep -i -A 4 %s oui.txt | cut -f 3'%filter_grep
                    #filter_command result
                    filter_result = subprocess.check_output(filter_command, shell=True)

                    #Check result
                    if filter_result == None:
                        result.append('UNKNOW')
                    else:
                        result.append(filter_result.split('\n'))

                print(Fore.BLUE+" "*20+"[+]ACTIVE MACHINE IN THE NETWORK[+]")
                print(Fore.GREEN+"IP" + " "*20 + Fore.GREEN+"MAC"+" "*25+Fore.GREEN+"VENDOR")

                #ADD VALUE DOWN TITLE
                for inf_found, info in zip(found_machine, result):
                    #VALUES
                    print(Fore.GREEN+"{:16}     {} ".format(inf_found['ip'], inf_found['mac'])+" "*10+info[:1][0])

            #FILTER LINUX OS EXCEPT
            except:

                #Asena SHUTDOWN
                print(Fore.RED+" "*20+"[!]THERE IS A PROBLEM ASENA IS SHUTDOWN[!]")
                #success exit
                sys.exit(0)
        
        #Process EXCEPT
        except:
            print(Fore.RED+"[-]ASENA IS SHUTDOWN[-]")
            #sucess exit
            sys.exit(0)


class Port_Scan_Classic:

    #ip subnet determine
    def set_ip_option(self, target_ip, port):
        #For keyboardinterrupt
        try:

            #presfix length control
            search_prefix = target_ip.find('/')
            if search_prefix != -1:
                
                #Create Scanned ip open result save list
                result_scanned_open = []
                #Create Scanned ip close result save list
                result_scanned_close = []
                #Create ip list for open port
                match_list = []
                
                #default ports reading for match
                port_read_file = open('default_port/default_ports.txt', 'r')
                port_read = port_read_file.read().split()
                port_read_file.close()

                #default ports banner reading for match
                banner_read_file = open('default_port/default_port_version.txt', 'r')
                banner_read = banner_read_file.read().split()
                banner_read_file.close()


                #Create socket for port scan on subnet
                sub_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                #port scan on destination subnet
                try:
                    for dst_ip in ipcalc.Network(target_ip):
                        
                        #scan result
                        result = sub_sock.connect_ex((str(dst_ip), port)) 
                        if 0 == result:
                            result_scanned_open.append(str(dst_ip))
                            match_list.append(str(port))
                    
                        elif 0 != result:
                            result_scanned_close.append(str(dst_ip))
                    
                    #Check destination ip list
                    if not result_scanned_open:
                        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                        print(Fore.RED+" "*10+"[-] NO FOUND {} NUMBERED PORT ON THIS SUBNET ==> {} [-]".format(port, target_ip))
                        


                    else:
                        #open port on destination ip filter
                        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                        for seq_match in range(0, len(match_list)):
                            if str(port) in port_read:
                                for match_port, match_banner in zip(port_read, banner_read):
                                    if str(port) in match_port:
                                        print(Fore.BLUE+" "*18+str(result_scanned_open[seq_match])+"==>"+"[+] {} {} => PORT IS OPEN[+]".format(match_list[seq_match], match_banner))
                            else:
                                for no_banner_ip in result_scanned_open:
                                    print(Fore.BLUE+" "*18+str(no_banner_ip)+"==>"+"[+] {} UNKNOW PORT IS OPEN [+]".format(port))

                    
                        #Choose user show 
                        print(Fore.GREEN+"[?] Do you want me to show you the found closed ports on target subnet ip [?]")
                        res_ask = raw_input(Fore.GREEN+"(Y/N)>>")
                    
                        if res_ask == 'Y' or res_ask == 'y':

                            if result_scanned_close == None:
                                print(Fore.BLUE+"[*] NO ONE LOOKS CLOSED [*]")
                            else:
                                #show close ports
                                for closed in result_scanned_close:
                                    #print scanned close port
                                    print(Fore.BLUE+" "*18+str(closed)+" ==>"+ "[-] %d NUMBERED PORT IS CLOSE [-]"%port)

                        else:
                            #succeess exit
                            sys.exit(0)
                    
                    #if scanned list is none
                    

                except KeyboardInterrupt:
                    quit()
            #IF NOT PREFIX IN TARGET IP
            elif search_prefix == -1:
                #target ip variable name change for other function process
                sock_target_ip = target_ip
                #call required function
                self.special_port_scan(sock_target_ip, port)
        
        #For user entry interrupt signal
        except KeyboardInterrupt:
            #success exit
            sys.exit(0)


    #for full port scan and required single target ip
    def Port_scan_tcp(self, target_ip):
        
        #Create port list for results
        port_list = []
        #Create match list for open ports
        match_list = []
        #match not list
        not_match_list = []
        #Create default ports list
        default_port_list = []

        #Default ports file reading
        port_read_file = open('default_port/default_ports.txt', 'r')
        port_read_result = port_read_file.read().split()
        port_read_file.close()

        #Default ports banner reading
        banner_read_file = open('default_port/default_port_version.txt', 'r')
        banner_read_result = banner_read_file.read().split()
        banner_read_file.close()

        #subnet filter check
        search_prefix = target_ip.find('/')
        
        if search_prefix == -1:

            #Interrupt signal check
            
            #Create open port list
            result_open_port = []
            #Create int port list
            int_ports = []
                
                
             #create all_ result
            result_ip_port = []

            #Convert int value from string value       
            int_ports = list(map(int, port_read_result))
                
            #Create match list
            match_list = []
            #Create not match list
            not_match_list = []

            #port scan on target subnet
                
            try:
                #default ports
                for port in int_ports:
                    sub_all_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sub_all_sock.connect_ex((str(target_ip), int(port)))
                    if 0 == result:
                        result_ip_port.append(str(port))
                        match_list.append(str(port))
                
                if not result_ip_port:
                
                    print(Fore.GREEN+" "*20+"**************** RESULT ***************")
                    print(Fore.RED+" "*16+"[-] NO OPEN PORT FOUND IN THE SCAN RESULT [-]")
                    

                else:
                    #open port on destination ip filter
                    print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                    
                    for seq_match in range(0, len(match_list)):
                        if str(result_ip_port[seq_match]) in port_read_result:
                            for match_port, match_ban in zip(port_read_result, banner_read_result):
                                if result_ip_port[seq_match] in match_port:
                                    print(Fore.BLUE+" "*23+"[+] {} {} => PORT IS OPEN[+]".format(result_ip_port[seq_match], match_ban))

                    
                        else:
                            #print no banner ports
                            print(Fore.BLUE+" "*23+"[+] {} UNKNOW => PORT IS OPEN [+]".format(result_ip_port[seq_match]))

            

            except KeyboardInterrupt:
                #success exit
                sys.exit(0)

            
        else:
            print(Fore.RED+" "*20+"[-] NO SUBNET ENTRY [-]")
            sys.exit(0)
    

    #ip all port scan
    def all_tcp_scan(self, target_ip):

        #Default ports file reading
        port_read_file = open('default_port/default_ports.txt', 'r')
        port_read_result = port_read_file.read().split()
        port_read_file.close()

        #Default ports banner reading
        banner_read_file = open('default_port/default_port_version.txt', 'r')
        banner_read_result = banner_read_file.read().split()
        banner_read_file.close()

        #Create port list
        port_list = []
        #Create match list for open ports
        match_list = []
        #match not list
        not_match_list = []
        #Create default ports list
        default_port_list = []

        #Check process
        try:
            #Check Process
            try:
                #TCP ALL PORT SCAN(DEFAULT)
                for p in range(1, 65353):
                    #create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    #socket timeout detect
                    sock.settimeout(1)
                    #result socket tcp scan
                    result_scan = sock.connect_ex((target_ip, int(p)))

                    #result control
                    if 0 == result_scan:
                        o_port = p
                        port_list.append(o_port)
            
                if port_list == None:
                    print(Fore.GREEN+" "*20+"************** RESULT ***************")
                    print(Fore.RED+" "*15+"[-] NO OPEN PORT FOUND IN THE SCAN RESULT [-]")
                elif port_list != None:
                    #create match length
                    match_length = len(port_list)
                    print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                #Read ports file append default_port list
                    for read_port in port_read_result:
                        default_port_list.append(read_port)

                #Match default port with open port number
                    #for seq_port_list in range(0, len(port_list)):
                    for o_port in port_list:
                        if str(o_port) in default_port_list:
                            match_list.append(o_port)
                        else:
                            not_match_list.append(o_port)
                
                    ###
                    for seq_match in range(0, len(match_list)):
                    #Combine default port and banner
                        
                        for res_port, res_banner in zip(port_read_result, banner_read_result):
                            if str(match_list[seq_match]) == str(res_port):
                                print(Fore.BLUE+" "*23+"[+]{} {} => PORT IS OPEN [+]".format(match_list[seq_match], res_banner))
                
                    #NO BANNER PORTS PRINT
                    if not_match_list != None:

                        #print no banner ports
                        for no_banner_port in not_match_list:
                            print(Fore.BLUE+" "*23+"[+] {} => PORT IS OPEN [+]".format(no_banner_port))


            

            #Process Except
            except:
                print(Fore.RED+" "*20+"[-]TCP PORT SCAN WRONG PROBLEM[-]")
                sys.exit(0)
        #Keyboard Interrupt
        except KeyboardInterrupt:
            #success exit
            sys.exit(0)

    def special_port_scan(self, sock_target_ip, port):

        #check Interrupt
        try:
            #check Process
            try:

                #Again default ports file reading
                port_read_file = open('default_port/default_ports.txt', 'r')
                port_read = port_read_file.read().split('\n')
                port_read_file.close()

                #Again Default ports banner reading
                banner_read_file = open('default_port/default_port_version.txt','r')
                banner_read = banner_read_file.read().split('\n')
                banner_read_file.close()


                #Create tcp socket
                spec_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                spec_sock.settimeout(1)
                #Result port scan on target ip
                result_spec_sock = spec_sock.connect_ex((sock_target_ip, port))

                #if result success
                if 0 == result_spec_sock:
                    print(Fore.GREEN+" "*20+"*************** RESULT **************")

                    #Banner search
                    if str(port) in port_read:
                        for p, banner in zip(port_read, banner_read):
                            
                            if str(port) in str(p):
                                print(Fore.BLUE+" "*23+"[+] {} {} => PORT IS OPEN [+]".format(port, banner))
                    
                    else:
                        print(Fore.BLUE+" "*23+"[+] {} => PORT IS OPEN [+]".format(port))

                else:
                    print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                    print(Fore.BLUE+" "*23+"[-] %d NUMBERED PORT IS CLOSE [-]"%port)
                    
            #Except Process
            except:
                print(Fore.RED+"[-] SOMETHING WENT WRONG [-] \n")
                #success exit
                sys.exit(0)

        #Except Interrupt
        except KeyboardInterrupt:
            print(Fore.GREEN+"[!]ASENA IS SHUTDOWNING[!] \n")

            #success exit
            sys.exit(0)
    
    
    def option_beetween_port_scan(self, target_ip, starting_port, ending_port):
        
        #Default ports file reading
        port_read_file = open('default_port/default_ports.txt', 'r')
        some_read_port = port_read_file.read().split()
        port_read_file.close()

        #Default ports banner reading
        banner_read_file = open('default_port/default_port_version.txt','r')
        some_read_banner = banner_read_file.read().split()
        banner_read_file.close()


        search_prefix = target_ip.find('/')

        if search_prefix != -1:
            
            #interrupt signal check
            try:

                try:
                    #Create open port list
                    result_open_port = []
                    #create open port on ip list
                    result_open_ip = []
                

                    #port scan choose
                    for b_port in range(starting_port, ending_port):
                        #ports scan on target subnet
                        
                        for dst_ip in ipcalc.Network(target_ip):
                            sock_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            result_b = sock_b.connect_ex((str(dst_ip), b_port))
                            if 0 == result_b:
                                result_open_port.append(str(b_port))
                                result_open_ip.append(str(dst_ip))

                    if not result_open_port:
                        print(Fore.GREEN+" "*20+"************** RESULT **************")
                        print(Fore.RED+" "*14+"[-] NO FOUND OPEN PORT ON " +str(target_ip)+ " TARGET SUBNET [-]")

                    else:
                        #create match list
                        match_list_b = []
                        print(Fore.GREEN+" "*20+"*************** RESULT ***************")

                        #open port banner match
                        for open_port in result_open_port:
                            #check list
                            if str(open_port) in some_read_port:
                                match_list_b.append(open_port)

                        for s_match in range(0, len(match_list_b)):
                            if str(match_list_b[s_match]) in some_read_port:

                                for r_p, r_b in zip(some_read_port, some_read_banner):
                                    if str(match_list_b[s_match]) in str(r_p):
                                        print(Fore.BLUE+" "*19+str(result_open_ip[s_match])+"==>"+" [+] {} {} PORT IS OPEN [+]".format(match_list_b[s_match], r_b))
                                
                            else:
                                print(Fore.BLUE+" "*19+str(result_open_ip[s_match])+"==>"+" {} UNKNOW PORT IS OPEN [+]".format(match_list_b[s_match]))


                except:
                    print(Fore.RED+" "*20+"[-]THERE IS A PROBLEM ON SCAN [-]")
                    sys.exit(0)
            
            
            except KeyboardInterrupt:
                #success exit
                sys.exit(0)

        

        else:    
            #Create open port list
            sing_open_port = []
            
            #interrupt signal
            try:
                #check process
            
                #try:
                #start and end port beetween scan loop
                

                for sing_port in range(starting_port, ending_port):
                    sing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    #scan on target ip
                    result_sing = sing_sock.connect_ex((target_ip, sing_port)) 
                    
                    if 0 == result_sing:
                        sing_open_port.append(sing_port)


                
                if not sing_open_port:
                        
                    print(Fore.RED+" "*15+"[-] NO OPEN PORT FOUND IN THE SCAN RESULT [-]")
                else:
                       
                    #create single match list
                    sing_match_list = []
                    print(Fore.GREEN+" "*20+"*************** RESULT ***************")
                        
                    for s_open in sing_open_port:
                        if str(s_open) in some_read_port:
                            sing_match_list.append(s_open)

                    for sing_match in range(0, len(sing_match_list)):

                        if str(sing_match_list[sing_match]) in some_read_port:

                            for s_p, s_b in zip(some_read_port, some_read_banner):
                                if str(sing_match_list[sing_match]) in str(s_p):
                                    print(Fore.BLUE+" "*19+str(target_ip)+"==>"+"[+] {} {} PORT IS OPEN [+]".format(sing_match_list[sing_match], s_b))
                        else:
                            print(Fore.BLUE+" "*19+str(target_ip)+"==>"+"[+] {} UNKNOW PORT IS OPEN [+]".format(sing_match_list[sing_match]))
                    
                    
                    
                #except:
                #    print(Fore.RED+" "*20+"[-]THERE IS A PROBLEM ON SCAN [-]")
                #    sys.exit(0)


            except KeyboardInterrupt:
                sys.exit(0)

                



#Ack scan on firewall
class FIREWALL_SCAN_OPTIONS:
    

    
    #Default ports reading
    port_file = open('default_port/default_tcp_ports.txt', 'r')
    read_ports = port_file.read().split()
    port_file.close()
    
    #Default banners reading
    banner_file = open('default_port/default_port_version.txt', 'r')
    read_banner = banner_file.read().split()
    banner_file.close()


    #ack scan function
    def ack_scan_option(self, target_ip, port):
        
        #Create random source port for tcp packet
        src_port = RandShort()

        #control process
        try:
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            #create ack packet
            ack_packet = sr1(IP(dst=target_ip)/TCP(dport=port, flags="A"),verbose=0, timeout=10)
            if (str(type(ack_packet)) == "<type 'NoneType'>"):
                print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+" [*] FILTERED FROM FIREWALL [*]")
                
            elif (ack_packet.haslayer(TCP)):
                
                if (ack_packet.getlayer(TCP).flags == 0x4):
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+" [*] UNFILTERED OR NO FIREWALL [*]")
            
            elif (ack_packet.haslayer(ICMP)):
                if(int(ack_packet.getlayer(ICMP).type) == 3 and int(ack_packet.getlayer(ICMP).code in[1,2,3,9,10,13])):
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+" [*] FILTERED FROM FIREWALL [*]")
            
        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)

    def ack_scan_option_default(self, target_ip):
        
        #Create source port
        src_port = RandShort()
        #Create int value ports list
        int_ports = []
        #Create filtered port list
        filtered_port = []
        #Create unfiltered port list
        unfiltered_port = []
        #Create could be filtered list
        c_filtered_port = []

        int_ports = list(map(int, self.read_ports))
        
        
        try:
            ##
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            for dst_port in int_ports:
                
                try:
                    
                    ack_packet = sr1(IP(dst=target_ip)/TCP(dport=dst_port, flags="A"), verbose=0, timeout=10)
                    if (str(type(ack_packet)) == "<type 'NoneType'>"):
                        filtered_port.append(str(dst_port))
                    elif (ack_packet.haslayer(TCP)):

                        if(ack_packet.getlayer(TCP).flags == 0x4):
                                unfiltered_port.append(str(dst_port))

                    elif(ack_packet.haslayer(ICMP)):
                        if(int(ack_packet.getlayer(ICMP).type) == 3 and int(ack_packet.getlayer(ICMP).code in[1,2,3,9,10,13])):
                            c_filtered_port.append(str(dst_port))
                    
                except:
                    pass 
        
            if filtered_port != None:
                for filter_port in filtered_port:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_port)+" ==>"+" [*]FILTERED FROM FIREWALL [*]")
                print('')
        
            if unfiltered_port != None:
                for unfilter_port in unfiltered_port:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(unfilter_port)+" ==>"+" [*]UNFILTERED OR NO FIREWALL[*]")

            if c_filtered_port != None:
                for c_filtered in c_filtered_port:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(c_filtered)+" ==>"+" [*] FILTERED FROM FIREWALL [*]")

        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)
        

        

    def null_scan_option(self, target_ip, port):
        
        #Create source port
        src_port = RandShort()

        #check process
        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
        try:
            Tcp_null_packet = sr1(IP(dst=target_ip)/TCP(dport=port,flags=""), verbose=0, timeout=10)
            
            if (str(type(Tcp_null_packet)) == "<type 'NoneType'>"):
                print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*] PORT IS OPEN|FILTERED [*]")
            elif(Tcp_null_packet.haslayer(TCP)):
                if(Tcp_null_packet.getlayer(TCP).flags == 0x4):
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*] PORT IS CLOSED [*]")
                elif(Tcp_null_packet.haslayer(ICMP)):
                    if(int(Tcp_null_packet.getlayer(ICMP).type)==3 and int(Tcp_null_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*] PORT IS FILTERED [*]")

        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)

    def null_scan_option_default(self, target_ip):
        
        #Create source port
        src_port = RandShort()
        #Create int value port list
        int_ports_default = []
        #Create filtered port list
        open_or_filtered = []
        #Create close port list
        close_ports = []
        #Create filtered ports
        filtered_ports = []

        int_ports_default = list(map(int, self.read_ports))

        try:
            ##
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            for dst_port in int_ports_default:
                #check process
                
                Tcp_null_packet = sr1(IP(dst=target_ip)/TCP(dport=dst_port, flags=""), verbose=0, timeout=10)
                try:
                    
                    if (str(type(Tcp_null_packet)) == "<type 'NoneType'>"):
                        open_or_filtered.append(str(dst_port))
                    elif(Tcp_null_packet.haslayer(TCP)):
                        if(Tcp_null_packet.getlayer(TCP).flags == 0x4):
                            close_ports.append(str(dst_port))
                        elif(Tcp_null_packet.haslayer(ICMP)):
                            if(int(Tcp_null_packet.getlayer(ICMP).type)==3 and int(Tcp_null_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                filtered_ports.append(str(dst_port))
                except:
                    pass
                
        
            if open_or_filtered != None:
                for filter_op in open_or_filtered:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_op)+" ==>"+"[*]PORT IS OPEN|FILTERED [*]")
        
            if close_ports != None:
                for close_port in close_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_op)+" ==>"+"[*]PORT IS CLOSED [*]")

            if filtered_ports != None:
                for filter_port in filtered_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_port)+" ==>"+"[*]PORT IS FILTERED [*]")
        
        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)
        

    def xmas_scan_option(self, target_ip, port):

        #Create source port
        src_port = RandShort()
        
        print(Fore.GREEN+" "*20+"*************** RESULT ***************")

        try:
            #create tcp packet(send and receive)
            Tcp_xmas_packet = sr1(IP(dst=target_ip)/TCP(dport=port, flags="FPU"),verbose=0, timeout=10)
            
            if (str(type(Tcp_xmas_packet)) == "<type 'NoneType'>"):
                print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS OPEN|FILTERED [*]")
            
                
            elif(Tcp_xmas_packet.getlayer(TCP).flags == 0x14):
                print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS CLOSED [*]")
                
            elif(Tcp_xmas_packet.haslayer(ICMP)):
                if(int(Tcp_xmas_packet.getlayer(ICMP).type) == 3 and int(Tcp_xmas_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS FILTERED [*]")

        
        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)

    def xmas_scan_option_default(self, target_ip):
        
        #Create source port
        src_port = RandShort()
        #Create open or filtered list
        open_or_filtered = []
        #Create close port
        close_ports = []
        #Create filtered_ports
        filtered_ports = []

        int_ports_default = list(map(int, self.read_ports))

        try:
            ##
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            try:
                for dst_port in int_ports_default:
                    Tcp_xmas_packet = sr1(IP(dst=target_ip)/TCP(dport=dst_port, flags="FPU"), verbose=0, timeout=10) 
                    if (str(type(Tcp_xmas_packet)) == "<type 'NoneType'>"):
                        open_or_filtered.append(str(dst_port))
                    
                    elif(Tcp_xmas_packet.getlayer(TCP).flags == 0x14):
                        close_ports.append(str(dst_port))

                    elif(Tcp_xmas_packet.haslayer(ICMP)):
                        if(int(Tcp_xmas_packet.getlayer(ICMP).type) == 3 and int(Tcp_xmas_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                            filtered_ports.append(str(dst_port))
            except:
                pass
                    

            if open_or_filtered != None:
                for filter_op in open_or_filtered:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_op)+" ==>"+"[*] PORT IS OPEN|FILTERED [*]")
                print('')
            else:
                if close_ports != None:
                    for close_port in close_ports:
                        print(Fore.BLUE+" "*18+str(target_ip)+" "+str(close_port)+" ==>"+"[*] PORT IS CLOSED [*]")
                    print('')
            
            if filtered_ports != None:
                for filter_port in filtered_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_port)+" ==>"+"[*] PORT IS FILTERED [*]")


        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)



    def fin_scan_option(self, target_ip, port):

        #Create source port
        src_port = RandShort()
        
        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
        
        try:
            Tcp_fin_packet = sr1(IP(dst=target_ip)/TCP(dport=port,flags="F"),verbose=0, timeout=10)
            if(str(type(Tcp_fin_packet)) == "<type 'NoneType'>"):
                print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS OPEN|FILTERED [*]")
            elif(Tcp_fin_packet.haslayer(TCP)):
                if(Tcp_fin_packet.getlayer(TCP).flags == 0x4):
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS CLOSED [*]")
                elif(Tcp_fin_packet.haslayer(ICMP)):
                    if(int(Tcp_fin_packet.getlayer(ICMP).type) == 3 and int(Tcp_fin_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+"[*]PORT IS FILTERED [*]")
                else:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(port)+" ==>"+" [*] PORT IS CLOSED OR NOT RESPONSE [*]")
        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)
    
    def fin_scan_option_default(self, target_ip):
       
        #Create source port
        src_port = RandShort()
        #Create open or filtered list
        open_or_filtered = []
        #Create close port list
        close_ports = []
        #Create filtered port list
        filtered_ports = []
        #Create int ports list
        int_ports_default = []

        int_ports_default = list(map(int, self.read_ports))

        try:
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            
            for dst_port in int_ports_default:
                try:
                    Tcp_fin_packet = sr1(IP(dst=target_ip)/TCP(dport=dst_port,flags="F"),verbose=0, timeout=10)
                    if(str(type(Tcp_fin_packet)) == "<type 'NoneType'>"):
                        open_or_filtered.append(str(dst_port))
                    elif(Tcp_fin_packet.haslayer(TCP)):
                        if(Tcp_fin_packet.getlayer(TCP).flags == 0x4):
                            close_ports.append(str(dst_port))
                        elif(Tcp_fin_packet.haslayer(ICMP)):
                            if(int(Tcp_fin_packet.getlayer(ICMP).type) == 3 and int(Tcp_fin_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                filtered_ports.append(str(dst_port))
                except:
                    pass

            if open_or_filtered != None:
                for filter_op in open_or_filtered:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_op)+" ==>"+"[*] PORT IS OPEN|FILTERED [*]")

            if close_ports != None:
                for close_port in close_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(close_port)+" ==>"+"[*] PORT IS CLOSED [*]")
            if filtered_ports != None:
                for filter_port in filtered_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_port)+" ==>"+"[*] PORT IS FILTERED [*]")
        
        except:
            print(Fore.RED+" "*20+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)


    def connect_scan_option(self, target_ip, port):
        
        #Create source port
        src_port = RandShort()

        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
        try:
            Tcp_packet = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=port), verbose=0, timeout=10)
            if(Tcp_packet.getlayer(TCP).flags == 0x12):
                #create ack_packet
                ack_packet = sr1(IP(dst=target_ip)/TCP(dport=port, flags="A"), verbose=0, timeout=10)
                if(str(type(ack_packet)) == "<type 'NoneType'>"):
                    print(Fore.BLUE+" "*23+str(port)+" ==>"+"[*] PORT IS FILTERED [*]")
                elif(ack_packet.haslayer(TCP)):
                    if(ack_packet.getlayer(TCP).flags == 0x4):
                        print(Fore.BLUE+" "*23+str(port)+" ==>"+"[*] PORT IS OPEN [*]")
                elif(ack_packet.haslayer(ICMP)):
                    if(int(ack_packet.getlayer(ICMP).type) == 3 and int(ack_packet.getlayer(ICMP).code in[1,2,3,9,10,13])):
                        print(Fore.BLUE+" "*23+str(port)+" ==>"+"[*] PORT IS FILTERED [*]")
            elif(Tcp_packet.getlayer(TCP).flags == 0x14):
                print(Fore.BLUE+" "*23+str(port)+" ==>"+"[*] PORT IS CLOSE [*]")
        except:
            print(Fore.BLUE+" "*18+str(port)+" ==>"+"[*] PORT IS FILTERED OR NOT RESPONSE [*]")


    def connect_scan_default(self, target_ip):
       #Create source port
        src_port = RandShort()
        #Create int value ports list
        int_ports = []
        #Create filtered port list
        filtered_port = []
        #Create open port list
        open_ports = []
        #Create could be filtered list
        c_filtered_port = []
        #close ports
        close_ports = []

        int_ports = list(map(int, self.read_ports))
        
        
        try:
            ##
            print(Fore.GREEN+" "*20+"*************** RESULT ***************")
            for dst_port in int_ports:
                Tcp_packet = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=dst_port), verbose=0, timeout=10)
            
                try:
                    if(Tcp_packet.getlayer(TCP).flags == 0x12):
                        #create ack packet
                        ack_packet = sr1(IP(dst=target_ip)/TCP(dport=dst_port, flags="A"), verbose=0, timeout=10)
                        if (str(type(ack_packet)) == "<type 'NoneType'>"):
                            filtered_port.append(str(dst_port))
                        elif (ack_packet.haslayer(TCP)):
                            if(ack_packet.getlayer(TCP).flags == 0x4):
                                open_ports.append(str(dst_port))

                        elif(ack_packet.haslayer(ICMP)):
                            if(int(ack_packet.getlayer(ICMP).type) == 3 and int(ack_packet.getlayer(ICMP).code in[1,2,3,9,10,13])):
                                c_filtered_port.append(str(dst_port))

                    elif(Tcp_packet.getlayer(TCP).flags == 0x14):
                        close_ports.append(str(dst_port))
                except:
                    pass 
        

            if open_ports != None:
                for open_port in open_ports:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(open_port)+" ==>"+" [*] PORT IS OPEN [*]")
                print('')

            if filtered_port != None:
                for filter_port in filtered_port:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(filter_port)+" ==>"+" [*] FILTERED FROM FIREWALL [*]")
                print('')    
            
            if close_ports != None:
                res = raw_input(Fore.GREEN+" "*23+"[?]SHOW CLOSED PORTS(Y/N)[?]")
                if res == 'Y' or res == 'y':
                    for close_port in close_ports:
                        print(Fore.BLUE+" "*18+str(target_ip)+" "+str(close_port)+" ==>"+" [*] PORT IS CLOSE [*]")
                    print('')
                
            if c_filtered_port != None:
                for c_filtered in c_filtered_port:
                    print(Fore.BLUE+" "*18+str(target_ip)+" "+str(c_filtered)+" ==>"+" [*] FILTERED FROM FIREWALL [*]")
                print('')
        except:
            print(Fore.RED+" "*23+"[!] A TCP PROBLEM OCCURED [!]")
            sys.exit(0)
        



class Main(Active_Machine, Port_Scan_Classic, FIREWALL_SCAN_OPTIONS):

        def parameter_control(self):

            #description for asena
            desc = "Asena - Network Analyse Tool"

            #defination parser value
            parser = argparse.ArgumentParser(description=desc)
            #Defination options
            option = parser.add_argument_group('[*]OPTIONS[*]')
            parser.add_argument("-i",help=Fore.GREEN+"[*]ACCORDING [*]",type=str,required=False)
            parser.add_argument("--interface",help=Fore.GREEN+"[*]DESIRED INTERFACE INPUT [*]",required=False)
            parser.add_argument("-d","--discover",help=Fore.GREEN+"[*]NETWORK ACTIVE MACHINE DETECTION [*]",action='store_true')
            parser.add_argument("-s","--scan",help=Fore.GREEN+"[*]PORT SCANNER ON TARGET SYSTEM [*]",action='store_true')
            parser.add_argument("-p","--port",help=Fore.GREEN+"[*]SPECIFYING A DESTINATION PORT [*]",type=int, required=False)
            parser.add_argument("-a","--all",help=Fore.GREEN+"[*]THIS OPTION IS SCAN ALL TCP PORTS [*]",action='store_true')
            parser.add_argument("-A","--ack", help=Fore.GREEN+"[*]THIS OPTION USAGE FOR IF HAVE FIREWALL ON TARGET SYSTEM, DISPLAY PORT STATUS [*]", action='store_true')
            parser.add_argument("-n","--null",help=Fore.GREEN+"[*]THIS OPTION USAGE FOR IF HAVE FIREWALL OR NOT RESPONSE FROM TARGET SYSTEM DISPLAY PORT STATUS [*]",action='store_true')
            parser.add_argument("-x","--xmas",help=Fore.GREEN+"[*]THIS OPTION USAGE FOR IF HAVE FIREWALL FROM TARGET SYSTEM DISPLAY PORT STATUS WITH PSH,FIN AND URG FLAGS [*]",action='store_true')
            parser.add_argument("-f","--fin",help=Fore.GREEN+"[*]THIS OPTION DISPLAY PORT STATUS WITH SEND FIN FLAG TO TARGET SYSTEM [*]",action='store_true')
            parser.add_argument("-c","--connect",help=Fore.GREEN+"[*]THIS OPTION DISPLAY PORT STATUS WITH TCP CONNECT SCAN [*]",action='store_true')



            parser.add_argument("--default", help=Fore.GREEN+"[*]THIS OPTION SCANS ON DEFAULT PORTS [*]",action='store_true')
            
            parser.add_argument("-b","--between", help=Fore.GREEN+"[*]PROVIDES PORT SCANNING BETWEEN SPECIFIED START AND END PORTS [*]",action='store_true')

            parser.add_argument("--start", help=Fore.GREEN+"[*]SPECIFYING THE STARTING PORT [*]",type=int, required=False)
            parser.add_argument("--end",help=Fore.GREEN+"[*]SPECIFYING THE ENDING PORT [*]",type=int, required=False)
            

            #Parser Option is Finished and create args value
            args = parser.parse_args()

    
            if args.discover:
                if args.i == None:
                    sys.exit(0)
                else:
                    sub = args.i
                    i_face = args.interface
                
                self.arp_packet_create(sub, i_face)

            elif args.scan:
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION IP ENTER[*]\n")
                    #success exit
                    sys.exit(0)
                else:
                    target_ip = args.i

                    if args.port:
                        port = args.port
                        self.set_ip_option(target_ip, port)
                    else:
                        print(Fore.RED+" "*20+"[*]PLEASE ADD PORT OR CHOOSE DEFAULT TCP PORT SCAN[*]\n")
                        sys.exit(0)

            elif args.between:
                        
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION SUBNET IP ENTER[*]\n")
                    sys.exit(0)

                else:
                    target_ip = args.i

                    if args.start and args.end:
                        
                        starting_port = args.start
                        ending_port = args.end

                        #call process function
                        self.option_beetween_port_scan(target_ip, starting_port, ending_port)


                    elif not args.start:
                        print(Fore.RED+" "*20+"[*]PLEASE STARTING PORT ENTER[*]")
                        sys.exit(0)
                    elif not args.end:
                        print(Fore.RED+" "*20+"[*]PLEASE ENDING PORT ENTER[*]")
                        sys.exit(0)


            
            elif args.all:

                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER[*]")
                else:
                    target_ip = args.i
                    self.all_tcp_scan(target_ip)


            elif args.default:

                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER[*]\n")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    self.Port_scan_tcp(target_ip)
                
            
            elif args.ack:
                
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER[*]")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    if args.port:
                        port = args.port
                        self.ack_scan_option(target_ip, port)
                    else:
                        self.ack_scan_option_default(target_ip)
                        
            elif args.null:
                
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER [*]")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    
                    if args.port:
                        port = args.port
                        self.null_scan_option(target_ip, port)
                    else:
                        self.null_scan_option_default(target_ip)

            elif args.xmas:
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER [*]")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    if args.port:
                        port = args.port
                        self.xmas_scan_option(target_ip, port)

                    else:
                        self.xmas_scan_option_default(target_ip)
            elif args.fin:
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER [*]")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    if args.port:
                        port = args.port
                        self.fin_scan_option(target_ip, port)
                    else:
                        self.fin_scan_option_default(target_ip)
            
            elif args.connect:
                if args.i == None:
                    print(Fore.RED+" "*20+"[*]PLEASE DESTINATION TARGET IP ENTER [*]")
                    sys.exit(0)
                else:
                    target_ip = args.i
                    if args.port:
                        port = args.port
                        self.connect_scan_option(target_ip, port)
                    else:
                        self.connect_scan_default(target_ip)

if __name__ == '__main__':    
    o = Main()
    o.parameter_control()
