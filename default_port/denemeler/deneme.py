#Create port list for results
res = 

port_list = []
#Check process
try:
    #Check Process
    #try:
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

    for open_port in zip(port_list, file_read):
        
        print(Fore.GREEN+" "*20+"*************** RESULT ***************")
        print(Fore.BLUE+" "*17+target_ip+"==>"+"[+] %d NUMBERED PORT IS OPEN \n"%open_port)
        
        #Process Except
        #except:
        #    print(Fore.RED+"[-]TCP PORT SCAN WRONG PROBLEM[-]")

#Keyboard Interrupt
except KeyboardInterrupt:
    #success exit
    sys.exit(0)
