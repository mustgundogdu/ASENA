import socket
import sys

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
        result_scan = sock.connect_ex(('192.168.235.2', int(p)))

        #result control
        if 0 == result_scan:
            o_port = p
            port_list.append(o_port)
    
#Keyboard Interrupt
except KeyboardInterrupt:
    #success exit
    sys.exit(0)

file_read = open('default_ports.txt','r')
result = file_read.read().split('\n')
file_read.close()


file_read_version = open('default_port_version.txt', 'r')
result_version = file_read_version.read().split('\n')
file_read_version.close()



match_list = []
match_length = len(port_list)
default_port_list = []
version_port = []

for i in result:
    default_port_list.append(i)



for i in range (0,len(port_list)):

    for j in default_port_list:

        if str(port_list[i]) == str(j):
            match_list.append(port_list[i])


for t in range(0, len(match_list)):

    for p, res in zip(result, result_version):

        if str(match_list[t]) == str(p):
            print('{} port is Open version = {}'.format(match_list[t], res))
            print(res)
        elif str(match_list[t] == str(p)):
            print("unknow")


