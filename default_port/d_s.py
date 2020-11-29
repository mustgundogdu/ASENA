import re
#Default ports file reading
port_read_file = open('default_ports.txt', 'r')
port_read_result = port_read_file.read().split('\n')
port_read_file.close()

#Default ports banner reading
banner_read_file = open('default_port_version.txt', 'r')
banner_read_result = banner_read_file.read().split('\n')
banner_read_file.close()


port = 53


for p, banner in zip(port_read_result, banner_read_result):
    
    if str(port) in str(p):

        print('{} {}'.format(p, banner))
