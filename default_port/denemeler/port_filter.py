
res = open('default_port_version.txt', 'r')
r = res.read().split('\n')
res.close()

ports = open('default_ports.txt', 'r')
ports_r = ports.read().split('\n')
ports.close()


port_list = []
port_service_name = []

for i in zip(ports_r,r):
    port_list.append(i[0])
    port_service_name.append(i[1])

for j in port_list:
    print(j)

for t in port_service_name:
    print(t)
    
