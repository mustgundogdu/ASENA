# ASENA

 Asena is the female wolf that guides the oğuz kağan in Turkish mythology.
The reason for the Asena analogy comes from the ability to guide packets on the network.Written with asena scapy module. to run you need to download scapy module.

![](https://github.com/mustgundogdu/ASENA/blob/master/asena.jpg)


Instalation:


Let's install scapy developer first:

 * cd /tmp/
  
 * git clone https://github.com/secdev/scapy.git
  
 * cd scapy
  
 * python setup.py install
 
Then download asena 

* git clone https://github.com/mustgundogdu/ASENA.git




USAGE:

![](https://github.com/mustgundogdu/ASENA/blob/master/help.png)

With the Asena tool, we can detect active machines in our network with the arp query.

For this:

./asena.py -s -i 192.168.2.0/24

We can also list the ports open on the target machine.

For example:

./asena.py --pscan -i 192.168.2.143

Performs ack scan for firewall detection on open ports.

 For example:
 
./asena.py -f -i 192.168.2.143

It also performs an arpspoof attack using scapy again.

For example:

./asena.py --arpspoof

It also shows the packet exit addresses using the traceroute working principle.

For example:

./asena.py --trace
