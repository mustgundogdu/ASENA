# ASENA

 Asena is the female wolf that guides the oğuz kağan in Turkish mythology.
The reason for the Asena analogy comes from the ability to guide packets on the network.Written with asena scapy module. to run you need to download scapy module.

![](https://github.com/mustgundogdu/ASENA/blob/master/asena.jpg)


Installation:


Let's install scapy developer first:

 * cd /tmp/
  
 * git clone https://github.com/secdev/scapy.git
  
 * cd scapy
  
 * python setup.py install
 
Then download asena 

* git clone https://github.com/mustgundogdu/ASENA.git




USAGE:

![](https://github.com/mustgundogdu/ASENA/blob/master/asena_help.png)



We can also list the ports open on the target machine.

For example:

python asena.py --pscan -i 192.168.2.143

Also With the Asena tool, we can detect active machines in our network with the arp query.

For this:

![](https://github.com/mustgundogdu/ASENA/blob/master/asena_networkscan.png)


Performs ack scan for firewall detection on open ports.

 For example:
 
python asena.py -f -i 192.168.2.143

It also performs an arpspoof attack using scapy again.

For example:

python asena.py --mitm -t 192.168.2.154 -g 192.168.2.1



