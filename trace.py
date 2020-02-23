#!/usr/bin/python3
import time
import sys
from scapy.all import *
t_out = 30

def udp_traceroute(hostname):
    result = []
    time_result = []
    i = 1
    while True:
        
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33433 + i)
        start_time = time.time()
        reply = sr1(pkt, verbose = 0, timeout = t_out)
        end_time = time.time()
        result.append(reply)
        time_result.append(end_time - start_time)

       
        if all(response is None for response in result[-5:]):
            break

        if reply is not None and reply.type ==3:
            break
        i+=1
    return result, time_result


if __name__ == "__main__":
    try:
        try:
            hostname = sys.argv[1]
            result, time_result = udp_traceroute(hostname)
        except :
            hostname = input("[H] Target Host:")
            result, time_result = udp_traceroute(hostname)
        
        for id, (reply, rtt) in enumerate(zip(result, time_result), start=1):
            if reply is not None:
                print(f"{id}: {reply.src} {int(rtt * 1000)}")
            else:
                print(f"{id}: *")
    except KeyboardInterrupt:
        print("Asena Shutdowning...\n")
        sys.exit()
