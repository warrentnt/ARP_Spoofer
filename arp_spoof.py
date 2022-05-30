#!/usr/bin/env python

import scapy.all as scapy
import argparse

def getcmd_args():
    cmd_parser = argparse.ArgumentParser()
    cmd_parser.add_argument("-n", "--network", dest="target_net", help="Target network range or individual ip address to scan")
    options = cmd_parser.parse_args()
    return options

def scan (ip):
    #scapy.arping(ip) # note this line works but we will build this from scratch
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    # Combine sections into one request
    arp_request_broadcast = broadcast/arp_request

    #Send packet with custom Ethernet framce and capture responses in variables responsive_list and unresponsive_list
    responsive_list, unresponsive_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    target_list = []
    count = 0
    for item in responsive_list:
        target_dict = {"index": count, "ip": item[1].psrc, "mac": item[1].hwsrc}
        target_list.append(target_dict)
        #print(item[1].psrc + "\t\t" + item[1].hwsrc)

        count += 1
    return target_list

def print_output(results_list):
    print("--------------------------------------------------")
    print("Index\tIP\t\t\tAt MAC Address")
    print("--------------------------------------------------")
    for target in results_list:
        print(str(target["index"]) + "\t" + target["ip"] + "\t\t" + target["mac"])
    #print(responsive_list.summary())

    #arp_request_broadcast.show()
    #print(arp_request_broadcast.summary())
    #print(arp_request.summary())
    #scapy.ls(scapy.Ether())

cmd_options = getcmd_args()
scan_result = scan(cmd_options.target_net)
print_output(scan_result)