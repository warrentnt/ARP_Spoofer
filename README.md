# ARP_Spoofer
Author: Warren Thompson
Date: 05/29/2022
Python Module Name: ARP_Spoofer.py
Description: Simple ARP Spoofer implemented in Python 3 using the PyCharm IDE on a Kali Linux distribution. The user must provide a network address range as a command
line argument in the format "python3 ARP_Spoofer.py -n x.x.x.x/y"
Also the linux machine must be configured to forward ip traffic with the command "echo 1 > /proc/sys/net/ipv4/ip_forward". If this is not done, the traffic between the
two target machines will be dropped by the attacker Linux machine. 
