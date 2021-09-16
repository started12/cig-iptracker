import socket
from scapy.all import *
import pyfiglet
import sys
import datetime

print(pyfiglet.print_figlet("IP Trackers"))
print(
"""
Created  By  STarTeD   (CiG)
"""
)

first_choice = input(
"""
[01] Get Domain IPs 
[02] Simple port scanner
[03] Exit 
"""
)

if first_choice == "3" or "03" :
    sys.exit(0)

if first_choice == "01" or "1" :
    print(pyfiglet.print_figlet("Domain IPs"))
    print(
        """
        Created  By  STarTeD   (CiG)
        """
    )
    Website32 = input("Enter Website Domain :  ")
    WebsiteIP = socket.gethostbyname(Website32)
    print(f"IP of the web domain ({Website32}) is '{WebsiteIP}' .")

if first_choice == "02" or "2" :
    scanning_IP = input("Enter the ip you want scan ports for :  ")
    print(f"Scanning target : '{scanning_IP}'.")
    print(f"Scanning started at : {str(datetime.now())} .")
    for port in range(1, 65535):
        socket32 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = socket32.connect_ex((scanning_IP, port))
        if result == 0:
            print(f"**Found an open port for '{scanning_IP}' is '{port}' .**")
