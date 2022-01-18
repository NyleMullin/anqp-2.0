from telnetlib import IP
from scapy.all import *

send(IP(dst="1.2.3.4")/ICMP())
sendp(Ether()/IP(dst="1.2.3.4",ttl=(1,4)),iface="eth0")