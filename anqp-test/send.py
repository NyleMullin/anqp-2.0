from telnetlib import IP
from scapy.all import *

sendp(Ether()/IP(dst="172.16.136.40",ttl=(1,4)),iface="eth0",loop=1,inter=3)
