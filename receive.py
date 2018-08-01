from scapy.all import *
import threading
import time

sniff(iface = "s7-trf", prn = lambda x: hexdump(x))
