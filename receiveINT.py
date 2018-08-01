from scapy.all import *
import threading
import time

sniff(iface = "s7-int", prn = lambda x: hexdump(x))
