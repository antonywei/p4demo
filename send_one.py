from scapy.all import *
pkt=[]

for i in range(1000):
    p = Ether(src="00:00:00:00:01:01",dst="00:00:00:00:07:07") / IP(src="10.0.0.1",dst="10.0.7.7") / TCP(sport=1,dport=2) / "aaaaaaaaaaaaaaaaaaa"
    # p.show()
    pkt.append(p)
wrpcap("send.pcap",pkt)
          #hexdump(p)
          #sendp(p, iface = "s0-trf")
        #sendp(p,iface= "s2-trf")
