from scapy.all import *
import time
import random
for m in xrange(100000):
	for i in range(10):
  		p = Ether(src="00:00:00:00:01:01",dst="00:00:00:00:07:07") / IP(src="10.0.0."+str(i),dst="10.0.7.7") / TCP() / "aaaaaaaaaaaaaaaaaaa"
	# p.show()
  		hexdump(p)
  	#sendp(p, iface = "s0-trf")
  		sendp(p,iface= "s2-trf")

  		p2 = Ether(src="00:00:00:00:07:07",dst="00:00:00:00:02:02") / IP(src="10.0.0."+str(i),dst="10.0.2.2") / TCP() / "aaaaaaaaaaaaaaaaaaa"
	#p.show()
  		hexdump(p2)
  		sendp(p2,iface= "s7-trf")
  	time.sleep(random.random())
  	time.sleep(1)


