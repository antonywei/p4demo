from scapy.all import *
import threading
import time

cs=0

class INT(Packet):
    name="INT"
    fields_desc=[ByteField("count",0),
                ShortField("routeid",0),
                ByteField("swid1",0),
                IntField("qtimedelta1",0),
                IntField("deqlen1",0),
                IntField("timestamp1",0),
                ByteField("swid2",0),
                IntField("qtimedelta2",0),
                IntField("deqlen2",0),
                IntField("timestamp2",0),
                ByteField("swid3",0),
                IntField("qtimedelta3",0),
                IntField("deqlen3",0),
                IntField("timestamp3",0),
                ByteField("swid4",0),
                IntField("qtimedelta4",0),
                IntField("deqlen4",0),
                IntField("timestamp4",0),
                ByteField("swid5",0),
                IntField("qtimedelta5",0),
                IntField("deqlen5",0),
                IntField("timestamp5",0)]

bind_layers(Ether,INT,type=0x801)
bind_layers(INT,IP)

def handle_pkt(pkt):

    count=pkt[INT].count
    timedelay1=pkt[INT].timestamp2-pkt[INT].timestamp1
    timedelay2=pkt[INT].timestamp3-pkt[INT].timestamp2
    timedelay3=pkt[INT].timestamp4-pkt[INT].timestamp3
    timedelay4=pkt[INT].timestamp5-pkt[INT].timestamp4



    int_receive={"routeid":pkt[INT].routeid,
                    "swid1":pkt[INT].swid1,
                    "swid1_qtime":pkt[INT].qtimedelta1,
                    "swid2":pkt[INT].swid2,
                    "swid2_qtime":pkt[INT].qtimedelta2,
                    "swid3":pkt[INT].swid3,
                    "swid3_qtime":pkt[INT].qtimedelta3,
                    "swid4":pkt[INT].swid4,
                    "swid4_qtime":pkt[INT].qtimedelta4,
                    "swid5":pkt[INT].swid5,
                    "swid5_qtime":pkt[INT].qtimedelta5,
                    "timedelay1":timedelay1,
                    "timedelay2":timedelay2,
                    "timedelay3":timedelay3,
                    "timedelay4":timedelay4}
    #print int_receive
    global cs
    cs+=1
    print str(cs)
    pkt.show2()
    sys.stdout.flush()

def listen(veth):
    sniff(iface = veth, prn = lambda x: handle_pkt(x))
    print str(cs)


t1=threading.Thread(target=listen,args=("s7-int",))
#t2=threading.Thread(target=listen,args=("s2-int",))
t1.setDaemon(True)
#t2.setDaemon(True)
t1.start()
#t2.start()
time.sleep(100)
