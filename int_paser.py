from scapy.all import *
import threading
import time
from multiprocessing import Process,Queue
from multiprocessing import Pool
import os,random

runtime=20
#define how long to get the infomation

class INT(Packet):
    name="INT"
    fields_desc=[ByteField("count",0),
                ShortField("routeid",0),
                ByteField("swid1",0),
                IntField("qtimedelta1",0),
                IntField("deqlen1",0),
                ByteField("swid2",0),
                IntField("qtimedelta2",0),
                IntField("deqlen2",0),
                ByteField("swid3",0),
                IntField("qtimedelta3",0),
                IntField("deqlen3",0),
                ByteField("swid4",0),
                IntField("qtimedelta4",0),
                IntField("deqlen4",0),
                ByteField("swid5",0),
                IntField("qtimedelta5",0),
                IntField("deqlen5",0)]

bind_layers(Ether,INT,type=0x801)
bind_layers(INT,IP)

def handle_pkt(pkt,data_info,flag):
    count=pkt[INT].count
    
    #normal lize data
    switch_data={}
    swid_list=[pkt[INT].swid1,pkt[INT].swid2,pkt[INT].swid3,pkt[INT].swid4,pkt[INT].swid5]
    deqlen_list=[pkt[INT].deqlen1,pkt[INT].deqlen2,pkt[INT].deqlen3,pkt[INT].deqlen4,pkt[INT].deqlen5]
    qtimedelta=[pkt[INT].qtimedelta1,pkt[INT].qtimedelta2,pkt[INT].qtimedelta3,pkt[INT].qtimedelta4,pkt[INT].qtimedelta5]
    print "swid:",swid_list
    if flag.empty()==True:
        for i in range (5):
            if qtimedelta[i]>0:
                switch_data[swid_list[i]]={"deqlen":deqlen_list[i],"qtimedelta": qtimedelta[i]}
  #print int_receive
        print "put switch_data in Queue",switch_data
        data_info.put(switch_data)
    else:
        print "reading"
    #pkt.show2()
    sys.stdout.flush()

def listen(veth,data_info,flag):
    sniff(iface = veth, prn = lambda x: handle_pkt(x,data_info,flag))
def read(data_info,flag):
    print "processing to read %s" %os.getpid()
    while True:
        while flag.empty():
            time.sleep(runtime)
            flag.put("1")
            while data_info.empty()==False:
                value=data_info.get(True)
                print("get from quene",value)
            time.sleep(1)
            flag.get()

        print flag.qsize()
        


'''


t1=Process(target=listen,args=("s7-int",data_info,flag ))
t2=Process(target=listen,args=("s2-int",data_info,flag))
t3=Process(target=read,args=(data_info,flag))
#t1.setDaemon(True)
#t2.setDaemon(True)
#t3.setDaemon(True)
t1.start()
t2.start()
t3.start()
t1.join()
t2.join()
t3.join()
#time.sleep(60)
print "program end"
t1.terminate()
t2.terminate()
t3.terminate()


'''
