import sys
import random
from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol
import runtimedata
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
import math
import time
from scapy.all import *
import threading
import re
from time import sleep
from scapy.all import *
import threading
import time
from multiprocessing import Process,Queue
from multiprocessing import Pool
import os,random
import int_paser

#from simple_switch import SimpleSwitch

CLIENTS=4
CPUALLO=[60,90,60,90]


SWITCH2SWITCH_PORT=[
[100,1,100,2,100,100,100,100,0,100],
[0,100,1,4,3,100,100,100,100,100],
[100,0,100,100,3,100,100,100,100,1],
[0,1,100,100,100,2,3,100,4,100],
[100,0,1,100,100,4,100,3,100,2],
[100,100,100,0,1,100,3,2,100,100],
[100,100,100,1,100,100,2,3,0,100],
[100,100,100,100,2,1,0,100,100,4],
[0,100,100,1,100,100,2,100,100,100],
[100,100,0,100,2,100,100,3,100,100]]

#define routeid  ABC =>A:src B:dst C:flowNum

#collect add_table return id for delete table key=routeid value=add_table_handle_id 
flowsHandleIDdic={}
#collect old_flow rules key=routeid value=flow rules;
old_flow_rules={}
#collect action group profile handle key=src2dst value=group_handle
action_profile_handle={}
#collect the routeid of src2dst key= src2dst value=route_id
src2dst_routeid={}
#collect member of flows key=routeid,value=member_handle
routeid_handle={}
#define int read time 
runtime=10

SWITCH_TO_HOST_PORT=10


switch_num=10

def thrift_connect(thrift_ip, thrift_port, services, out=sys.stdout):
    def my_print(s):
        out.write(s)

    # Make socket
    transport = TSocket.TSocket(thrift_ip, thrift_port)
    # Buffering is critical. Raw sockets are very slow
    transport = TTransport.TBufferedTransport(transport)
    # Wrap in a protocol
    bprotocol = TBinaryProtocol.TBinaryProtocol(transport)

    clients = []

    for service_name, service_cls in services:
        if service_name is None:
            clients.append(None)
            continue
        protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, service_name)
        client = service_cls(protocol)
        clients.append(client)

    # Connect!
    try:
        transport.open()
    except TTransport.TTransportException:
        my_print("Could not connect to thrift client on port {}\n".format(
            thrift_port))
        my_print("Make sure the switch is running ")
        my_print("and that you have the right port\n")
        sys.exit(1)

    return clients

class SWITCH():

    def __init__(self,thrift_port,thrift_ip="localhost"):
        self.client=thrift_connect(thrift_ip, thrift_port, [("standard", Standard.Client)])[0]

    def counter_read(self,counter_name):
        message=self.client.bm_counter_read(cxt_id=0, counter_name=counter_name,index=0)
        return message
    def counter_reset(self,counter_name):
        self.client.bm_counter_reset_all(cxt_id=0, counter_name=counter_name)
    def register_write(self,register_name,index,value):
        self.client.bm_register_write(0,register_name,index,value)

    def table_delete(self,table,entry_handle):
        self.client.bm_mt_delete_entry(0,table,entry_handle)
    def register_read(self, register_name, index):
        return self.client.bm_register_read(0, register_name, index)
    def set_default_action(self,table_name,action,runtime_data,runtime_data_types):
        self.client.bm_mt_set_default_action(0, table_name=table_name, action_name=action, action_data=runtimedata.parse_runtime_data(runtime_data,runtime_data_types))
    def table_modify(self,table,handle,action,runtime_data,runtime_data_types):
        message = self.client.bm_mt_modify_entry(0,table,handle,action,runtimedata.parse_runtime_data(runtime_data,runtime_data_types))
        return message
    #types mean "ip" or "mac" or a "integer", integer is bitwidth of a param
    def table_add(self,table,match_key,match_key_types,action,runtime_data,runtime_data_types):
        message=self.client.bm_mt_add_entry(0,table,runtimedata.parse_lpm_match_key(match_key,match_key_types),action,runtimedata.parse_runtime_data(runtime_data,runtime_data_types),BmAddEntryOptions(priority = 0))
        return message
    def table_add1(self,table,match_key,match_key_types,action,runtime_data,runtime_data_types):
        message=self.client.bm_mt_add_entry(0,table,runtimedata.parse_match_key(match_key,match_key_types),action,runtimedata.parse_runtime_data(runtime_data,runtime_data_types),BmAddEntryOptions(priority = 0))
        return message
    def table_get(self,table_name):
        message = self.client.bm_mt_get_entries(0,table_name)
        return message;
    def mirroring_add(mirror_id, egress_port):
        self.client.mirroring_mapping_add(self, mirror_id, egress_port)
    def create_group(self,action_profile_name):
        message=self.client.bm_mt_act_prof_create_group(0,act_prof_name=action_profile_name)
        return message
    def add_member_to_group(self,action_profile_name, mbr_handle, grp_handle):
        message=self.client.bm_mt_act_prof_add_member_to_group(0,action_profile_name, mbr_handle, grp_handle)
        return message
    def act_prof_add_member(self,action_profile_name,action_name,runtime_data,runtime_data_types):
        message=self.client.bm_mt_act_prof_add_member(0, action_profile_name, action_name, action_data=runtimedata.parse_runtime_data(runtime_data,runtime_data_types))
        return message
    def add_entry_to_group(self,table_name, match_key,match_key_types, grp_handle):
        self.client.bm_mt_indirect_ws_add_entry(0, table_name=table_name, match_key=runtimedata.parse_lpm_match_key(match_key,match_key_types), grp_handle=grp_handle, options=BmAddEntryOptions(priority = 0))
   
###write int rules     
def writeINTrules(switch_list,swid,Num):
    switch_list[Num].set_default_action(
        table_name="add_mri1",
        action="addmri1",
        runtime_data=[str(swid)],
        runtime_data_types=['4']
        )
    print "Installed INT rule on s"+str(Num+1)

    switch_list[Num].set_default_action(
        table_name="add_mri2",
        action="addmri2",
        runtime_data=[str(swid)],
        runtime_data_types=['4']
        )

    print "Installed INT rule on s"+str(Num+1)

    switch_list[Num].set_default_action(
        table_name="add_mri3",
        action="addmri3",
        runtime_data=[str(swid)],
        runtime_data_types=['4']
        )

    print "Installed INT rule on s"+str(Num+1)

    switch_list[Num].set_default_action(
        table_name="add_mri4",
        action="addmri4",
        runtime_data=[str(swid)],
        runtime_data_types=['4']
        )

    print "Installed INT rule on s"+str(Num+1)

    switch_list[Num].set_default_action(
        table_name="add_mri5",
        action="addmri5",
        runtime_data=[str(swid)],
        runtime_data_types=['4']
        )

    print "Installed INT rule on s"+str(Num+1)
###write tunnel rules
def setRouteidGroup(switch,routeid_list,actionProfileName):
        #set group
        routeid_num=len(routeid_list)
        #check route id is correct 
        for i in range(routeid_num):
            if routeid_list[i][0]!=routeid_list[0][0] or routeid_list[i][1]!=routeid_list[0][1]:
                print "set routeid invalid routeid ABC =>A:src B:dst C:flowNum, different src2dst can not in same group"
                return
        #set src2dst dict 
        src2dst=str(routeid_list[0][0]+routeid_list[0][1])
        src2dst_routeid[src2dst]=[]

        for i in range(routeid_num):
            src2dst_routeid[src2dst].append(str(routeid_list[i]))
        print "src2dict: ",src2dst_routeid
        print actionProfileName
        info=switch.create_group(actionProfileName)
        
        action_profile_handle[str(src2dst)]=info
        print "add group from h"+src2dst[0]+" to "+src2dst[1]
        ##add set_routeid action to member 
        for i in range(routeid_num):
            info=switch.act_prof_add_member(action_profile_name=actionProfileName,
                                action_name="set_routeid",
                                runtime_data=[str(routeid_list[i])],
                                runtime_data_types=['12'])
            routeid_handle[str(routeid_list[i])]=info
            print "routeid_handle ",routeid_handle
            print "routeid_handle[str(routeid_list[i])]",routeid_handle[str(routeid_list[i])]
            switch.add_member_to_group(action_profile_name=actionProfileName,
                                mbr_handle=routeid_handle[str(routeid_list[i])],
                                grp_handle=action_profile_handle[str(src2dst)])

def addRouteid2Group(switch,routeid,action_profile_name):
    if routeid in routeid_handle:
        print "this route id has already add to group"
        return
    src2dst=str(routeid[0]+routeid[1])
    info=switch.act_prof_add_member(action_profile_name=action_profile_name,
                                action_name="set_routeid",
                                runtime_data=[str(routeid)],
                                runtime_data_types=['12'])
    routeid_handle[str(routeid)]=info
    switch.add_member_to_group(action_profile_name=action_profile_name,
                                mbr_handle=routeid_handle[str(routeid)],
                                grp_handle=action_profile_handle[str(src2dst)])

def setMatch2Group(switch,src2dst,dst_ip_addr):
    switch.add_entry_to_group(table_name="add_mri",
                             match_key=[dst_ip_addr],
                             match_key_types=["ip"],
                             grp_handle=action_profile_handle[src2dst])

def deleteRouteidInGroup():
    pass
def writeTunnelRules(switch_list,flow_rules, route_id,dst_ip_addr, dst_eth_addr):
    flowsHandleIDdic[str(route_id)]=[];
    Hop = len(flow_rules)
    '''
    info = switch_list[int(flow_rules[0])-1].table_add(
        table="add_mri",
        action="set_routeid",
        match_key=[dst_ip_addr],
        match_key_types=["ip"],
        runtime_data=[str(route_id)],
        runtime_data_types=['12']
        )
    flowsHandleIDdic[str(route_id)].append(info)
    print "set routeid in s"+ str(flow_rules[0])
    '''
    for i in xrange(Hop-1):
        SWITCH_TO_SWITCH_PORT=SWITCH2SWITCH_PORT[int(flow_rules[i])][int(flow_rules[i+1])]
        info=switch_list[int(flow_rules[i])].table_add1(
            table="routeid_fwd",
            action="ipv4_fwd",
            match_key=[str(route_id)],
            match_key_types=['12'],
            runtime_data=[str(SWITCH_TO_SWITCH_PORT)],
            runtime_data_types=['9']
        )
        print "add route on S" +flow_rules[i]+"handle is ",info
        print "port is ",SWITCH_TO_SWITCH_PORT
        flowsHandleIDdic[str(route_id)].append(info)

    info=switch_list[int(flow_rules[Hop-1])].table_add1(
            table="routeid_fwd",
            action="fwd2host",
            match_key=[str(route_id)],
            match_key_types=['12'],
            runtime_data=[dst_eth_addr,str(SWITCH_TO_HOST_PORT)],
            runtime_data_types=['mac','9']
        )
    print "add route on S" +str(int(flow_rules[Hop-1]))
    print "port is ",SWITCH_TO_HOST_PORT
    flowsHandleIDdic[str(route_id)].append(info)
    old_flow_rules[str(route_id)]=flow_rules
#delete table by route id 
def deleteTunnelRules(switch_list,route_id):
    Hop = len(old_flow_rules[str(route_id)])
    print "flowsHandleIDdic " ,flowsHandleIDdic
    for i in range(0,Hop):
        print "delete switch num is",int(old_flow_rules[str(route_id)][i])
        print "delete flowsHandleIDdic is",flowsHandleIDdic[str(route_id)][i]

        switch_list[int(old_flow_rules[str(route_id)][i])].table_delete(
        table="routeid_fwd",
        entry_handle=flowsHandleIDdic[str(route_id)][i],
        ) 
        print "delete table of s"+  old_flow_rules[str(route_id)][i]
    del old_flow_rules[str(route_id)]
    del flowsHandleIDdic[str(route_id)]
#create new flow rules
def flowRulesInit(switch_list,routeid_list,flowRules_list,dst_ip_addr,dst_eth_addr):
    if len(routeid_list) != len(flowRules_list):
        print "routeid num doesn't match flow_rules"
        return 
    for i in range(len(routeid_list)):
        if routeid_list[i][0] != flowRules_list[i][0] or routeid_list[i][1] != flowRules_list[i][-1]:
            print "routeid key doesn't match flow_rules"
            return
        if routeid_list[i] in routeid_handle:
            print "route_id has already add in group please use flow rules modify"
    print "adding group .....\n"
    setRouteidGroup(switch_list[int(flowRules_list[0][0])],routeid_list,actionProfileName="set_routeid_profile")
    print "adding match to group....\n"
    src2dst=routeid_list[i][0]+routeid_list[i][1]
    setMatch2Group(switch_list[int(flowRules_list[0][0])],src2dst,dst_ip_addr=dst_ip_addr)
    for i in range (len(routeid_list)):
        writeTunnelRules(switch_list=switch_list,flow_rules=flowRules_list[i], route_id=routeid_list[i],dst_ip_addr=dst_ip_addr, dst_eth_addr=dst_eth_addr)
def flowRulesModify(switch_list,route_id,flow_rules,dst_ip_addr,dst_eth_addr):
    deleteTunnelRules(switch_list=switch_list,route_id=route_id)
    writeTunnelRules(switch_list=switch_list,flow_rules=flow_rules, route_id=route_id,dst_ip_addr=dst_ip_addr, dst_eth_addr=dst_eth_addr)

#read counter of switch
def readTable(switch_list):
    for i in range  (switch_num):
        print( "read table of mri")
        a = switch_list[i].table_get("add_mri")
        print "s"+str(i+1)+" add_mri infomation: " 
        print a; 
        print '\n'
    for i in range  (switch_num):
        print "read table of route_id forward"
        a = switch_list[i].table_get("routeid_fwd")
        print "s"+str(i+1)+" routid_fwd infomation: "
        print a;
        print '\n'

#read counter of switch

def switchConnect():

    try :
        print "connect to s0"
        s0=SWITCH(9000,"127.0.0.1")
        print "connect to s1"
        s1=SWITCH(9001,"127.0.0.1")
        print "connect to s2"
        s2=SWITCH(9002,"127.0.0.1")
        print "connect to s3"
        s3=SWITCH(9003,"127.0.0.1")
        print "connect to s4"
        s4=SWITCH(9004,"127.0.0.1")
        print "connect to s5"
        s5=SWITCH(9005,"127.0.0.1")
        print "connect to s6"
        s6=SWITCH(9006,"127.0.0.1")
        print "connect to s7"
        s7=SWITCH(9007,"127.0.0.1")
        print "connect to s8"
        s8=SWITCH(9008,"127.0.0.1")
        print "connect to s9"
        s9=SWITCH(9009,"127.0.0.1")
        switch_list=[s0,s1,s2,s3,s4,s5,s6,s7,s8,s9]
    except:
        print "connect error"
    return switch_list


def normalData(int_recv,value):
    key_list=value.keys()
    for i in key_list:
        if "deqlen" in int_recv[i]:
            int_recv[i]["deqlen"]=(int_recv[i]["deqlen"]+value[i]["deqlen"])/2.0
            int_recv[i]["qtimedelta"]=(int_recv[i]["qtimedelta"]+value[i]["qtimedelta"])/2.0
        else:
            int_recv[i]["deqlen"]=value[i]["deqlen"]
            int_recv[i]["qtimedelta"]=value[i]["qtimedelta"]
    return int_recv


def readIntTable(data_info,flag,switch_list,counterName):
    int_recv={}
    print "processing to read %s" %os.getpid()
    if flag.empty(): #make sure can put a flag to stop collection
        for i in range(switch_num):
            int_recv[i]={}
            switch_list[i].counter_reset(counter_name=counterName)
        time.sleep(runtime)    #collect period about runtime seconds
        flag.put("1")     #put a flag to pause collection int infomation
        while data_info.empty()==False:
            value=data_info.get(True)
            int_recv=normalData(int_recv,value)
        for i in range(switch_num):
            info=switch_list[i].counter_read(counter_name=counterName)
            int_recv[i]["packets"]=info.packets
            int_recv[i]["bytes"]=info.bytes
    print flag.qsize()
    return int_recv


def controllerMain(data_info,flag):
    try : 
        switch_list=switchConnect()
        #add int rules
        for i in range (switch_num):
            writeINTrules(switch_list,swid=i,Num=i)
        #init two flows
        flowRulesInit(switch_list,routeid_list=['271','272'],flowRules_list=['247','297'],dst_ip_addr="10.0.7.7", dst_eth_addr="00:00:00:00:07:07")
        flowRulesInit(switch_list,routeid_list=['721','722'],flowRules_list=['742','792'],dst_ip_addr="10.0.2.2", dst_eth_addr="00:00:00:00:02:02")
        #get table flow rules
        readTable(switch_list)
        while True:
            int_data=readIntTable(data_info,flag,switch_list,counterName="my_counter")
            print "int_data",int_data
            sleep(10) #replace by machine learing algorithm
            print "modify flow rules"
            flowRulesModify(switch_list,route_id='271',flow_rules='21357',dst_ip_addr="10.0.7.7",dst_eth_addr="00:00:00:00:07:07")
            flowRulesModify(switch_list,route_id='272',flow_rules='21457',dst_ip_addr="10.0.7.7",dst_eth_addr="00:00:00:00:07:07")
            flag.get()  #continue to collect data
            readTable(switch_list)
    except KeyboardInterrupt:
        print " Shutting down."




if __name__=="__main__":
    data_info = Queue()
    flag = Queue()
    t1=Process(target=int_paser.listen,args=("s7-int",data_info,flag ))
    t2=Process(target=int_paser.listen,args=("s2-int",data_info,flag))
    t3=Process(target=controllerMain,args=(data_info,flag))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    #t2=Process(target=listen,args=("s2-int",data_info,flag))
    #t3=Process(target=read,args=(data_info,flag))
    #controllerMain()

