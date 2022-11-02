import pyshark
import hashlib

capFile = input("Capture file: ")
cap = pyshark.FileCapture(capFile)

# sender set in problem set.
sender = '10.182.0.2'
# receiver set in problem set.
receiver = '34.125.237.121'

class Flow():
    def __init__(self, srcport, srcaddr, dstport, dstaddr):
        self.srcport = srcport
        self.srcaddr = srcaddr
        self.dstport = dstport
        self.dstaddr = dstaddr
        self.dHash = hashlib.md5("{0}{1}{2}{3}".format(srcport, srcaddr, dstport, dstaddr).encode()).hexdigest()

# when we find a SYN packet, we append the flow data to this list.
activeFlows = []
# when we find a FIN packet, we append the flow data to this list.
closedFlows = []
# later when we match the md5 hashes of the flow data, if we are able to pair an active flow with a closed flow, we append it to this list.
pairdFlows = {}
# When we see a SYN packet that matches the criteria layed out in the problem set, we add a number here.
tcpInitiatedBySender = 0

for packet in cap:
    if ((int(packet.tcp.flags_syn) and not int(packet.tcp.ack))):
        if packet.ip.src == sender:
            tcpInitiatedBySender += 1
        flow = Flow(packet.tcp.srcport, packet.ip.src, packet.tcp.dstport, packet.ip.dst)
        activeFlows.append(flow)


        


    if ((int(packet.tcp.flags_fin))):
        flow = Flow(packet.tcp.srcport, packet.ip.src, packet.tcp.dstport, packet.ip.dst)
        closedFlows.append(flow)


for item in activeFlows:
    for flow in closedFlows:
        if item.dHash == flow.dHash:
            pairdFlows[item] = flow

print(f"Number of TCP Flows initiated by sender defined in problem set: {tcpInitiatedBySender}")

for item in pairdFlows:
    print(f'[Source Port:] {item.srcport}, [Source Address:] {item.srcaddr}, [Destination Port:] {item.dstport}, [Destination Address:] {item.dstaddr}')




    

