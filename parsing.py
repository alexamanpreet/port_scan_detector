import dpkt #  To Read the Raw Data From PCAP File
import socket # To Convert Raw IP to Readable Format
import copy # To Deep Copy Lists
import os # To Run Linux Commands

#Class Defination
class packet(object):
	"""docstring for packet"""
	def __init__(self, ip, dip):
		self.ip = ip
		self.dip = dip
		self.time = []
		self.sport = []
		self.dport = []
		self.flag = []
		self.xmas = 0
		self.fin = 0
		self.null = 0
		self.tcps = 0
		self.tcpc = 0
		self.tcpsc = 0
		self.ctr = 0
		self.st = "NB"
	def __repr__(self):
		return repr((self.ip, self.dip, self.time, self.sport, self.dport, self.flag, self.ctr, self.st))
	def __str__(self):
		return str((str (self.ip), str (self.dip), str (self.time), str(self.sport), str (self.dport), str (self.flag), str (self.ctr), str (self.st)))

# Convert Raw IP Packet to Readable Format
def ip_to_str(address):
	return socket.inet_ntop(socket.AF_INET, address)

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

#Reading The File
filename='/root/Desktop/myfile.pcap'
#Some Lists & Variables for Further Use
packetlisttcp = []
packetlistudp = []
timelist = []
portlist = []
output = []
output1 = []
output2 = []
temp = 9
temp1 = []
temp2 = []
uportlist = []
uport = 0
traversed = []
detect = []

# Start PCAP File Parsing
for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):

	counter+=1
	eth=dpkt.ethernet.Ethernet(pkt) 
	if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
		continue
    
	ip=eth.data
	ipcounter+=1
	count = 0
	count1 = 0
#Check if IP Packet is TCP and and Append Time, Destination Port, Source Port & Flags for a pair for IP
	if ip.p==dpkt.ip.IP_PROTO_TCP: 
		tcpcounter+=1
		if (len(packetlisttcp) == 0):
			packetlisttcp.append(packet(eth.ip.src, eth.ip.dst))
			for i in range(int(len(packetlisttcp))):
				if (eth.ip.src == packetlisttcp[i].ip and eth.ip.dst == packetlisttcp[i].dip):
					packetlisttcp[i].time.append(ts)
					packetlisttcp[i].dport.append(ip.tcp.dport)
					packetlisttcp[i].sport.append(ip.tcp.sport)
					packetlisttcp[i].flag.append(ip.tcp.flags)
					packetlisttcp[i].ctr += 1
					count = 1
					break
		if (len(packetlisttcp) > 0 and count == 0):
			for i in range(int(len(packetlisttcp))):
				if (eth.ip.src == packetlisttcp[i].ip and eth.ip.dst == packetlisttcp[i].dip):
					packetlisttcp[i].time.append(ts)
					packetlisttcp[i].dport.append(ip.tcp.dport)
					packetlisttcp[i].sport.append(ip.tcp.sport)
					packetlisttcp[i].flag.append(ip.tcp.flags)
					packetlisttcp[i].ctr += 1
					count1 = 1
					break
				if (eth.ip.src != packetlisttcp[i].ip and eth.ip.src != packetlisttcp[i].dip):
					packetlisttcp.append(packet(eth.ip.src, eth.ip.dst))
					for i in range(int(len(packetlisttcp))):
						if (eth.ip.src == packetlisttcp[i].ip and eth.ip.dst == packetlisttcp[i].dip):
							packetlisttcp[i].time.append(ts)
							packetlisttcp[i].dport.append(ip.tcp.dport)
							packetlisttcp[i].sport.append(ip.tcp.sport)
							packetlisttcp[i].flag.append(ip.tcp.flags)
							packetlisttcp[i].ctr += 1
							count1 = 1
							break
		if (len(packetlisttcp) > 0 and count1 == 0 and count == 0):
			for i in range(int(len(packetlisttcp))):
				 if (eth.ip.src == packetlisttcp[i].dip and eth.ip.dst == packetlisttcp[i].ip):
				 	packetlisttcp[i].time.append(ts)
					packetlisttcp[i].dport.append(ip.tcp.sport)
					packetlisttcp[i].sport.append(ip.tcp.dport)
				 	packetlisttcp[i].flag.append(ip.tcp.flags)
				 	break
#Check if IP Packet is UDP and Append Time, Destination Port, Source Port for a pair for IP
	if ip.p==dpkt.ip.IP_PROTO_UDP:
		udpcounter+=1
		if (len(packetlistudp) == 0):
			packetlistudp.append(packet(eth.ip.src, eth.ip.dst))
			for i in range(int(len(packetlistudp))):
				if (eth.ip.src == packetlistudp[i].ip and eth.ip.dst == packetlistudp[i].dip):
					packetlistudp[i].time.append(ts)
					packetlistudp[i].dport.append(ip.udp.dport)
					packetlistudp[i].sport.append(ip.udp.sport)
					packetlistudp[i].ctr += 1
					count = 1
					break
		if (len(packetlistudp) > 0 and count == 0):
			for i in range(int(len(packetlistudp))):
				if (eth.ip.src == packetlistudp[i].ip and eth.ip.dst == packetlistudp[i].dip):
					packetlistudp[i].time.append(ts)
					packetlistudp[i].dport.append(ip.udp.dport)
					packetlistudp[i].sport.append(ip.udp.sport)
					packetlistudp[i].ctr += 1
					break
				if (eth.ip.src != packetlistudp[i].ip and eth.ip.src != packetlistudp[i].dip):
					packetlistudp.append(packet(eth.ip.src, eth.ip.dst))
					for i in range(int(len(packetlistudp))):
						if (eth.ip.src == packetlistudp[i].ip and eth.ip.dst == packetlistudp[i].dip):
							packetlistudp[i].time.append(ts)
							packetlistudp[i].dport.append(ip.udp.dport)
							packetlistudp[i].sport.append(ip.udp.sport)
							packetlistudp[i].ctr += 1
							break

#If there are 10 consiquitive packets which lie within 
#5000 miliseconds then its a port scan and will set the status to B(Blocked)
for i in range(int(len(packetlisttcp))):
	while len(output) > 0 : output.pop()
	while len(output1) > 0 : output1.pop()
	for j in range(int(len(packetlisttcp[i].time)-9)):
		for k in range(temp):
			output1.append(packetlisttcp[i].dport[j+k])
		for x in output1:
			if x not in output:
				output.append(x)
		if ((packetlisttcp[i].time[j+9]-packetlisttcp[i].time[j]) < 0.0005 and len(output) > 1):
			packetlisttcp[i].st = "B"
			break

while len(output) > 0 : output.pop()
while len(output1) > 0 : output1.pop()

for i in range(int(len(packetlisttcp))):
	if (packetlisttcp[i].st == "B"):
		for x in packetlisttcp[i].dport:
			if x not in output2:
				output2.append(x)


#IF any IP has status as B(Blocked) then look for Type of Attacks() and set the Flags for Detected Attacks
for i in range(int(len(packetlisttcp))):
	if (packetlisttcp[i].st == "B"):
		for x in range(int(len(output2))):
			for j in range(int(len(packetlisttcp[i].dport))):
				if (output2[x] == packetlisttcp[i].dport[j] and packetlisttcp[i].dport[j] not in traversed):
					if (len(uportlist) == 0):
						uportlist.append(j)
						uport = packetlisttcp[i].dport[j]
						
					if (len(uportlist) > 0):
						for k in range(int(len(packetlisttcp[i].dport))):
							if (uport == packetlisttcp[i].dport[k] and j != k):
								uportlist.append(k)
						for l in range(int(len(uportlist))):
							detect.append(packetlisttcp[i].flag[uportlist[l]])
						if (len(detect) >= 1):
							for y in range(int(len(detect))):
								if (detect[y] == 41):
									packetlisttcp[i].xmas = 1
									break
							for y in range(int(len(detect))):
								if (detect[y] == 1):
									packetlisttcp[i].fin = 1
									break
							for y in range(int(len(detect))):
								if (detect[y] == 0):
									packetlisttcp[i].null = 1
									break
						if (len(detect) >= 2):
							for y in range(int(len(detect)-1)):
								if ((detect[y] == 2 and detect[y+1] == 4)):
									packetlisttcp[i].tcps = 1
									break
							for y in range(int(len(detect)-1)):
								if (detect[y] == 16 and detect[y+1] == 20):
									packetlisttcp[i].tcpc = 1
									break
							for y in range(int(len(detect)-1)):
								if (detect[y] == 2 and detect[y+1] == 20):
									packetlisttcp[i].tcpsc = 1
									break
						uport = 0
						while len(uportlist) > 0 : uportlist.pop()
						while len(detect) > 0 : detect.pop()
					traversed.append(output2[x])

#If a Port Scan Is Detected then Merge the Current myfile.pcap File to output.pcap file
for i in range(int(len(packetlisttcp))):
	if (packetlisttcp[i].st == "B"):
		os.system('sudo mergecap -a -w /root/Desktop/output.pcap /root/Desktop/myfile.pcap')

#Print The Scan and Types of Attacks Detected
for i in range(int(len(packetlisttcp))):
	if (packetlisttcp[i].st == "B"):
		temp1 = copy.deepcopy(packetlisttcp[i].time)
		temp2 = copy.deepcopy(packetlisttcp[i].dport)
		print "Scan Detected:"
		print "Source IP:", ip_to_str(packetlisttcp[i].ip)
		print "Destination IP:", ip_to_str(packetlisttcp[i].dip)
		print "Scanned Port List:", packetlisttcp[i].dport
		if (packetlisttcp[i].xmas == 1):
			print "XMAS Scan Detected"
		if (packetlisttcp[i].fin == 1):
			print "FIN Scan Detected"
		if (packetlisttcp[i].tcps == 1):
			print "TCP Stealth Scan Detected"
		if (packetlisttcp[i].tcpc == 1):
			print "TCP Connect Scan Detected"
		if (packetlisttcp[i].null == 1):
			print "NULL Scan Detected"
		if (packetlisttcp[i].tcpsc == 1):
			print "TCP Stealth or TCP Connect Scan Detected"
		timelist = sorted(temp1)
		portlist = sorted(temp2)
		for x in portlist:
			if x not in output:
				output.append(x)
		for x in timelist:
			if x not in output1:
				output1.append(x)
		if (len(output) > 1):
			print "Range of Ports Scanned: ", output[0], '-', output[len(output)-1]
		if (len(output1) > 1):
			print "Duration of TCP Scan: ", output1[len(output1)-1] - output1[0], "Seconds\n"
		while len(timelist) > 0 : timelist.pop()
		while len(portlist) > 0 : portlist.pop()
		while len(output) > 0 : output.pop()
		while len(output1) > 0 : output1.pop()


#Detect if There is A UDP Scan
for i in range(int(len(packetlistudp))):
	while len(output) > 0 : output.pop()
	while len(output1) > 0 : output1.pop()
	for j in range(int(len(packetlistudp[i].time)-9)):
		for k in range(temp):
			output1.append(packetlistudp[i].dport[j+k])
		for x in output1:
			if x not in output:
				output.append(x)
		if ((packetlistudp[i].time[j+9]-packetlistudp[i].time[j]) < 0.0005 and len(output) > 1):
			packetlistudp[i].st = "B"
			break

while len(output) > 0 : output.pop()
while len(output1) > 0 : output1.pop()

#Print If UDP Scan Detected
for i in range(int(len(packetlistudp))):
	if (packetlistudp[i].st == "B"):
		temp1 = copy.deepcopy(packetlistudp[i].time)
		temp2 = copy.deepcopy(packetlistudp[i].dport)
		print "Scan Detected:"
		print "Source IP: ", ip_to_str(packetlistudp[i].ip)
		print "Destination IP: ", ip_to_str(packetlistudp[i].dip)
		print "Destination Port List: ", packetlistudp[i].dport
		print "UDP Port Scan Detected"
		timelist = sorted(temp1)
		portlist = sorted(temp2)
		for x in portlist:
			if x not in output:
				output.append(x)
		for x in timelist:
			if x not in output1:
				output1.append(x)
		if (len(output) > 1):
			print "Range of Ports Scanned: ", output[0], '-', output[len(output)-1]
		if (len(output1) > 1):
			print "Duration of UDP Scan: ", output1[len(output1)-1] - output1[0], "Seconds\n"
		while len(timelist) > 0 : timelist.pop()
		while len(portlist) > 0 : portlist.pop()
		while len(output) > 0 : output.pop()
		while len(output1) > 0 : output1.pop()
		