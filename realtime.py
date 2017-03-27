import os
x = 2
# Program to run in Realtime(Infinite Loop)
while x:
	#Use TCP Dump for program parsing.py
	os.system('sudo tcpdump -G 2 -W 1 -w /root/Desktop/myfile.pcap')
	#run the program parsing.py on the file name myfile.pcap
	os.system('sudo python /root/Desktop/parsing.py')