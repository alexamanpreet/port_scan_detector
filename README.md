# Port Scan Detector
# This application works on a pcap file and real-time performing active port scanning.

The following types of port scans are going to be performed:

•	XMAS scan
•	FIN Scan
•	TCP SYN stealth scan
•	TCP Connection scan

The dpkt module was the most suitable module to perform these scans.

The features of dpkt that were really helpful are as follows:
•	dpkt is a python library for manipulating packets and it an excellent library that has not been documented properly.
•	The following attributes of dpkt in our program that were not unmatched by any other module:
  o	 dpkt.pcap.Reader(f) to implement an iterator.
  o	dpkt.ethernet.Ethernet that has the attributes 'data', 'dst', 'get_type', 'ip', 'pack', 'pack_hdr', 'set_type', 'src', 'type', and 'unpack'.
  o	dpkt.ip to interpret and work with IP packet formats.

The socket module in Python also provided really excellent interpretation and access to the BSD socket interface.

The following parameters of the socket interface were the most useful:
•	The socket() function returns a socket object whose methods implement the various socket system calls.
•	socket.inet_aton(ip_string) was used to convert an IPv4 address from dotted-quad string format to a 32-bit packed binary format, as a string of four characters in length.
•	The socket.AF_INET is used and it is a constant that represent the address.

Other tools such as Kali, Wireshark, nmap, bash scripts, and tcpdump were also used for testing and training purposes.

## The logic is to look at the first 10 consecutive packets that are transferred / captured within 5000 milliseconds.

Algorithms were created to recognize the type of scan by analyzing the host's pcap TCP dump file.

The packets are compared against the port scan logic to set the status of that packet class/structure to 'B' (blocked). If the IP is blocked our program traverses across the flag list within the packet class and looks for a pattern in the set flags.

A secondary logic was used to output the range of ports scanned and to display the duration of the scan.

The logic looks at a source and destination IP pair and notes down source port, destination port, flag, and time that can be used to analyze in any manner depending on the pattern we are looking for.
