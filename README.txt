[Project]

Code contained in this folder parses pcap files and looks for SYN and FIN,ACK packets. Once the code has identified each set of packets,
they are appended to a list which is then compared to eachother later to build a dictionary of full flows.

[Requirements]
hashlib
pyshark

[Build]
Place a pcap file in the folder you're working in
Execute the code with `python3 {name}.py`
Input the name of the pcap file

The script will return the number of flows seen from the sender (10.182.0.2) and will then generically return all the flows observed in the capture.

[Contributions]
Jackson Davies
Cameron Emfinger