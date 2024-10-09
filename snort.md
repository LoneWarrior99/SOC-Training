This is a writeup for TryHackMe's snort module. 

"SNORT is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS). It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team."  



### The Basics
---
Let's create IDSRules for HTTPtraffic!
	
	Write a single rule to detect "all TCP port 80 traffic" packets in the given pcap file. 
	What is the number of detected packets?
	
		Open local.rules filege with sudo gedit;
		alert tcp any 80 <> any any (msg:"src-TCP port 80 found"; sid: 100001; rev:1;)
		alert tcp any any <> any 80 (msg:"des-TCP port 80 found"; sid: 100002; rev:1;)
		
		Snort the file;
		sudo snort -c local.rules -A full -l . -r mx-3.pcap
		
		Ls to see alert and log file created
		
		Snort log file to read - 
		sudo snort -r snort.log.1724256760
		Total at end represents detected packets: 164
	
	Investigate the log file.
	
	Info we can find;
		○ Destination address, ACK number, SEQ number, TTL of packet, Source IP, Source port
	
	EX. What is the destination address of packet 63?
	
		Snort the log file to read again, add tack -n *packet*
		sudo snort -r snort.log.1724256760 -n 63
		
		Scroll up and look at last packet destination address
		216.239.59.99
	
	
Let's create IDSRules for FTP!

	Write a single rule to detect "all TCP port 21"  traffic in the given pcap.
	What is the number of detected packets?
	
		alert tcp any 21 -> any any (msg:"src:FTP found"; sid:100001; rev:1;)
		alert tcp any any -> any 21 (msg:"des:FTP found"; sid:100002; rev:1;)
		This rule will create an alert for each TCPpacket sent to port 21.
	
		Snort the file;
		Sudo snort -c local.rules -A full - l . -r .ftp
		
		Ls to view new files created
		
		Snort log file to read - 
		Sudo snort -r snort.log
	
	Investigate the log file.
	What is the FTP service name?
		
		Use the same code as  before but add tack -X 
		Sudo snort  -r snort.log  -X  -n 10
		
		Look through text for information from small sample
	
	
	
	Write a rule to detect failed FTP login attempts in the given pcap.
	What is the number of detected packets?
	
		Alert tcp any 21 -> any any (msg:"Detected Failed FTP Login"; content:"530 User"; sid: 100003; rev:1;) 
		
		Sudo snort -c local.rules -A full -l . -r .ftp
		
		
	Write a rule to detect FTP login attempts with a valid username but no password entered yet.
	
		Alert tcp any 21 -> any any (msg:"Detected Successful FTP Login"; content:"230 User"; sid: 100004; rev:1;) 
		
		Sudo snort -c local.rules -A full -l . -r .ftp
		
	Write a rule to detect FTP login attempts with a valid username but no password entered yet.
	
		Alert tcp any 21 -> any any (msg:"Detected FTP valid user name login attempt"; content:"331 Password"; sid: 100005; rev:1;) 
		
	
	Write a rule to detect FTP login attempts with the "Administrator" username but no password entered yet.
	
		Alert tcp any 21 -> any any (msg:"FTP admin login attempt, wrong password"; content:"331 Password"; fast_pattern; content:"Administrator"; sid: 100006; rev:1;) 
		
	
Let's create IDSRules for PNG files in the traffic!
	
	Write a rule to detect the PNG file in the given pcap.
	Investigate the logs and identify the software name embedded in the packet.
	
		alert tcp any any -> any any (msg:"PNG file Detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:100002; rev:1;)
	
	Investigate the logs and identify the software - Review a full sample
		
		sudo snort -r snort.log.1724270009 -X -n 10
		
	Write a rule to detect the GIF file in the given pcap.
	
		alert tcp any any -> any any (msg:"GIF file Detected"; content:"|47 49 46 38|"; sid:100003; rev:1;)
	
	Investigate the logs and identify the image format embedded in the packet.
	
		sudo snort -r snort.log.1724271670 -X -n 10
		

Let's create IDSRules for torrent metafiles in the traffic!
	
	alert tcp any any <> any any (msg:"Torrent MetaFile Detected"; content:"torrent"; sid:100001; rev:1;)
	
	Things we can find: name of application, MIME type of the torrent, hostname of the torrent
	


Using External Rules

Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

	alert tcp any any <> any any (msg:"\IPC$ Payload Detected"; content:”\IPC$”; sid:100001; rev:1;)
	
	”\IPC$” - this content needs to be changed into hex to work, 
	 5c 49 50 43 24 an input between | |
	
	
Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.
	
	
		alert tcp any any <> any any (msg:"Log4j detected-Byte size"; dsize:770<>855; sid:100001; rev:1;)

---

### Snort Challenge - Live Attacks
---
Scenario 1 | Brute-Force

	Run snort on sniffer mode
	
		Capture packets usings
		
		Sudo snort -X
		
		Parse through the Data
			08/22-14:00:33.645805 10.10.245.36:46490 -> 10.10.140.29:22
			SSH connection
	
	Config local.rules
	
		Etc/snort/rules/local.rules
		
		Creating a rule to block ip from ssh
		
			Alert tcp (10.10.245.36) any <> any any  (msg:"sus ip"; sid:10001; rev:1;)
			
			Run sudo snort -c local.rules -A full
			
	Looking at logs
	
		Var/log/snort
		Sudo snort -r log
		
		Confirm suspciousions we can edit the rule again to reject
		
		reject tcp (suspicious ip) any <> any any (msg: “reject suspicious ip”; sid: 1000002; rev: 1;
	
	
	
	
Scenario 2 | Reverse-Shell

	Run snort on sniffer mode
		
		Capture packets using - sudo snort -X
		
			08/22-14:27:10.786707 10.10.196.55:54116 -> 10.10.144.156:4444
			TCP TTL:64 TOS:0x0 ID:48797 IpLen:20 DgmLen:136 DF
			***AP*** Seq: 0xFEA595A9  Ack: 0x19D439EF  Win: 0x1EB  TcpLen: 32
			TCP Options (3) => NOP NOP TS: 2358141704 1980309403 
			0x0000: 02 15 8B 5C 4F EF 02 7C 9A 93 DF DD 08 00 45 00  ...\O..|......E.
			0x0010: 00 88 BE 9D 40 00 40 06 12 EB 0A 0A C4 37 0A 0A  ....@.@......7..
			0x0020: 90 9C D3 64 11 5C FE A5 95 A9 19 D4 39 EF 80 18  ...d.\......9...
			0x0030: 01 EB 69 62 00 00 01 01 08 0A 8C 8E 63 08 76 09  ..ib........c.v.
			0x0040: 1F 9B 0A 0A 1B 5D 30 3B 75 62 75 6E 74 75 40 69  .....]0;ubuntu@i
			0x0050: 70 2D 31 30 2D 31 30 2D 31 39 36 2D 35 35 3A 20  p-10-10-196-55: 
			0x0060: 7E 07 1B 5B 30 31 3B 33 32 6D 75 62 75 6E 74 75  ~..[01;32mubuntu
			0x0070: 40 69 70 2D 31 30 2D 31 30 2D 31 39 36 2D 35 35  @ip-10-10-196-55
			0x0080: 1B 5B 30 30 6D 3A 1B 5B 30 31 3B 33 34 6D 7E 1B  .[00m:.[01;34m~.
			0x0090: 5B 30 30 6D 24 20                                [00m$ 
			
			Suspicious packet captured; port 4444 used to backdoor in Metasploit
		
	Config local.rules
		
		Etc/snort/rules
			Create Rule to block sus ip and port going outbound
			
			Reject tcp any any <> 10.10.144.156 any (msg:"sus ip"; sid:100001; rev:1;)
			
			Reject tcp any any <> any 4444 (msg:" Backdoor port"; sid: 100002; rev:1;)
			
			
		



