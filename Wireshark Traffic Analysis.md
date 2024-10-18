# Wireshark: Traffic Analysis

This room will cover key points and techniques of traffic analysis and detecting suspicious activities. 


## Nmap Scans

This section will cover the identification of the most common Nmap scan types including TCP connect scans, SYN scans, and UDP scans.

      Some Helpful Wireshark Filters
      - tcp.flags == 2 | Only SYN flag 
      - tcp.flags.syn == 1 | SYN Flag is set. The rest of the bits are not important.
      
      - tcp. flags == 16 | Only ACK flag
      - tcp.flags.ack == 1 | ACK Flag is set.
      
      - tcp.flags == 18 | Only SYN,ACK flags
      - (tcp.flags.syn == 1) and (tcp.flags.ack == 1) | SYN and ACK are set
      
      - tcp.flag == 4 | Only RST flag
      - tcp.flags.reset == 1 | RST flag is set
      
      - tcp.flags == 20 | Only RST, ACK flags
      - (tcp.flags.syn == 1) and (tcp.flags.ack == 1) | RST and ACK are set
      
      - tcp.flags == 1 | Only FIN flag
      - tcp.flags.fin == 1 | FIN flag is set

      TCP Connect Scan 
      - Relies on three-way handshake
      - Usually Conducted with nmap -sT
      - Used by non-privileged users
      - Usually has a windows size larger than 1024 byte

  ![image](https://github.com/user-attachments/assets/70ccfb6c-1502-4934-ac99-34661902bbeb)


      SYN Scans
      - Doesn't rely on three-way handshake
      - Usually conducted with nmap -sS
      - Used by Privileged users
      - Usually have a size lees than or equal to 1024 bytes
      
  ![image](https://github.com/user-attachments/assets/f1cfd7da-e140-4d98-b3cd-3f0d1a4040f9)


      UDP Scans
      - Doesn't require a handshake process
      - No prompt for open ports
      - ICMP error message for closed ports
      - Usually conducted wiht nmap -sU

![image](https://github.com/user-attachments/assets/c78dd0c4-6fd6-4bfc-b6d2-e3e0b2ddb10a)

We can differentiate the error by looking into the packet details panel and see the encapsulated data and the original data.


### What is the total number of the "TCP Connect" scans?

We can view the TCP connect scan patterns using this:

      tcp.flags.syn==1 && tcp.flags.ack==0 && tcpwindow_size > 1024
      
![image](https://github.com/user-attachments/assets/141b6c00-46e6-479c-8f13-5223dce6c65d)
![image](https://github.com/user-attachments/assets/83043a54-6582-4857-bbd2-13a599cec80b)
      

### Which scan type is used to scan the TCP port 80?

Lets view it by typing:

      tcp.port == 80

Now we can verify by looking at the info which reads, "(SYN), (SYN ACK), (ACK), (RST ACL)", which tells us that it is a TCP Connect Scan.

![image](https://github.com/user-attachments/assets/b4129774-d380-45e6-9992-3b7fbef7e892)


### How many "UDP close port" messages are there?

This filter will show us the UDP scan patterns:

      icmp.type==3 && icmp.code==3

![image](https://github.com/user-attachments/assets/c72e9fd6-87ef-45fe-89b5-75c3d5d2dbd0)
![image](https://github.com/user-attachments/assets/25e4e24d-2956-43dc-8d5b-c2c7ffa7ef75)


### Which UDP port in the 55-70 port range is open?  

We can filter for this range using this:

      udp.port in {55..70}
Then look at the info for our answer.
![image](https://github.com/user-attachments/assets/c0d9a7cd-e1ce-4052-8ad3-09db02c0072a)

      
## ARP Poisoning / Spoofing (MITM)

This section discusses Address Resolution Protocol Poisoning which is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The aim is to manipulate the "IP to MAC address table" and sniff the traffic of the target host.

It is easy to detect when knowing the ARP protocol workflow and since the attack is static. 

            Arp Analysis
            - Works on local network
            - Enables the communication between MAC addresses
            - Not secure protocol
            - Not routable protocol
            - No authentication function
            - Common patterns are request and response, announcement and gratuitious packets.


Let's review some legitimate and suspicious ARP Packets: 

Wireshark Filter: 

![image](https://github.com/user-attachments/assets/fb25b561-1a06-4909-9e45-65806b9bd437)

ARP Request:

![image](https://github.com/user-attachments/assets/480f8f75-fbcd-42d0-88d8-5ef3d6f90024)

![image](https://github.com/user-attachments/assets/82c93bb8-a45f-4e32-9f2d-16a9b5f8fd0c)


ARP Reply:

![image](https://github.com/user-attachments/assets/273f3ca3-39df-4d18-9ce7-9631f1abc485)

![image](https://github.com/user-attachments/assets/99a34dc7-ffdc-4a5b-93cf-75b725ffff08)

Suspicious Event:
Two different ARP resonponses for an IP address, thankfully Wireshark's expert info tab warns for this. Further identification is needed to figure out which has the malcicious packet. Here is a possible IP spoofing case:

![image](https://github.com/user-attachments/assets/1663c6f6-ab33-4491-b51b-f9bdcc03cc7a)

Another anomaly is a flood of ARP request which could be a malcious activity, scan, or netwwork problems. We can also see that one of the mac addresses crafted multiple requests:

![image](https://github.com/user-attachments/assets/9fbbc704-1a30-4d2e-b8ba-3a6e0602debe)

Finally we can see an obvious anomaly that all the HTTP packets are being sent to this suspicous MAC address. This is enough evidence to say there is a MITM attack.

![image](https://github.com/user-attachments/assets/73216582-d18d-4527-82f1-cac8496db64b)




Lets dive into the exercise:

### What is the number of ARP requests crafted by the attacker?

I intially used arp.opcode == 1 to see the traffic. The mac address ending in b4 is sending all the packets so we will add that to the filter for just that mac address.

      arp.opcode == 1 && arp.src.hw_mac == 00:0c:29:e2:18:b4

![image](https://github.com/user-attachments/assets/b93764aa-469a-4aa9-b112-fb6cf1a8061f)

![image](https://github.com/user-attachments/assets/7d2a567c-6819-4a77-9501-856de92fe993)


### What is the number of HTTP packets received by the attacker?

Let's change the filter to show only http and the suspicous mac address

      (http ) && (eth.dst == 00:0c:29:e2:18:b4)

![image](https://github.com/user-attachments/assets/fd592d9e-a8c8-4fa2-b1da-d29cb008e5c5)

![image](https://github.com/user-attachments/assets/005ada9d-7086-4318-b7df-6db9b48234f8)


### What is the number of sniffed username&password entries?

We can view filter for the site first then look at the POST requests. From there I saw a login and just added a filter for something I saw in common and counted 6 of them manually.

![image](https://github.com/user-attachments/assets/108f802b-d6df-4642-a97a-fb4310c4d6cf)


### What is the password of the "Client986"?

We can just search through each packet and look for this info.

![image](https://github.com/user-attachments/assets/0f8b1f74-f42e-4a8c-8d76-49df0fe3c6ff)


### What is the comment provided by the "Client354"?

Same thing, just look through the packets with the current filter.

![image](https://github.com/user-attachments/assets/858e116a-f755-4c17-a52b-040ed86cda9e)


## Identifying Hosts: DHCP, NetBIOS and Kerberos

      Protocols that can be used in Host and User identification:
      - DHCP Traffic
      - NetBIOS Traffic
      - Kerberos Traffic

DHCP Analysis:

![image](https://github.com/user-attachments/assets/c464fb74-dd9c-432a-a65e-b80de238b043)

NetBIOS Analysis:

![image](https://github.com/user-attachments/assets/ada50b54-5cd1-43a6-af41-a82c19f17d22)


Kerberos Analysis:

![image](https://github.com/user-attachments/assets/87f1af81-0ae1-4aae-aa55-22ff6d242b7d)

### What is the MAC address of the host "Galaxy A30"?

I filtered for "Galaxy" and manually look through the packets and found the Client MAC address in the DHCP request.

![image](https://github.com/user-attachments/assets/d239e05a-f606-4491-a68b-02d2d113f0fd)


### How many NetBIOS registration requests does the "LIVALJM" workstation have?

Used the filter they gave us:

      ((nbns.name contains "LIVALJM") ) && (nbns.flags.opcode == 5)

![image](https://github.com/user-attachments/assets/e9e2bd48-15b6-4f37-b1d7-199bbb60b2d1)

![image](https://github.com/user-attachments/assets/bbfadc27-5b64-4f2b-a544-a4b0aeba44a3)


### Which host requested the IP address "172.16.13.85"?

Found this filter and inputted the requested ip address.
      
      dhcp.option.requested_ip_address == 172.16.13.85
            
![image](https://github.com/user-attachments/assets/e3b5e8be-b666-459b-8b3b-05f6cb117b09)


### What is the IP address of the user "u5"? (Enter the address in defanged format.)

Found it using this filter:

kerberos.CNameString contains "u5"

![image](https://github.com/user-attachments/assets/aa619fa6-4eb2-4c99-8910-2dfb063d8eca)


### What is the hostname of the available host in the Kerberos packets?

The wireshark analysis text from earlier gave us a hint that values that end with "$" are hostnames so we can apply this filter here.

        kerberos.CNameString and (kerberos.CNameString contains "$" )

![image](https://github.com/user-attachments/assets/7845a5ec-d07a-429c-9fb2-36c3f3899b59)


## Tunnelling Traffic: ICMP and DNS 
        
Also known as port forwarding, transferring data/resources this way is very secure and in alot of enterprise networks. Attackers can also use tunneling to bypass security perimeters using the standard and trusted protocols used everyday traffic like ICMP and DNS which is why it is crucial to spot anomalies.

ICMP Analysis:
      
      - Appears or starts after a malware execution or vulnerability explotiation
      - Sometimes used for DoS attacks
      - Also used in data exfiltration and C2 tunneling activities; check TCP, HTTP, or SSH data
      - Indicators of tunneling: Large volume of ICMP traffic, Anomalous packet sizes
      - Adversaries could create custom packets that match the regular packet size but most enterprise networks block custom packets or require admin privileges.

![image](https://github.com/user-attachments/assets/d9d0807c-3500-4654-ae1e-a8caf032e892)

DNS Analysis:

      - Appears or starts after a malware execution or vulnerability explotiation
      - Adversary creates or has a domain address and configures it as a C2 channel
      - Malware or commands send DNS queries to the C2 server which are longer than default DNS queries and crafted for subdomain addresses.
      - Subdomains addresses are not actual addresses; they are encoded commands
            - "encoded-commands.maliciousdomain.com"
      
![image](https://github.com/user-attachments/assets/4eb12ed3-3df8-44b3-9ec5-c04859ef283d)

### Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

We will create a filter to check for C2 tunnelling activities:

      (icmp contains "tcp" or icmp contains "http" or icmp contains "ssh") and (data.len > 64) 

Reviewing each packet we see some keywords like diffie-hellman, sha256, ssh, aes128, which tells us SSH is being used.

![image](https://github.com/user-attachments/assets/388352ff-231d-41a5-b7f2-bba199190956)


### Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)

Really had to dig for this one, used the filter they gave us and manually inspected each packet and found data exfil site in the packet data.

![image](https://github.com/user-attachments/assets/3a0fd854-1a25-4b16-9bb5-325a951e5509)


## Cleartext Protocol Analysis: FTP

FTP Analysis
 - Designed for file transfer with little security
 - Beware of MITM attacks, Credential stealing and unauthorized access, phishing, malware planting, data exfiltration

![image](https://github.com/user-attachments/assets/98f803e9-afdd-4447-bb73-569c3973ffe2)

### How many incorrect login attempts are there?

This filter shows this:

      ftp.response.code == 530
      
![image](https://github.com/user-attachments/assets/4253ab46-8916-40bd-b20f-bbaa8528fa56)

![image](https://github.com/user-attachments/assets/bd677936-60bb-43d0-8776-e82550f270b7)


### What is the size of the file accessed by the "ftp" account?

First I checked to see if there was a user login which return one entry. Then I followed the tcp stream and found the file accessed which indicated the SIZE to 39424.

![image](https://github.com/user-attachments/assets/5ce7255b-31fb-4339-b220-435d7b41a984)

![image](https://github.com/user-attachments/assets/45f75d2f-e8fd-4e08-81fb-a508fa1b186e)


### The adversary uploaded a document to the FTP server. What is the filename?

Following the stream from the last question we can see the upload.

![image](https://github.com/user-attachments/assets/c1269200-f714-479f-852a-d7181097acf9)


### The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?

Again, follow the stream to the end and we can find this.

![image](https://github.com/user-attachments/assets/8cfaef09-20dc-4a7e-9e90-66df0bc2e817)


## Cleartext Protocol Analysis: HTTP

 HTTP Analysis:
      - Cleartext-based, request-response protocol
      - Attacks: Phishing pages, web attacks, data exfiltration, C2
      
![image](https://github.com/user-attachments/assets/5784934c-3b58-44b2-9bf3-37ef57377b2b)

---
      User Agent Analysis:
      - Great resource for spotting anomalies in HTTP traffic
      - Still replicable so don't depend on it
      - Never whitelist a user agent
      - If unsure, web search for defualt and normal user agent info
      
![image](https://github.com/user-attachments/assets/179516c5-0b6f-4ba8-8056-b10d507e3902)

---

      Log4j Analysis:

![image](https://github.com/user-attachments/assets/888a688c-efc4-4f59-a7cf-b25abdcab15e)


### Investigate the user agents. What is the number of anomalous  "user-agent" types?

This required manually inspection, after filtering for http.user_agent, I found 6 entries.

![image](https://github.com/user-attachments/assets/35ef053d-48f6-436e-9d24-eea54487e80a)
![image](https://github.com/user-attachments/assets/c7721fd8-614f-4083-bbd5-e938cc409526)
![image](https://github.com/user-attachments/assets/f6f7e80c-98a2-4b58-ae88-10684106a154)

![image](https://github.com/user-attachments/assets/5d8aed58-c04a-4f6e-95c1-5c43600ead97)

![image](https://github.com/user-attachments/assets/8c0ed41d-6f6b-4aef-a202-d50d0a857bc5)
![image](https://github.com/user-attachments/assets/b5c1478a-fa89-424d-b543-a4710b15ed16)


### What is the packet number with a subtle spelling difference in the user agent field?

We found this earlier, Mozlila: 52

![image](https://github.com/user-attachments/assets/f34b71f7-b0ad-4d08-a664-6bd27793cf39)


### Locate the "Log4j" attack starting phase. What is the packet number?

We know that attacks wstart with a POST request so we can filter for that.

![image](https://github.com/user-attachments/assets/a7732f97-da6f-4008-b771-d0c107801190)


### Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (Enter the address in defanged format and exclude "{}".)

So we will take what we found from the last question and decode it in CyberChef:

![image](https://github.com/user-attachments/assets/481e003e-6d41-4b26-9c1e-1ed3c15bc62e)


## Encrypted Protocol Analysis: Decrypting HTTPS

      - Enhanced security against spoofing, sniffing, and intercepting
      - Uses TLS protocol to encrypt communications
      - Impossible to decrypt without having key pairs

![image](https://github.com/user-attachments/assets/ae8f04cb-cb10-4da4-9c5e-b2415f232909)

TLS Protocol also has a handshake process, Client and Server Hello. Here are helpful filters to spot involved IP addresses:

      - Client Hello: (http.request or tls.handshake.type == 1) and !(ssdp) 
      - Server Hello: (http.request or tls.handshake.type == 2) and !(ssdp)  


"An encryption key log file is a text file that contains unique key pairs to decrypt the encrypted traffic session. These key pairs are automatically created (per session) when a connection is established with an SSL/TLS-enabled webpage. As these processes are all accomplished in the browser, you need to configure your system and use a suitable browser (Chrome and Firefox support this) to save these values as a key log file. To do this, you will need to set up an environment variable and create the SSLKEYLOGFILE, and the browser will dump the keys to this file as you browse the web. SSL/TLS key pairs are created per session at the connection time, so it is important to dump the keys during the traffic capture. Otherwise, it is not possible to create/generate a suitable key log file to decrypt captured traffic"

We will add the key log files now with "Edit > Preferences > Protocols > TLS" and browse for the provided file.

Decompressed header info and HTTP2 packet details are available after decrypting the traffic. Depending on the packet details, you can also have the following data formats:

    Frame
    Decrypted TLS
    Decompressed Header
    Reassembled TCP
    Reassembled SSL

### What is the frame number of the "Client Hello" message sent to "accounts.google.com"?

Use this to view Client Hello:

      (http.request or tls.handshake.type == 1) and !(ssdp)
            
Search for accounts.google in the bytes panel.

![image](https://github.com/user-attachments/assets/2a23961f-07b3-4fa8-8844-fd383394a135)


### Decrypt the traffic with the "KeysLogFile.txt" file. What is the number of HTTP2 packets?

Aleady added the key log file, just filter for http2 for answer.

![image](https://github.com/user-attachments/assets/c9c4d561-0ff8-487d-bdc7-17c939b7fe6f)


### Go to Frame 322. What is the authority header of the HTTP2 packet? (Enter the address in defanged format.)

Look through the panel, HTTP2 > Stream > Header > authority

![image](https://github.com/user-attachments/assets/be42d732-0fee-4489-9f51-43a2c344c137)


### Investigate the decrypted packets and find the flag! What is the flag?

They hint said "you can export objects after decryping the traffic". Went to export httb object, then saved it onto the desktop. Opened the file to reveal the answer. This was very cool.

![image](https://github.com/user-attachments/assets/d55018ec-53ae-44e0-8439-7c32e817a757)

![image](https://github.com/user-attachments/assets/fe715296-0730-4b03-80d3-ddebbc170761)


## BONUS

Cleartext Credentials:

"Some Wireshark dissectors (FTP, HTTP, IMAP, pop and SMTP) are programmed to extract cleartext passwords from the capture file. You can view detected credentials using the "Tools --> Credentials" menu. This feature works only after specific versions of Wireshark (v3.1 and later). Since the feature works only with particular protocols, it is suggested to have manual checks and not entirely rely on this feature to decide if there is a cleartext credential in the traffic"

Actionable Results: 

"You can create firewall rules by using the "Tools --> Firewall ACL Rules" menu. Once you use this feature, it will open a new window and provide a combination of rules (IP, port and MAC address-based) for different purposes. Note that these rules are generated for implementation on an outside firewall interface."

Currently, Wireshark can create rules for:

    Netfilter (iptables)
    Cisco IOS (standard/extended)
    IP Filter (ipfilter)
    IPFirewall (ipfw)
    Packet filter (pf)
    Windows Firewall (netsh new/old format)
