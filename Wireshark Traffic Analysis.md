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


ARP Reply:


### What is the number of ARP requests crafted by the attacker?


### What is the number of HTTP packets received by the attacker?


### What is the number of sniffed username&password entries?


### What is the password of the "Client986"?


### What is the comment provided by the "Client354"?















