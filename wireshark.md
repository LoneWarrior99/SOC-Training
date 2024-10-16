
Wireshark is an open-source, cross-platform network packet analyzer tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP).

This a walkthrough of THM's Wireshark Basic and Packet Operation. This covers how to use wireshark and how to do packet level searches.

---

# Wireshark: The Basics

## Tool Overview:

 ### Read the "capture file comments". What is the flag?
  
    - Reading the File properties will show us the comment.
    
  ![image](https://github.com/user-attachments/assets/e87d40f1-8308-4485-aa16-80706a4b9cb0)

  ![image](https://github.com/user-attachments/assets/920c6378-df0f-43c1-9645-efe6f744c4a1)


 ### What is the total number of packets?

    - The file properties from the last question can answer this, but you can also find it at the bottom of the capture.

  ![image](https://github.com/user-attachments/assets/4b13133c-fe28-469b-9232-7b2159edf847)

  ![image](https://github.com/user-attachments/assets/6fe966b0-a22e-4f21-be57-5fce7f5fd032)

  
  ### What is the SHA256 hash value of the capture file?

    - This can also be found in the file properties from last question under File

  ![image](https://github.com/user-attachments/assets/6fa48077-b43a-4d8c-96c5-84e3ea40accd)

---
## Packet Dissection:

 ### View packet number 38. Which markup language is used under the HTTP protocol?

    - Go to packet 38 and look under details panel.

  ![image](https://github.com/user-attachments/assets/2703b682-c501-4ae1-a635-45eac1d79731)


### What is the arrival date of the packet? (Answer format: Month/Day/Year)

    - Under the same details panel open up Frame and you will find your answer.

  ![image](https://github.com/user-attachments/assets/1b407066-a3cf-4019-8153-94990503c895)


### What is the TTL value?

    - This is under Internet Protocol Version 4

  ![image](https://github.com/user-attachments/assets/2429e3b6-4749-40b8-b6b5-9d409b7a52ba)

### What is the TCP payload size?

    - Look under Transmission Control Protocol

![image](https://github.com/user-attachments/assets/887e7e6f-d390-40e1-9349-92c1f810e9a5)


### What is the e-tag value?

    - Under Hypertext trasnfer Protocol 

  ![image](https://github.com/user-attachments/assets/36dbe449-ce48-44dc-8c06-431de20d9143)

---
## Packet Navigation:
 ### Search the "r4w" string in packet details. What is the name of artist 1?

    - We can go to edit and use find packet then search for the string "raw" to find our answer.

  ![image](https://github.com/user-attachments/assets/d8c4052d-ea9b-48b0-bbce-8b24b7f33acb)
  
  ![image](https://github.com/user-attachments/assets/63c3a09d-5a85-42d6-9510-abefd3e8f685)

  
    
### Go to packet 12 and read the comments. What is the answer?

    - Use Go to packet and type 12, look into details panel under Packet Comments

  ![image](https://github.com/user-attachments/assets/fdf6ce88-e457-4219-91e4-27431f85fe2d)

  ![image](https://github.com/user-attachments/assets/5404650d-080d-4467-a07a-99bb0b951abc)

    - This is not the answer and we can't see all of it so we can look at the capture file properties and head down to packet comments to see what it says. 

  ![image](https://github.com/user-attachments/assets/6f862b2b-4562-4e1c-b677-ba0aec9810fd)

    - Follow the exact instructions and we can find the md5 hash

  ![image](https://github.com/user-attachments/assets/3dd9cab4-0129-428c-8b0c-b52be51fc0c8)


    
    
### There is a ".txt" file inside the capture file. Find the file and read it; what is the alien's name?

    - So theres two ways we can see this, one would to be just to look for the .txt string and look through the packet under Line- Based text data: text.plain or we could export the http object and download the txt file and view the contents.
    
  ![image](https://github.com/user-attachments/assets/46341788-3011-41ec-bc06-8d9faa0307e6)


    
### Look at the expert info section. What is the number of warnings?

    - We can click on this red dot on the bottome left to see exepert info and review count.

![image](https://github.com/user-attachments/assets/fdd03dcb-e9ca-42bb-8b30-f5bf7499308f)

![image](https://github.com/user-attachments/assets/62080872-265f-41c2-a437-7ed7f0553748)

---
## Packet Filtering:
 ### Go to packet number 4. Right-click on the "Hypertext Transfer Protocol" and apply it as a filter. Now, look at the filter pane. What is the filter query?
 
      - Follow the instructions and we can find the answer pretty easily.

 ![image](https://github.com/user-attachments/assets/b8b64bed-9f0a-40a1-8367-8f65f0f64ff9)



### What is the number of displayed packets?

    - Check the bottom right "Displayed" for this info.

![image](https://github.com/user-attachments/assets/35dcf22d-3af4-4800-b9d5-77b9c32ed33c)



### Go to packet number 33790 and follow the stream. What is the total number of artists?

      - We will go to packet 33790 follow the http stream and look for artists to find the answer

![image](https://github.com/user-attachments/assets/00335c0a-8a0c-4cdc-8ec3-6628ae49fbe6)

![image](https://github.com/user-attachments/assets/5bc1777e-381b-49d4-9b5b-e8c81c84619c)



### What is the name of the second artist?
    
      - We can use the same image from the last question and answer this.

![image](https://github.com/user-attachments/assets/aa5929b5-d07e-4511-9c52-7687f412a4f0)





---
# Wireshark: Packet Operations

This room will cover the advanced features of the Wireshark by focusing on packet-level details with Wireshark statistics, filters, operators and functions. 

---

## Statistics | Summary:
### Investigate the resolved addresses. What is the IP address of the hostname starts with "bbc"?

      - For this we will head to the top and go to Statistics into Resolved Addresses. From there we can search for "bbc" and find the IP associated.

![image](https://github.com/user-attachments/assets/902c0057-d1bc-491b-a07c-91b920ad99b4)

      

### What is the number of IPv4 conversations?

      - This time from Statistics, we will go into conversations and we can see our answer right away.

![image](https://github.com/user-attachments/assets/54d1acc7-ce32-4103-8f17-2a9393aed63c)



### How many bytes (k) were transferred from the "Micro-St" MAC address?

      - Looking at Endpoints under Statistics can tell us this.

![image](https://github.com/user-attachments/assets/e7aa0cdc-f309-40ee-8ce8-7f89bcf6fcb6)



### What is the number of IP addresses linked with "Kansas City"?

      - Still under Endpoints we can look over to IPv4 and sort for Kansas City to show us. We can see 4 entries.

   ![image](https://github.com/user-attachments/assets/7aa51e1a-6fdb-4a87-b15e-8452460128a0)



### Which IP address is linked with "Blicnet" AS Organisation?

      - Under the same process/image we can find the answer sorting alphabetically for AS Organization.

![image](https://github.com/user-attachments/assets/f686b017-b218-4ca9-b118-44bb37f61e12)

---

## Statistics | Protocol Details:

### What is the most used IPv4 destination address?
     
      - Check under Statistics, IPv4, Destinations and Ports to find the answer. Sort under Count.

![image](https://github.com/user-attachments/assets/5371fac6-298a-4d2c-a8c5-d3e75359cb61)



### What is the max service request-response time of the DNS packets?

      - Go to Statistics, DNS, and look for Max Val request-response under Service Stats.

![image](https://github.com/user-attachments/assets/59a080a7-d0f0-490d-8a8e-3c7953a9d539)


### What is the number of HTTP Requests accomplished by "rad[.]msn[.]com?

      - Looking for requests so go to Statistics, HTTP, requests. We can look for the exact site and scroll over to find the count.

![image](https://github.com/user-attachments/assets/d36e1fa4-7215-4cdb-adee-e84d894be37d)

![image](https://github.com/user-attachments/assets/91318143-f7f7-49c2-af66-f027c72344d1)


---

## Packet Filtering | Protocol Filters:
 ### What is the number of IP packets?

    - Pretty easy just search for ip and look a below.
    
![image](https://github.com/user-attachments/assets/2d84fdae-c164-4f22-aa39-79344a3eaf8e)

![image](https://github.com/user-attachments/assets/046f4124-3339-4113-90d2-efdfa59a0c39)


### What is the number of packets with a "TTL value less than 10"?

    - Used a quick google search for the syntax, answer will be at the bottom.

![image](https://github.com/user-attachments/assets/ccd0bc6a-e796-4f6b-9489-fbf2ddc6f74c)

![image](https://github.com/user-attachments/assets/0b7a2cca-335c-417d-a0e9-f52a318585ec)



### What is the number of packets which uses "TCP port 4444"?

    - Syntax was in the reading just apply it here and it will show us the same way.
    
![image](https://github.com/user-attachments/assets/73b80754-6acc-4c92-b06f-3831b0bee09f)

![image](https://github.com/user-attachments/assets/a4b250d8-289d-4663-9c4f-3af57feb5584)



### What is the number of "HTTP GET" requests sent to port "80"?

    - Also gives us the syntax here but just combine with tcp.port and theres the answer.
    
![image](https://github.com/user-attachments/assets/54efa3b8-e718-4198-b348-8a46e6b93b39)

![image](https://github.com/user-attachments/assets/6eb2d6a4-b62b-40f5-a0ef-fcfe42de624b)


### What is the number of "type A DNS Queries"?

    - dns.qry.type == 1 shows us type A records and dns.flags.response == 1 shows us the responses. Combine these two for the answer.

![image](https://github.com/user-attachments/assets/091a3eca-2819-4be8-83f4-f9a4217d022c)

![image](https://github.com/user-attachments/assets/c6cb7396-4e9c-4135-819c-50445c7b5c13)

---

## Advanced Filtering:

### Find all Microsoft IIS servers. What is the number of packets that did not originate from "port 80"?

    - From the text we will use http.server contains "IIS" and tack on !(tcp.srcport ==80) to tell it not to show us anything from port 80.
    
![image](https://github.com/user-attachments/assets/85e52768-c741-458b-8acb-9df2563b1309)

![image](https://github.com/user-attachments/assets/d67f66a9-6863-4039-abe0-22749d5b6db7)


### Find all Microsoft IIS servers. What is the number of packets that have "version 7.5"?

    - Here we will continue to use the "http.server contains "IIS" and add on "http.server matches "7.5""
    
![image](https://github.com/user-attachments/assets/ef66cc46-1d50-4056-a845-d1ae92ced1f5)

![image](https://github.com/user-attachments/assets/8dd6de55-63e2-49f0-ab5a-88e875b868d5)


### What is the total number of packets that use ports 3333, 4444 or 9999?
   
    - The text was nice enough to give us the syntax here too.

![image](https://github.com/user-attachments/assets/627639a4-e429-4797-9aa9-38dea4ccd187)

![image](https://github.com/user-attachments/assets/38b58843-a068-4b2d-9c75-3b8558ee900f)


### What is the number of packets with "even TTL numbers"?

    - Used the hint here and the provided us with some nice directions for the syntax.

 ![image](https://github.com/user-attachments/assets/14b290ab-1342-4427-9a2e-0d32f7578d63)

![image](https://github.com/user-attachments/assets/99611a56-38f7-478d-95c2-ae5dd18899ff)


### Change the profile to "Checksum Control". What is the number of "Bad TCP Checksum" packets?

    - We will change the profile by goign into Edit > Configuration Profiles and selecting Checksum Control. From there we can filter for bad packets with the syntax: tcp.checksum.status == 0

![image](https://github.com/user-attachments/assets/5908f4fd-afb9-4b8b-882c-dd2c93bd143d)

![image](https://github.com/user-attachments/assets/edc6b51e-e52e-4427-ac65-d39f04f56ad8)


### Use the existing filtering button to filter the traffic. What is the number of displayed packets?

    - Click the bottom next to the filter to show our answer.

![image](https://github.com/user-attachments/assets/ff0c9dd1-caa0-430d-b532-2859ac4cba34)

![image](https://github.com/user-attachments/assets/fff832aa-c04e-4513-a63d-f64b5a189e89)




