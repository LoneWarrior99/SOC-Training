# Incident Handling with Splunk
This is a write up over THM's Splunk module. The main objective is to learn how to handle incidents with splunk.


There are four distinct phases in the Incident Response Life Cycle.

Preparation:
- Readiness of an attack
- Documenting requirements
- Defining Policies
- Incorporating security controls, SIEM / IDS, etc
- Training Staff

Detection and Analysis:
- Getting alerts from the security controls
- Investigating the alert to find the root cause
- Hunting for unknown threats within the organization

Containment, Eradication, and Recovery:
- Actions needed to prevent the incident from spreading and securing the network
- Isolating the  infected host
- Clearing the network from the infection taces
- Gaining control back from the attack

Post-Incident Activity / Leesons Learnt:
- Identifying the loopholes in the organizations security posture
- Improving security to prevent attack from happening again
- Identify weakness, add detection rule, train stuff

## Scenario
In this exercise an attacker has defaced an organization's website. Using Splunk as our SIEM solution, our job as a security analyst is to investigate this cyber attack and map the attacker's activitieis into all 7 of the Cyber Kill Chain Phases.
Logs are ingested from webserver/firewall/Suricata/Sysmon etc.

Note that it is not necessary to follow the sequeunce of phases while investigating.
- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command and Control
- Actions on Objectives

"A Big corporate organization Wayne Enterprises has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website http://www.imreallynotbatman.com. Their website is now showing the trademark of the attackers with the message YOUR SITE HAS BEEN DEFACED  as shown below."

![dcc528c218e8dda78504f55f58188575](https://github.com/user-attachments/assets/d88a8f09-83dc-4b42-bca3-ca1dc2836e8e)

All event logs are present in index=botsv1

      Helpful log sources

      wineventlog - contains windows event logs
      winRegistry - contains the logs related to registry creation / modification / deletion etc
      XmlWinEvenLog - contains sysmon event logs. Very important log source from an investigation point of view
      fortifate_utm - contains Fortinent Firewall logs
      iis - contains IIS web server logs
      Nessus:scan - contains the results from the nessus vulnerability scanner
      Suricata - contains the details of the alerts from suricata ids. Shows which alert was triggered and cause. Very important.
      stream:http - contains the network flow related to http traffic
      stream: DNS - contains the network flow related to DNS traffic
      stream:icmp - contains the network flow related to icmp traffic

      

## Reconnaissance Phase

Start our analysis by searching for any reconnaissance attempt against our web server (imreallnotbatman.com).

      Search Query: index=botsv1 imreallynotbatman.com

First task is to identify the possible source IP address. We will use http as our sourcetype.

![image](https://github.com/user-attachments/assets/cbcaa985-9457-4a85-952c-37b5ab5679b0)

40.80.148.42 looks interesting, we can view the fields such as User-Agent, Post request, URIs, etc., to view the traffic more. We can see some traces of it being probed 

![image](https://github.com/user-attachments/assets/377f9859-e7b2-4cc3-a99f-a366350db4a6)

![image](https://github.com/user-attachments/assets/325e5536-da0c-47ab-b022-0881256cdf29)

Lets validate if thats the right IP scanning, by filtering deeper into the suricata logs.

Looking at the alert filter shows us what we need to know.

![image](https://github.com/user-attachments/assets/ac6ca4b5-4b55-4998-bf48-92751f18dc06)

Questions:

#### One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?

Using the filter we had earlier we can search for alert and look for this value.

![image](https://github.com/user-attachments/assets/ba836bc5-b835-4c33-8dbb-37da16d29d20)



#### What is the CMS our web server is using?

We can find the content management system with http.url which shows us it in the value, joomla.

![image](https://github.com/user-attachments/assets/7a0c74aa-7e36-42f9-afd1-90b5cdef64df)



#### What is the web scanner, the attacker used to perform the scanning attempts?

Look at the user agent field and we can find a popular scanner at the bottom, acunetix.

![image](https://github.com/user-attachments/assets/c41141e8-eab0-469d-a565-116933ab8584)


#### What is the IP address of the server imreallynotbatman.com?
    
Our web server is being scanned so we can look at the destination ip field, 192.168.250.70.

![image](https://github.com/user-attachments/assets/4b565667-dc33-4f6f-ad9e-c11712cb0c2d)


## Exploitation Phase

Look for any exploitation attempt to our web server and see if it was successful.

Lets see the number of counts by each source IP against our server using this query:

      index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests

![image](https://github.com/user-attachments/assets/bfbc74f0-98c7-4936-b8e4-a812aeffa5bb)

This is also where we can create other forms of visualization,

![image](https://github.com/user-attachments/assets/2619145e-cb38-48d1-ae96-7f83e2935f0a)

Lets look at all inbound traffic towards our web server IP:

      index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"

![image](https://github.com/user-attachments/assets/b8a70434-595b-4f97-a0b7-08ecb7721368)

We can observe that there are 2 remote IPs and 1 local IP that originated the HTTP traffic.

Another interesting field we can look at is http_method which shows a lot of POST request.

![image](https://github.com/user-attachments/assets/6dcf93fc-4958-4b46-809f-edbddb28f298)


Filtering for the POST requests, we can see what IPs are sending it.

![image](https://github.com/user-attachments/assets/4f540aa0-a64d-454a-a46c-c5fa5cef0d87)

Other interesting fields we can look at other than src_ip is form_data, http_user_agent, and uri.

One of the uri shows us the admin login page let's filter for that and look deeper.

      index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70"  uri="/joomla/administrator/index.php"

form_data shows 100+ entries, we can suspect that the attacker used multiple credentials and dive deeper to confirm.

![image](https://github.com/user-attachments/assets/84bda886-b14a-41bb-b64b-5421272315c2)

Lets add this filter to look for important fields:

      table _time uri src_ip dest_ip form_data

![image](https://github.com/user-attachments/assets/6084d94d-54dd-40e9-b204-e22f9693c8a2)

Looking at the results we can see logins with the username, "admin", and several passwords attempts from the IP 23.22.63.114. The time between events also tells us a tool was most likely used to brute force this account.

Lets use Regex to extract all the password values found:

      index="botsv1" sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd*
      | rex field=form_data "passwd=(?<creds>\w+)" 
      | table src_ip uri creds


![image](https://github.com/user-attachments/assets/0628856f-4fe2-4812-9b36-943c8c30cf64)

If we go back we can look at the fields http_user_agent and see that python was used automate the brute force attack.

![image](https://github.com/user-attachments/assets/30edd644-ff87-4ad6-ac95-8d85bc134e5f)

Adding http_user_agent to our filter we can see the continuous brute force attempts from 23.22.63.114  and 1 password attempt from 40.80.148.42 with the creds "batman".


![image](https://github.com/user-attachments/assets/002509a6-5ba9-41f3-ae35-97fa1654bdca)



#### What was the URI which got multiple brute force attempts?
We can see this with our last images or like in the uri field.

- /joomla/administrator/index.php

#### Against which username was the brute force attempt made?
Looking at the form data will show us.

- admin      

#### What was the correct password for admin access to the content management system running imreallynotbatman.com?
40.80.148.42 showed 1 attempt with a different http_user_agent.

- batman


#### How many unique passwords were attempted in the brute force attempt?
The statistics can show us this, assuming python cracked the password and the attacker logged on in with it, we can subtract 1 from the total to give us the answer

- 412

  ![image](https://github.com/user-attachments/assets/6e0a782c-db09-4968-b87d-77a288cd6f60)
 

#### What IP address is likely attempting a brute force password attack against imreallynotbatman.com?
We caught this looking multiple brute force attempt.

- 23.22.63.114


#### After finding the correct password, which IP did the attacker use to log in to the admin panel?
Of the two IP addresses, only one of them had a password attempt that did not come from using python. We can assume they found the password and logged in.

- 40.80.148.42


## Installation Phase

Know that we know what IP and password the attacker used, we can assume they have successfully exploited the security of the system. He will try to install a backdoor or an application for persistence or to gain more control of the system.

Lets look for any .exe traffic coming into our server.

            index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe

![image](https://github.com/user-attachments/assets/308a94fb-c644-4878-b0ee-6b19737abaff)


We can see that the .exe came from the same IP.

![image](https://github.com/user-attachments/assets/bceffa9f-52cb-4eb8-9e84-5fc306b29469)


Lets see if this file was executed by filtering for it.

![image](https://github.com/user-attachments/assets/6c2afbf2-c24a-4cac-9c03-496cabee4d34)

We found some traces, lets leverage sysmon and look for EventCode=1 for evidence of execution.

![image](https://github.com/user-attachments/assets/35b1aff8-e56e-4ccc-85b9-46d05afe3bd8)

Looking at command line we can see it was in fact executed.



#### Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?
Let's add the commandline with the .exe to the filter and then look inside the event.

![image](https://github.com/user-attachments/assets/09c36346-cadc-44a2-aec9-a8d2e7847026)

- MD5=AAE3F5A29935E6ABCC2C2754D12A9AF0

#### Looking at the logs, which user executed the program 3791.exe on the server?
We can keep the current filter and look at the user field.

![image](https://github.com/user-attachments/assets/66d9af69-eb6f-4390-81d3-bd8f2a0f09a6)

- IUSR

#### Search hash on the virustotal. What other name is associated with this file 3791.exe?

![image](https://github.com/user-attachments/assets/4f3b6348-504c-4bd5-bce9-4d180125af9d)

![image](https://github.com/user-attachments/assets/f89a12dd-0690-490b-ab99-46a0b262a261)

- ab.exe

## Action on Objectives
Since our site was successfully attacked, we should see what ended up on the site that caused defacement.

Lets figure out the traffic flow that and look through the suricata logs.

      Search Query:index=botsv1 src=192.168.250.70 sourcetype=suricata

![image](https://github.com/user-attachments/assets/6bf0fb16-3c0c-4d93-b0ed-793e5c4b2ce8)

Web servers typically do not originate traffic since the browser or client would be the source and the server would be the destination.

Lets look into this traffic an observe this abnormalitiy.

![image](https://github.com/user-attachments/assets/272a9d5a-b073-486f-893f-764ace8b9fdf)

The second IP shows two .php files and .jpeg file. Lets look where this jpeg came from and adjust the filter.

![image](https://github.com/user-attachments/assets/e28405d3-8d2f-47b3-ba68-a4a3204f5cdb)

Looks like the jpeg was downloaded from the attacker's host.

#### What is the name of the file that defaced the imreallynotbatman.com website ?
We found this earlier,
- poisonivy-is-coming-for-you-batman.jpeg


#### Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

Filtering for this we can lookout for SQL in the attack field.

![image](https://github.com/user-attachments/assets/d6916c3a-d52a-4bae-8341-f38a6c278ae2)

- HTTP.URI.SQL.Injection


## Command and Control Phase

"The attacker uploaded the file to the server before defacing it. While doing so, the attacker used a Dynamic DNS to resolve a malicious IP. Our objective would be to find the IP that the attacker decided the DNS.

To investigate the communication to and from the adversary's IP addresses, we will be examining the network-centric log sources mentioned above. We will first pick fortigate_utm to review the firewall logs and then move on to the other log sources."

Lets adjust the filter to fortigate and look for the jpeg.

![image](https://github.com/user-attachments/assets/7d70a2d2-0f86-4930-bfec-00cc5dad0138)

![image](https://github.com/user-attachments/assets/4a8c48eb-c683-4b45-b580-494f26a56387)

We got the IP and even the FQDN.

- 192.168.250.70

#### This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

Our last image showed this.
- prankglassinebracket.jumpingcrab.com

## Weaponization Phase
In this phase attackers would
- Create malware or malicious documents to gain intial access or evade detection
- Establish domains similar to the target domain to trick users
- Create C2 server for post-exploitation communication or activity

We found some ip addresses and domains so lets try looking into OSINT sites to gather more info.

Lets use Robtex, a threat intel site, to search for the domain and IP:

![image](https://github.com/user-attachments/assets/75bb7e99-d5c0-4f33-9d5e-a849798240b9)

![image](https://github.com/user-attachments/assets/893583c6-b996-426a-8596-47e3b5c8bb1a)

![image](https://github.com/user-attachments/assets/c1230fab-6ed0-4866-8232-d981b44ab279)

Lets also use VirusTotal:

![image](https://github.com/user-attachments/assets/0be38e62-0c62-4471-978d-b682f3caab5c)

In the domains poisonivy looks relevant lets look.

![image](https://github.com/user-attachments/assets/45a74db5-c438-4da4-8d2a-06d2e4b407a0)


We can also look at whois for more info:



#### What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

From our robtex site:

![image](https://github.com/user-attachments/assets/bb03b557-52dd-42ad-a898-95573fb3eaab)

- 23.22.63.114


#### Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

Hint tell us to use otx.alienvault:

![image](https://github.com/user-attachments/assets/ba8c24dc-4d14-4e7c-bc9a-372595a839c1)

- lillian.rose @po1s0nvy.com


## Delivery Phase

"Attackers create malware and infect devices to gain initial access or evade defenses and find ways to deliver it through different means. We have identified various IP addresses, domains and Email addresses associated with this adversary. Our task for this lesson would be to use the information we have about the adversary and use various Threat Hunting platforms and OSINT sites to find any malware linked with the adversary.

Threat Intel report suggested that this adversary group Poison lvy appears to have a secondary attack vector in case the initial compromise fails. Our objective would be to understand more about the attacker and their methodology and correlate the information found in the logs with various threat Intel sources."

OSINT sites

    Virustotal
    ThreatMiner
    Hybrid-Analysis

I enjoy using Virustotal so lets dig for some information:

![image](https://github.com/user-attachments/assets/7f471934-f567-4eda-b2de-fc13662c8a48)

Looking at this exe we can see that our IP address is under the contacted relations as well.

![image](https://github.com/user-attachments/assets/f13f8d01-1184-4bfb-a16b-ef11ab2745aa)




#### What is the HASH of the Malware associated with the APT group?
Assuming this screensaver is the malware from our last image.

![image](https://github.com/user-attachments/assets/03fef1b6-d5ed-43ca-b144-168a5b4af4dd)

-  c99131e0169171935c5ac32615ed6261 

#### What is the name of the Malware associated with the Poison Ivy Infrastructure?

Again analysis tells us that it should be,

- MirandaTateScreensaver.scr.exe












