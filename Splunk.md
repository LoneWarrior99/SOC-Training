# Splunk
This is a write up over THM's Splunk modules. The main objective is to understand and learn how to use Splunk in the real scenarios.

There is three parts to this write up including, "Incident Handling with Splunk", "Investigating with Splunk", and "Benign".


## Incident Handling with Splunk

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

### Scenario
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

      

### Reconnaissance Phase

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

![image](https://github.com/user-attachments/assets/99fc84a4-ebd7-490d-bee5-482543b405dd)


#### What is the CMS our web server is using?

We can find the content management system with http.url which shows us it in the value, joomla.

![image](https://github.com/user-attachments/assets/7a0c74aa-7e36-42f9-afd1-90b5cdef64df)



#### What is the web scanner, the attacker used to perform the scanning attempts?

Look at the user agent field and we can find a popular scanner at the bottom, acunetix.

![image](https://github.com/user-attachments/assets/c41141e8-eab0-469d-a565-116933ab8584)


#### What is the IP address of the server imreallynotbatman.com?
    
Our web server is being scanned so we can look at the destination ip field, 192.168.250.70.

![image](https://github.com/user-attachments/assets/4b565667-dc33-4f6f-ad9e-c11712cb0c2d)






