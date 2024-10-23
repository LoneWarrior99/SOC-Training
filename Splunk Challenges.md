# Splunk Challenges
This is an investigation of anomalies using Splunk. Written is write up of two rooms from tryhackme with the purpose to learn and develop skills against compromised hosts and events using Splunk. The first scenario will be following "Investigating with Splunk" and the second scenario will be following the room, "Benign".


## Scenario 1 - Investigating with Splunk
"SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies. "


### How many events were collected and Ingested in the index main?
Just filter for index=main,

![image](https://github.com/user-attachments/assets/de8d0c51-563c-4bea-8b3e-e59716cb5ba8)

- 12,256

### On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

Lets look for newly created users using windows event id = 4720

![image](https://github.com/user-attachments/assets/0fe48900-74f6-40ae-bbf8-b3420f055724)

![image](https://github.com/user-attachments/assets/c102a49e-4cb2-4454-8088-546d6b8d5628)

- A1berto

### On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?
Filtering for the new user and registry event,

    index=main A1berto registryevent

Found this CreateKey

![image](https://github.com/user-attachments/assets/4ab10f64-80e9-41a3-bcea-d33e1732da34)

-HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto 


### Examine the logs and identify the user that the adversary was trying to impersonate.
We can tell by looking at the name that the 1 is supposed to be an L for Alberto. We can confirm by looking at our user list.

![image](https://github.com/user-attachments/assets/38cb257b-59a1-4eea-ac9b-647af9963303)

- Cybertees\Alberto

### What is the command used to add a backdoor user from a remote computer?
Filtered for just A1berto and looked at CommandLine Field. WMIC is typically used for remote execution.

- "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"

![image](https://github.com/user-attachments/assets/da6cfaf6-292e-4b57-bbab-29865b27e1bc)


### How many times was the login attempt from the backdoor user observed during the investigation?
Used Windows event 4624 to see if there was any logins from A1berto

![image](https://github.com/user-attachments/assets/02732325-dbd5-4e25-af2c-75888d8b826d)


### What is the name of the infected host on which suspicious Powershell commands were executed?
We saw this earlier looking for the remote cmd and can filter for it.

![image](https://github.com/user-attachments/assets/60ff1b06-2adb-409b-9d4e-d1d160083a0f)

- james.browne
  
### PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?
Filtered for eventid 4103 for powershell execution. AccountName only shows records for James, our compromised host.

![image](https://github.com/user-attachments/assets/8714c603-2030-4d1f-93ef-e5eb249f52f1)

- 79 events


### An encoded Powershell script from the infected host initiated a web request. What is the full URL?
We saw this when filtering for event id 4103,

![image](https://github.com/user-attachments/assets/54e7fa3f-0297-40cf-9fde-5a27997063ee)

Used CyberChef to decode Base64 and remove null bytes to read this:

![image](https://github.com/user-attachments/assets/46c72785-197e-4ac8-b5db-bc7968ec2cfe)

Decoded the string within it,

![image](https://github.com/user-attachments/assets/e8ec8800-cda9-498b-a020-3827a8371230)

![image](https://github.com/user-attachments/assets/94ef352e-7f11-4789-b9c9-eac062186b0d)

- http ://10[.]10[.]10[.]5/news[.]php



## Scenario 2 - Benign
"One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index win_eventlogs for further investigation."

About the Network Information:

The network is divided into three logical segments. It will help in the investigation.

IT Department

    James
    Moin
    Katrina

HR department

    Haroon
    Chris
    Diana

Marketing department

    Bell
    Amelia
    Deepak


### How many logs are ingested from the month of March, 2022?
Adjust the time for March 2022,

![image](https://github.com/user-attachments/assets/f9eaf67f-df1e-443c-8326-d3353ad18b34)

- 13,959 Events

### Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

Looking at the username field there is 11 entries but only 10 show. We can filter this to show all 11.

    index=win_eventlogs | top limit=11 UserName

  ![image](https://github.com/user-attachments/assets/432d6843-5ea0-4b36-a501-984628975428)
  
We can easily tell which the imposter account is and who they are trying to impersonate. 

- Amel1a

### Which user from the HR department was observed to be running scheduled tasks?

Add schtasks to the filter and lets look at UserName field to see.

![image](https://github.com/user-attachments/assets/714cc2cd-67c9-4f48-b6c9-cb16beda8c4c)

- Chris.fort is a part of HR and is running schtasks



### Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

Lets check the rare values from cmd with our HR staff. 

![image](https://github.com/user-attachments/assets/083c4130-9820-4d66-8817-b9c0893c7960)

View the event and we can see who did it.

![image](https://github.com/user-attachments/assets/486e80c8-6084-4f8f-8fb8-47bef0412956)

- haroon

### To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

We can see it in the beginning of the cmd.

![image](https://github.com/user-attachments/assets/393a612e-c3d5-428f-b114-097b8d400ffa)

- certutil.exe


### What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

Look for EventTime:

![image](https://github.com/user-attachments/assets/c757aa9a-e219-4af7-bcfd-c8ebbda19c28)

2022-03-04

### Which third-party site was accessed to download the malicious payload?

Again, view the cmd line and we can catch it near the end.

![image](https://github.com/user-attachments/assets/31dd053e-8b76-463c-a840-07b4fee197d0)

- controlc.com


### What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?
The name is at the very end of cmd line.

![image](https://github.com/user-attachments/assets/62ebde78-638f-423e-bf22-58337cdd3a2f)

- benign.exe

### The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?
Go to the site to see the file.

![image](https://github.com/user-attachments/assets/08460d34-7882-4b36-ba0a-2cf121d747e8)

- THM{KJ&*H^B0}

### What is the URL that the infected host connected to?
Found this earlier when viewing the cmd.

- https://controlc.com/e4d11035


## Closing Notes

This was a great challenge and a really fun way to learn Splunk more. 
