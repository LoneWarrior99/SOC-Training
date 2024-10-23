# Investigating with Splunk
This is an investigation of an anomaly using Splunk. 


## Scenario
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
