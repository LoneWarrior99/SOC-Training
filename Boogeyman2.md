## Overview

### The Boogeyman is back!
Maxine, a Human Resource Specialist working for Quick Logistics LLC, received an application from one of the open positions in the company. Unbeknownst to her, the attached resume was malicious and compromised her workstation.

![image](https://github.com/user-attachments/assets/fa59052a-9691-404b-9ee2-3ab380dd6e21)

The security team was able to flag some suspicious commands executed on the workstation of Maxine, which prompted the investigation. Given this, you are tasked to analyse and assess the impact of the compromise.


### What email was used to send the phishing email?
westaylor23@outlook[.]com

### What is the email of the victim employee?
maxine[.]beck@quicklogisticsorg[.]onmicrosoft[.]com

### What is the name of the attached malicious document?
Resume_WesleyTaylor.doc

### What is the MD5 hash of the malicious attachment?
md5sum <file> outputs:
52c4384a0b9e248b95804352ebec6c5b


### What URL is used to download the stage 2 payload based on the document's macro?
Used the tool olevba for this info.

### What is the name of the process that executed the newly downloaded stage 2 payload?
Olevba showed this

### What is the full file path of the malicious stage 2 payload?
Olevba still works here

### What is the PID of the process that executed the stage 2 payload?
Back to using vol, syntax for this is vol -f <file> windows.pstree
windows .pstree shows this

### What is the parent PID of the process that executed the stage 2 payload?
Windows.pstree shows this

### What URL is used to download the malicious binary executed by the stage 2 payload?
We can manually search the raw using strings and grepping for boogeymanisback (retrieved from early question)

### What is the PID of the malicious process used to establish the C2 connection?
Windows.netscan shows connections

### What is the full file path of the malicious process used to establish the C2 connection?
Can use PID we found and filter for it
Windows.dlllist –pid <>

### What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)
Windows.netscan shows connections

### What is the full file path of the malicious email attachment based on the memory dump?
Windows.filescan can show us this, grep for file (Resume)

### The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?
We can use strings on the raw and grep for schtasks
