## Overview

### Lurking in the Dark

Without tripping any security defences of Quick Logistics LLC, the Boogeyman was able to compromise one of the employees and stayed in the dark, waiting for the right moment to continue the attack. Using this initial email access, the threat actors attempted to expand the impact by targeting the CEO, Evan Hutchinson. 

![image](https://github.com/user-attachments/assets/64b70e39-2e29-449f-88c1-1ab0eda8b9a1)

The email appeared questionable, but Evan still opened the attachment despite the scepticism. After opening the attached document and seeing that nothing happened, Evan reported the phishing email to the security team.

### Initial Investigation

Upon receiving the phishing email report, the security team investigated the workstation of the CEO. During this activity, the team discovered the email attachment in the downloads folder of the victim.
![image](https://github.com/user-attachments/assets/49481ca0-c839-4035-b22c-b1b663dda981)

In addition, the security team also observed a file inside the ISO payload, as shown in the image below.
![image](https://github.com/user-attachments/assets/70b2fd9a-b2c0-4e6a-859e-c65e4ac9d3ca)

Lastly, it was presumed by the security team that the incident occurred between August 29 and August 30, 2023.

Given the initial findings, you are tasked to analyse and assess the impact of the compromise.

We will be using elastic to answer all of these questions.

## Questions
### What is the PID of the process that executed the initial stage 1 payload?
Since we know the file downloaded, we can filter for it in the search bar and also include files with a html extension,"ProjectFinancialSumary_Q3.pdf" or ".html" After that we can view the fields, specifically "process.command_line" and view PID.
6392

### The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?
We will edit the search query just to the pdf (ProjectFinancialSumary_Q3.pdf). Looking through the command lines, I ended up finding the process.


### The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?
Just scrolling down and following the events we can find the next answer.


### The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?
Same as before if we look for something along the lines of powershell and schtask, we can find the name of the registered task.


### The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)
Clear the current filter and add filter to find event.code 3 to see network connections. Select fields dest.port/ip and we can see the connection.


### The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?
We will use the info we got earlier and filter for review.dat since it created a dll file. Looking throught the command lines we can find the .exe process.
fodhelper.exe


### Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?
Here we will filter for event code 1 for process creation and search for *github*. 


### After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)
Using the info we got from the last question, this time we will search for *mimi* and look through the commandlines again for this info.


### Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?
Following the events we can see the script used to enumerate the shares and the name.


### After getting the contents of the remote file, the attacker used the new credentials to move laterally. What is the new set of credentials discovered by the attacker? (format: username:password)
Right after the last question's input we can see that the new credentials on the next line.


### What is the hostname of the attacker's target machine for its lateral movement attempt?
Same line on the last question.


### Using the malicious command executed by the attacker from the first machine to move laterally, what is the parent process name of the malicious command executed on the second compromised machine?
Now we will move and filter to the host WKSTN-1327 and view the commands to find the .exe process.


### The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)
Looking ahead again we can find the command for mimikatz and the credentials.


### After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?
Switching the host to the DC machine we can see the dsync and the user.


### After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?
Move down a bit from the last question and we can see a nice url.

