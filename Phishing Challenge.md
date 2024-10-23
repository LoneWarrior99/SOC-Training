# Phishing Analysis
This is a write up of THM's Phishing modules specifically, "The Greenholt Phish" and "Snapped Phish-ing Line", which will be split up into Scenario 1 and 2 respectively. 
The purpose of this write up is to show learned skills to probe malicious emails and URLs. It is important to analyze and defend against phishing attempts as they are so prevelant in the real world. 

## Scenario 1 - "The Greenholt Phish"
"A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation".

Investigate the email sample to determine if it is legitimate.

Let's get started by opening up the eml file in thunderbird to observe it.

### What is the Transfer Reference Number listed in the email's Subject?

![image](https://github.com/user-attachments/assets/c8f5e102-ea41-4f85-ba9d-cf085d79bb35)

- 09674321

### Who is the email from?

![image](https://github.com/user-attachments/assets/3b9bb6b5-0890-4100-8383-b6408aac5792)

- Mr. James Jackson

### What is his email address?

![image](https://github.com/user-attachments/assets/3b9bb6b5-0890-4100-8383-b6408aac5792)

- info@mutawamarine.com

### What email address will receive a reply to this email? 

![image](https://github.com/user-attachments/assets/2de7a38c-960f-4146-8dc9-3f2d93a10c6e)

- info.mutawamarine@mail.com

### What is the Originating IP?
Let open the .eml file with mousepad to find this.

![image](https://github.com/user-attachments/assets/bff2d4aa-111e-46c5-a889-c74e81e4130f)

- 192.119.71.157

### Who is the owner of the Originating IP? (Do not include the "." in your answer.)
Lets use the Whois tool and search for the IP we found.

![image](https://github.com/user-attachments/assets/e3021b53-fe8b-412d-bb31-71b575f67cdb)

- Hostwinds LLC

### What is the SPF record for the Return-Path domain?
Let's use my favorite tool mxtoolbox and search for the domain.

![image](https://github.com/user-attachments/assets/638f5f65-762c-4e92-9e89-1c4a68c16b5c)

-v=spf1 include:spf.protection.outlook.com -all

### What is the DMARC record for the Return-Path domain?
Search for DMARC on mxtoolbox:

![image](https://github.com/user-attachments/assets/4e8b63f2-cfd5-416e-8228-25ec61685b1b)

- v=DMARC1; p=quarantine; fo=1

### What is the name of the attachment?
Going back to thunderbird lets look at the attachment:

![image](https://github.com/user-attachments/assets/3de1aa50-af29-40d2-8591-9ae28d557db4)

-SWT_#09674321____PDF__.CAB

### What is the SHA256 hash of the file attachment?
Let's download the attachment onto our desktop then use terminal to find the hash;

![image](https://github.com/user-attachments/assets/380a94ee-ddb6-46fa-9054-abce677a4b1d)

-2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f

### What is the attachments file size? (Don't forget to add "KB" to your answer, NUM KB)
Lets look up the hash on VirusTotal check it out.

![image](https://github.com/user-attachments/assets/02bb04ab-8142-4bdb-8ae2-996154f60207)

- 400.26 KB


### What is the actual file extension of the attachment?
With VirusTotal, lets look into the details and find out.

![image](https://github.com/user-attachments/assets/1a1625e7-ed80-4dc5-957e-70d31ff94254)

- File Type : RAR


## Scenario 2 - "Snapped Phish-ing Line"


"An Ordinary Midsummer Day...

As an IT department personnel of SwiftSpend Financial, one of your responsibilities is to support your fellow employees with their technical concerns. While everything seemed ordinary and mundane, this gradually changed when several employees from various departments started reporting an unusual email they had received. Unfortunately, some had already submitted their credentials and could no longer log in".

You now proceeded to investigate what is going on by:

    Analysing the email samples provided by your colleagues.
    Analysing the phishing URL(s) by browsing it using Firefox.
    Retrieving the phishing kit used by the adversary.
    Using CTI-related tooling to gather more information about the adversary.
    Analysing the phishing kit to gather more information about the adversary.


Looks like we have five emails to look from. Let's use thunderbird to look at each one and answer the questions below.

![image](https://github.com/user-attachments/assets/40d0ec53-60f9-48fa-9338-cb4eb7ec960b)


### Who is the individual who received an email attachment containing a PDF?

![image](https://github.com/user-attachments/assets/6eb007ee-1ee5-4614-af67-cff730cd6026)

- William McClean 

### What email address was used by the adversary to send the phishing emails?

![image](https://github.com/user-attachments/assets/a1a2af0a-80ec-4c61-9175-5a865fd3c4eb)

- Accounts.payable@groupmarketingonline .icu

### What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)
Downloaded the html file and opened it up with the text editor to view redirect.

![image](https://github.com/user-attachments/assets/07e24368-c700-4d74-b050-c02c0e608123)

- hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error


### What is the URL to the .zip archive of the phishing kit? (defanged format)
Looking at the redirect URL we can go to it and look for a zip archive.

![image](https://github.com/user-attachments/assets/954f513f-4d18-48f4-931b-d8793a6537a8)

- hxxp[://]kennaroads[.]buzz/data/Update365[.]zip

### What is the SHA256 hash of the phishing kit archive?
Download the zip file and lets use terminal to find the hash.

![image](https://github.com/user-attachments/assets/a0ddb032-686c-4f9a-bb4a-8d970ab5056c)

- ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686


### When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

Lets use VirusTotal and the hash to find this info.

![image](https://github.com/user-attachments/assets/f5f3ae69-42c1-4472-9931-dae11b893cf9)

- 2020-04-08 21:55:50 UTC 



### When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)
WhoIS lookup will show this:

![image](https://github.com/user-attachments/assets/ee5dafe2-a190-438b-a8f3-06c9b2ec2560)

- 2020-06-25


### What was the email address of the user who submitted their password twice?
Lets go to the site, looks like they have a log.txt.

![image](https://github.com/user-attachments/assets/6ce0366e-52cf-4654-b36a-e3a1ea95e16e)

- michael.ascot@swiftspend.finance


### What was the email address used by the adversary to collect compromised credentials?
Let's open the zip file we downloaded and look for some clues to where these credentials are being sent to.

![image](https://github.com/user-attachments/assets/76e96124-e3fd-4801-9f72-ce37b01b5e3e)

![image](https://github.com/user-attachments/assets/75be5fea-913c-496e-b8b9-a8097eb8b92e)

Looked around for scripts and php files and found this within the validation directory.

- m3npat@yandex.com

### The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?
Was looking for a script and opened this file. At the bottom it shows us who its sending it to.

![image](https://github.com/user-attachments/assets/10af2677-57cc-4f69-8d69-df7a1709dbdf)

-jamestanner2299@gmail.com


### What is the hidden flag?

The provided hint said that it was downloadable from the directory. So I added flag.txt to each directory until I found it.

![image](https://github.com/user-attachments/assets/efbce251-2668-49e4-83fc-a5fa91d4d6ac)

Cyberchef to decode of course base64, looks backwards so add reverse.

![image](https://github.com/user-attachments/assets/64d1f4cf-174a-48d6-9bdf-601b2ba1e96c)

- THM{pL4y_w1Th_tH3_URL}

## Closing Notes
Examining emails is a great way to learn. Phishing emails are very prevalent in our world and it is important to know what to do and what tools we can use. 
















