# OWASP Juice Shop Walkthrough

## Objective
This web hacking lab project aims to identify and exploit the common web application vulnerabilites. The primary focus was to cover the following topics: 
Injection, Broken Authentication, Sensitive Data Exposure, Broken Access Control, Cross-Site Scripting XSS

### Skills Learned
- Advanced understanding of web application vulnerabilities and practical application.
- Proficiency in analyzing and interpreting vulnerabilites.
- Ability to generate and recognize attack vectors and patterns.
- Enhanced knowledge of web protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used
- Burp Suite Community Edition for capturing and modifying data
- Foxy proxy to forward network traffic to Burp

## Steps
### Exploring the website

Looking around the website we can find reviews on products from users:

![image](https://github.com/user-attachments/assets/b8d0e790-f8f1-4f55-bb52-3a2a78482d38)

*Ref 1: Product Review (This shows us an Admin email!)*

![image](https://github.com/user-attachments/assets/c88de241-e430-4f13-a22a-27e0ca57fe19)

*Ref 2: Product Review 2 (User references the replicator from Star Trek. This gives us some insight on the user's hobbies/interest.)*



We can also look at the parameters used for searching:

![image](https://github.com/user-attachments/assets/bd44250c-d994-4361-9c6f-fb2fad8ec562)

![image](https://github.com/user-attachments/assets/f440e625-4cc2-489f-b623-be0fc58dc3c1)

![image](https://github.com/user-attachments/assets/c0e5f1ce-d7d2-440d-976f-672f6f99081c)

*Ref 2: Search Parameters* (returns /#/search?q= )


### Simulating an Injection:

Using Foxy Proxy to connec to our Burp Suite Tool, we will turn Intercept mode on to see the data that is being sent to the server.

![image](https://github.com/user-attachments/assets/5156f704-1854-4ae7-b7ea-3642ecc9f304)

*Ref 3: Burp Suite's Intercepted Data on Login*

Here we can see the input for the email and password prompt. We can change the username's "test" input to "' or 1=1--" and forward it to the server. Because this SQL statement will return true since 1=1 is always true, it will tell the server that the email is valid and log us into user id 0, which coincidentally is the admin account.

![image](https://github.com/user-attachments/assets/b5ac510b-05c6-4c22-b250-251b7bfdf17c)

*Ref 4: SQL query using 1=1--*

![image](https://github.com/user-attachments/assets/124bb0eb-7131-43a7-9e29-7708f89f69d7)

*Ref 5: Successful admin login*

We can also use an already existing valid email, "bender@juice-sh.op", and add '-- to the input to bypass the login system.  

![image](https://github.com/user-attachments/assets/a8040667-d596-4201-8509-3a1cc4e40ee0)

*Ref 6: SQL query adding '--*

![image](https://github.com/user-attachments/assets/0a06a613-cd33-4970-9b77-41bbac89097b)

*Ref 7: Sucessful user login*

### Broken Authentication:

Since we still don't know the admin's password, we will brute force it. Capturing a login request again, we will send it Intruder instead to configure a payload. We will replace the "test" with Burp's implementaion of quotations.

 ![image](https://github.com/user-attachments/assets/fe44694e-2ab0-4869-ae8a-649ec00d7ce5)
 
 *Ref 8: Intruder function*

 For the payload we will use a common credential wordlist and load it into the settings and start the attack.
 
![image](https://github.com/user-attachments/assets/d3f167fe-d67d-48f0-8b33-e63dfad9bf3d)

We found a successful response code 200, now we know the admin login.

![image](https://github.com/user-attachments/assets/3669ba7e-56fb-4fbf-b7cf-2566ba96ad0e)

*Ref 9: Brute forced password*

### Exploiting the Reset Password Mechanism

Knowing some valid accounts, we can see how the forgot password option was setup. This particular site uses security questions set up by the user. Depending on the question, we can easily find user information online from google or other social media websites.

![image](https://github.com/user-attachments/assets/4f0acdb7-688a-462b-b72b-72b0a0edcf13)

*Ref 10: Jim's Security Question*

We found an inkling earlier that Jim had something to do with Star Trek. Looking at the characters in the show, a simple google search shows that there is a brother for the character named Samuel. Inputting that allowed us to change the password!

![image](https://github.com/user-attachments/assets/44f9ef24-38f1-4ab3-a1f1-453fccb787f9)

*Ref 11: Successfully changing password*

### Sensitive Data Exposure

Looking at the links on the website, we found that one of them actually points to a ftp directory.

![image](https://github.com/user-attachments/assets/fa411ad1-f987-4253-ab2c-2e5c7023c930)

*Ref 12: Link Reveal*

![image](https://github.com/user-attachments/assets/948d05d7-cfd5-497b-b49e-4aebd30aac8b)

*Ref 13: ftp directory*

Using this directory, we will attempted to download a backup file name package.json.bak. 

![image](https://github.com/user-attachments/assets/b0bb849d-8f15-4b03-9eb1-9abaf6357ae0)

*Ref 14: Error 403*

In order to bypass this error, we will use a character bypass called "Poison Null Byte" which looks like this: %00. Encoding this into a url format will now look %2500. Finally, adding .md at the end will bypass the 403 error.

![image](https://github.com/user-attachments/assets/4a9cffbe-8e68-436a-8fb2-a6701b768665)

*Ref 15: Bypassing Error 403*

### Broken Access Control

Let's see if we can find the administration page. Looking through debugger on firefox, we will look for the javascript file main-es2015.js and search for the term "admin". We see that the there is a path to administration. It doesn't seeme to work unless we are already logged into an admin account.

![image](https://github.com/user-attachments/assets/661ef2e9-0166-487d-89da-ca0538d699f2)

*Ref 16: Sensitive Information*

Logged in as admin, we can also view other users' basket granted they have one by capturing the request. Once captured, we can see a request: GET /rest/basket/1 HTTP/1.1. We can simply change the "1" after basket to a "2" which will take us to users ID 2's basket.

![image](https://github.com/user-attachments/assets/3a80d837-0922-4f1f-8cff-135d71b67188)

*Ref 17: GET /rest/basket/1 HTTP/1.1 request*

### Cross-site Scripting XSS

Let's perform a DOM XSS. In the search bar, if we input, "<iframe src="javascript:alert(`xss`)">", will trigger the alert. Without correct input sanitation, we are able to perofrm a XSS attack against the search bar.

![image](https://github.com/user-attachments/assets/5f50b220-14f7-4919-9612-1caea4c2ccf1)

*Ref 18: DOM XSS*

Next we will perform a persistent XSS. This javascript will run when the server loads the page containing it. This will occur when the server does not sanitise the user data when it is uploaded to a page. Going through privacy and security we cna see the last login IP.

![image](https://github.com/user-attachments/assets/49805ad0-c283-43cc-aa4e-d901bc92f66d)

*Ref 19: Last login IP*

We will logout and use burp so that it logs a new IP. Make sure to capture the logout request then head to the headers tab to add a new header to forward the request to the swerver.

![image](https://github.com/user-attachments/assets/67d79e1a-a1c6-4a05-b0da-f13cca2d9490)

*Ref 20: Adding header*

Once we sign back into the admin account and navigate to the Last Login IP page, we will see the XSS alert.

![image](https://github.com/user-attachments/assets/bbb6bdf8-bea3-4782-a18d-c796f16eb076)

*Ref 21: Alert from persistant XSS*


Finally we will perform a reflected XSS. This is javascript that will run on the client side of the web application and can happen when the server doesn't sanitise search data. Navigating to the delivery page we can see that there is an id paired with the order.

![image](https://github.com/user-attachments/assets/18006872-9ae5-42ed-8400-6243eb9a65b2)

*Ref 22: id pair*

Putting the iframe XSS (<iframe src="javascript:alert(`xss`)">),  after the = will result in recieving an alert. The server will have a lookup table or database for each tracking ID and because the 'id' parameter was not sanitised before it was sent to the server, we were able to perfrom an XSS attack.

![image](https://github.com/user-attachments/assets/11b5f1a4-d6e6-4b92-a5d1-6f51a8045f98)

*Ref 23: Reflected XSS*
















