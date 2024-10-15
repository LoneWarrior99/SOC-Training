# Wireshark: The Basics

Wireshark is an open-source, cross-platform network packet analyzer tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP).

### Here we will walk through the questions:

---

 ### Read the "capture file comments". What is the flag?
  
    - Reading the File properties will show us the comment.
    
  ![image](https://github.com/user-attachments/assets/e87d40f1-8308-4485-aa16-80706a4b9cb0)

  ![image](https://github.com/user-attachments/assets/920c6378-df0f-43c1-9645-efe6f744c4a1)

 --- 
 ### What is the total number of packets?

    - The file properties from the last question can answer this, but you can also find it at the bottom of the capture.

  ![image](https://github.com/user-attachments/assets/4b13133c-fe28-469b-9232-7b2159edf847)

  ![image](https://github.com/user-attachments/assets/6fe966b0-a22e-4f21-be57-5fce7f5fd032)

  ---
  ### What is the SHA256 hash value of the capture file?

    - This can also be found in the file properties from last question under File

  ![image](https://github.com/user-attachments/assets/6fa48077-b43a-4d8c-96c5-84e3ea40accd)

---
### View packet number 38. Which markup language is used under the HTTP protocol?

    - Go to packet 38 and look under details panel.

  ![image](https://github.com/user-attachments/assets/2703b682-c501-4ae1-a635-45eac1d79731)

---
### What is the arrival date of the packet? (Answer format: Month/Day/Year)

    - Under the same details panel open up Frame and you will find your answer.

  ![image](https://github.com/user-attachments/assets/1b407066-a3cf-4019-8153-94990503c895)


---
### What is the TTL value?

    - This is under Internet Protocol Version 4

  ![image](https://github.com/user-attachments/assets/2429e3b6-4749-40b8-b6b5-9d409b7a52ba)

---
### What is the TCP payload size?

    - Look under Transmiision Control Protocol

![image](https://github.com/user-attachments/assets/887e7e6f-d390-40e1-9349-92c1f810e9a5)

---
### What is the e-tag value?

    - Under Hypertext trasnfer Protocol 

  ![image](https://github.com/user-attachments/assets/36dbe449-ce48-44dc-8c06-431de20d9143)

---
### Search the "r4w" string in packet details. What is the name of artist 1?

    - We can go to edit and use find packet then search for the string "raw" to find our answer.

  ![image](https://github.com/user-attachments/assets/d8c4052d-ea9b-48b0-bbce-8b24b7f33acb)
  
  ![image](https://github.com/user-attachments/assets/63c3a09d-5a85-42d6-9510-abefd3e8f685)

  
---    
### Go to packet 12 and read the comments. What is the answer?

    - Use Go to packet and type 12, look into details panel under Packet Comments

  ![image](https://github.com/user-attachments/assets/fdf6ce88-e457-4219-91e4-27431f85fe2d)

  ![image](https://github.com/user-attachments/assets/5404650d-080d-4467-a07a-99bb0b951abc)

    - This is not the answer and we can't see all of it so we can look at the capture file properties and head down to packet comments to see what it says. 

  ![image](https://github.com/user-attachments/assets/6f862b2b-4562-4e1c-b677-ba0aec9810fd)

    - Follow the exact instructions and we can find the md5 hash

  ![image](https://github.com/user-attachments/assets/3dd9cab4-0129-428c-8b0c-b52be51fc0c8)


    
---    
### There is a ".txt" file inside the capture file. Find the file and read it; what is the alien's name?

    - So theres two ways we can see this, one would to be just to look for the .txt string and look through the packet under Line- Based text data: text.plain or we could export the http object and download the txt file and view the contents.
    
  ![image](https://github.com/user-attachments/assets/46341788-3011-41ec-bc06-8d9faa0307e6)


---    
###Look at the expert info section. What is the number of warnings?

    - We can click on this red dot on the bottome left to see exepert info and review count.

![image](https://github.com/user-attachments/assets/fdd03dcb-e9ca-42bb-8b30-f5bf7499308f)

![image](https://github.com/user-attachments/assets/62080872-265f-41c2-a437-7ed7f0553748)





## Wireshark: Packet Operations


## Wireshark: Traffic Analysis



