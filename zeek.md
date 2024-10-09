This was a writeup tryhackme's zeek modules.

The official description; "Zeek (formerly Bro) is the world's leading platform for network security monitoring. Flexible, open-source, and powered by defenders." "Zeek is a passive, open-source network traffic analyser. Many operators use Zeek as a network security monitor (NSM) to support suspicious or malicious activity investigations. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting."

---

An alert triggered: "Anomalous DNS Activity".
The case was assigned to you. Inspect the PCAPand retrieve the artefacts to confirm this alert is a true positive. 


	Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address?

		zeek -C -r dns-tunneling.pcap
		catdns.log | zeek-cut qtype_name | sort| uniq-c
	
		
		
		Answer: AAAA - 320
		
		
	Investigate the conn.log file. What is the longest connection duration?
	
		Cat conn.log | zeek-cut duration | sort-r | head-n 1
		
		
		
		
	Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?
	
		Cat dns.log | zeek-cut query |rev | cut-d '.'-f 1-2 | rev | sort|uniq| wc-l
		

			
		
	There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the conn.log file. What is the IP address of the source host?
	
	
		catconn.log | zeek-cut id.orig_h | sort| uniq-c
		

An alert triggered: "Phishing Attempt".
The case was assigned to you. Inspect the PCAPand retrieve the artefacts to confirm this alert is a true positive. 


	Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.
	
		zeek -Cr phishing.pcap
		catconn.log | zeek-cut id.orig_h | sort| uniq-c
		
		
	Investigate the http.log file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.
	
		cathttp.log | zeek-cut uri host
	

	Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?
	
		Use Script provided and grab md5 hash value.
		zeek -Cr phishing.pcap hash-demo.zeek

    Search for fields:
		catfiles.log | zeek-cut mime_type md5
				
		
	Investigate the extracted malicious .exe file. What is the given file name in Virustotal?
	
		Look at the md5 value then go to VirusTotal.
	
	Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.
	
		VT>Behavior>DNS Resolutions. Cyberchef can defang.
	
	Investigate the http.log file. What is the request name of the downloaded malicious .exe file?
	
		cat http.log | grep "exe"
	
	
	
An alert triggered: "Log4J Exploitation Attempt".
The case was assigned to you. Inspect the PCAPand retrieve the artefacts to confirm this alert is a true positive. 
	
	
	Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?
	
		zeek -C -r log4shell.pcapng detection-log4j.zeek
		cat signatures.log | zeek-cut note | uniq -c
		
	
	Investigate the http.log file. Which tool is used for scanning?
	
		cat http.log | zeek-cut user_agent | sort | uniq
	
	
	Investigate the http.log file. What is the extension of the exploit file?
	
		cathttp.log | zeek-cut uri| sort| uniq
			
	Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
	
		catlog4j.log | zeek-cut value | head-n20
		Decode base64 to find answer
		
		
		
		
		
		
	
		
	
	
	
	
	
		
	
	
		
	
	
	
	
	
	
	
	

		
	
		
		
	
	
