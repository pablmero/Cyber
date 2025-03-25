# Attaktive Directory

In this post we are going to be solving and explainig the TryHackme machine [Attacktive Directory](https://tryhackme.com/room/attacktivedirectory).
This machine focuses on Active Directory use. Windows active Directory is a service that allows applications to use, find and 
administrate the harware and software resources of the domain.

We will learn the vulnerabilities one may find in a business active directory environment how to use step by step the hacking 
tools used to enumerate and exploit those vulnerabilities.

## Deployment

To access the Virtual Machine, you will need to first connect to THM's network using OpenVPN. You can follow a mini walkthrough of 
getting connected described in the TASK 1 (Attacktive Directory TASK 1). Or follow this simple [tutorial](https://www.youtube.com/watch?v=2-cAHdM57sM)

Download the configuration file, exeute it ```sudo openvpn $(configuration file name)```. 

![imagen](https://github.com/user-attachments/assets/a13bc455-010a-49d8-8967-61ae3029807c)


If you execute it and obtain 'Inicialization Sequence Complete', you can now refresh the OpenVPN Access Details to see that you are connected,
Using ```ifconfig``` will confirm that the ip (tun0 interface) is the same as the one shown in the OpenVPN Access Details.
Once connected we can check our connectivity to the machine deployed in THM. ```ping -c 1 10.10.191.137```

![imagen](https://github.com/user-attachments/assets/2d55f321-cc92-4310-a4e5-487551b72776)

*Curiosity: TTL (Time To Live) is 127. This a trick for knowing if it is a Linux or Windows machine. In this case is Windows, but 
if it was around 60, it would be a Linux machine.

Following the THM TASK 2 recommendations we will install Impacket, Bloodhound and neo4j

    Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level
    programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. 
    Packets can be constructed from scratch, as well as parsed from raw data, and the object-oriented API makes it simple to 
    work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the 
    context of this library.

    BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory 
    environment. Attackers can use BloodHound to easily identify highly complex attack paths that would otherwise be 
    impossible to quickly identify. Defenders can use BloodHound to identify and eliminate those same attack paths. 
    Neo4j is a database for bloodhound API. A Neo4j graph database stores data as nodes, relationships, and properties instead 
    of in tables or documents. This means you can organize your data in a similar way as when sketching ideas on a whiteboard.


## Enumeration

Once connected lets check if there are any ports open. Nmap is a scanning tool. As defined in the THM TASK 3, ```nmap``` can detect what ports are open on a device, what services are running, and even detect what operating system is running. It's important to note that not all services may be deteted correctly and not enumerated to it's fullest potential. Despite nmap being an overly complex utility, it cannot enumerate everything. Therefore after an initial nmap scan we'll be using other utilities to help us enumerate the services running on the device.

```nmap -p- --open --min-rate 5000 -sS -sC -sV -vvv -n -Pn 172.17.0.2 -oG scanfile```

- -p- : Scan all ports
- --open: Chech just the open ports
- --min-rate 5000: Send packets faster (faster scanning)
- -sS: Sync Scan. Fast and silent scan.
- -sC: Script scanning. (For services running in the open ports)
- -sV: Version of the service runnning in the port.
- -vvv: Increase verbosity (more information)
- -n: No DNS resolution (faster scanning)
- -Pn: Ignores if the ip is active or not
- Export result to a file:
   -oG: Exports the result in a grepable format (to extract more easily the data with tools such as grep, awk)
   -oN: Export the result to the designated file.

![imagen](https://github.com/user-attachments/assets/b1cf16cc-e2d1-437f-957e-f030447f5f68)

We discovered many open ports (this is only part of the information shown by scan, specifically this info was shown thanks to -vvv which allow us to see the progress of nmap).
Some important ports among the open are:
- Port 80

      Ports 80, 443, 8080, and 8443 Vulnerabilities (HTTP and HTTPS)
        
        Anyone who has visited a web page has used the HTTP or HTTPS protocols in their web browser. As mentioned, web ports are commonly targeted by attackers for many types of attacks, including:
    
        Cross-site scripting. Attackers inject malicious scripts into web pages and applications to steal cookies, tokens, or data.
        SQL injections. Attackers insert malicious SQL code into input fields to manipulate a database.
        Cross-site request forgers. An attacker exploits the trust between a user’s web browser and a web application to trick the user into performing actions on a website without their knowledge or consent.
        DDoS attacks

- Port 445

        SMB 445/TCP is a Microsoft Windows file sharing protocol that can expose networks to unauthorized access and malicious exploits. Cybercriminals can leverage vulnerabilities in this port to inject malware, ransomware, or carry out Denial of Service (DoS) attacks.

Let's check the all the info reported by nmap.
First, as we previously pointed out, we can check port 80 in the web browser. For now, thanks to nmap, we know the version and the web server used: Microsoft IIS httpd 10.0 --> Apache version 10.0

![imagen](https://github.com/user-attachments/assets/91f53b14-2f7b-4b59-83a2-6bd4bead395c)

In port 389, we find something very interesting, a domain name. We can also find the same domain name in ports 3268 and 3389. In port 3389 we find even more information.

![imagen](https://github.com/user-attachments/assets/b1f408bf-e5ec-4b4b-8027-6d2a166df17c)

### AD enumerations: Domain Name and hosts file
Why is a domain name so important? First we need to undestand what OU (Organizational Units) are. OU is a container within a Microsoft Windows Active Directory (AD) domain that can hold users, groups and computers. 
An [Active Directory domain](https://www.techtarget.com/searchwindowsserver/definition/Active-Directory-domain-AD-domain) (AD domain) is a collection of objects within a Microsoft Active Directory network. An object can be a single user or a group, or it can be a hardware component, such as a computer or printer. Each domain holds a database containing object identity information.

AD is the foundation of most modern Windows-based network management. It's part of the Windows Server family of operating systems (OSes). Conceptually, AD is often visualized as a classic telephone directory where users can look up anyone with a telephone and know their location and the number at which to reach them.

The domain name is usually formed by the domain name plus the TLD. Top-level domain (TLD) or a domain extension is the final part of a web address after the domain name. For example, in spookysec.local, .local is the TLD or in google.com, the TLD is .com.

So let's recap. From this scan we discover the Domain Name of the machine as well as the the full AD domain. For further enumeration we need to add domain name and add it to /etc/hosts.
A hosts file which is used by operating systems to map a connection between an IP address and domain names before going to domain name servers. This file is a simple text file with the mapping of IPs and domain names.
The hosts file (whether you're on a PC, Mac, or Linux) is used as a kind of hard override for DNS/host names. That is, instead of doing a normal lookup of a particular host/domain name's IP address, your computer will use the IP that you have defined in the hosts file.
```echo 10.10.193.34 spookysec.local >> /etc/hosts``` to map the ip of the machine to the domain name. For example, if we execute a ping command to the spookysec.local domain, it will be the same as executing a ping to the ip 10.10...

https://serverfault.com/questions/760109/dns-security-com-ad-domains-what-are-the-dangers-to-my-ad-domain-if-someone
https://www.ionos.es/digitalguide/servidores/configuracion/archivo-hosts/

### AD enumeration: SMB -> crackmapexec and enum4linux

Let's continue exploring the results of nmap. As we discussed earlier, the port 445 corresponding to SMB was open, so let's check it. We are going to use two different tools for SMB enumeration:

- crackmapexec:

        Very powerful tool for post-exploitation tasks, especially in Active Directory environments. The first versions focused on SMB service enumeration, but nowadays it supports other common protocols in this type of         environment such as Kerberos, LDAP, MS-SQL, WinRM, among others.

    ```crackmapexec smb 10.10....``` SMB service enumeration
  
    
- enum4linux: (Most common one, hint for an answer of TASK 2)

        Enum4linux is a tool for enumerating information from Windows and Samba systems. Allows information to be retrieved via the SMB protocol.
        Typically, there are SMB shares on a server that can be connected to and used to view or transfer files.
        SMB can often be a great starting point for an attacker looking to discover sensitive information. Enu4mlinux is a great tool to get SMB information.
        
    ```enum4linux -a 10.10...```
      - -a: Do all simple enumeration (check ```enum4linux -h``` to list all the flags executed)

     In this case we didn´t find anything insteresting but in other cases we might find users and passwords.

  ### Kerberos enumeration: Kerbrute
  


