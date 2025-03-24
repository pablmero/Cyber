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



