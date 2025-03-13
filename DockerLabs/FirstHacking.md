# [FirstHacking](https://dockerlabs.es/)

## Deployment

We deploy the machine: ```bash auto_deploy.sh firsthacking.tar```.

![Image](https://github.com/user-attachments/assets/67c70aa9-322a-479c-b3d8-0e17fe8cb6e7)

## First tests

Fistly, we need to check if the machine is deployed correctly and if there is connectivity. We can do that by pinging the machine  ```ping -c 1 172.17.0.2```  

![Image](https://github.com/user-attachments/assets/3f889464-a2f4-44dc-833e-3d534c349aae)

Once we've stablished that we can reach the machine, let's run a few simple tests. The technologies we will be using are:
- Nmap
- Searchsploit

This two tecnologies are often used in the enumeration phase. Enumeration is defined as the process of extracting user names, machine names, network resources, shares and services from a system.

## Enumeration

Using Nmap.
First, we will try a simple nmap test ```nmap -sS -p- -vv 172.17.0.2``` .
- sS: Sync scan. Simple port scan.
- -p-: Definition of the ports to scan. In this case, this flag means EVERY port.
- -vv: We add verbosity to the response (more text = more information)
- (172...): ip of the machine or vulnerable device

![Image](https://github.com/user-attachments/assets/96f4573c-b6d8-48a9-93c8-181a1cc4c7e3)

As we can observe in the resulting solution, nmap indicates that the port 21 is open, but even if we used the -vv, we didn't obtain much information apart from the protocol and service. Let's complete a bit more the command ```nmap -p21 -sS  -sV -vvv 172.17.0.2```
- sV: Shows the version of the service that is running in the port.
- p21: Only scans port 21
  
![Image](https://github.com/user-attachments/assets/b5904d6d-c1ee-40e6-8850-df5de0cf6d77)

Port 21 Vulnerabilities (FTP)

The File Transfer Protocol (FTP) is assigned port 21. FTP enables users to send and receive files in an unencrypted transmission to and from servers. FTP is considered outdated and insecure and should not be used for any file transfers, especially any sensitive data, as it can easily be exploited using any of the following methods:

    Brute-forcing passwords
    Anonymous authentication (it’s possible to log into the FTP port with “anonymous” as the username and password)
    Cross-site scripting
    Directory traversal attacks
    Man-in-the-middle


Using searchsploit. Finding exploiting options.

![Image](https://github.com/user-attachments/assets/ca79b983-85b0-4f32-a7e1-6f0c9a3374a9)

## Exploiting
Two different option to exploit this vulnerability:

### Metasploit
To access Metasploit we use the command ```msfconsole```. 

![Image](https://github.com/user-attachments/assets/41c25a83-aa3a-4801-ac53-0a06f9efd373)

Once using Metasploit we can search for the different sploits using ```search ${version}```, in this case ${version} = vsftpd. We will then be able to find the code we will run against the machine. We select the code:  ```use 1``` (the one that is described as backdoor seems as a pretty good option).

![Image](https://github.com/user-attachments/assets/68589428-38f3-4536-a015-b619f25c2084)

Once the code is selected we can explore the different options inside the code. We will need to set the required value "RHOSTS" ```set RHOSTS 172.17.0.2```.

![Image](https://github.com/user-attachments/assets/5f802986-e03c-4d5a-9e32-3a2c4ce128ce)

Once set it is all set up to run it! You'll be able to see that once the code is run we are root. In other words, we have all the permits to interact with whatever we want.

![imagen](https://github.com/user-attachments/assets/aecea981-cea9-4c14-a43b-2008e9ed877e)

### Python

To successfully exploit the vulnerability using Python we need to search manually the vulnerability. The are some websites dedicated to this purpose for example:
- [Exploit DB](https://www.exploit-db.com/): As we did in the previous example, knowing the version of the service running in the port, we can search for known exploits in this database. This would lead us to a file we can run with python.
- Github: Similar to Explot DB, we could search in our trusted navigator "vsftpd 2.3.4 exploit github". Usually the easiest option as it is common that the repository found comes with instructions.
- [CVE Program](https://www.cve.org/): Every exploit is registered using a CVE code. If you know the code, you could also use this website.

For this example we will use Github. Choose one of the many repositories found. In this case [vsftpd_2.3.4_Exploit](https://github.com/Hellsender01/vsftpd_2.3.4_Exploit) does just fine.

Following the instructions, we need to install pwntools ```sudo python3 -m pip install pwntools``` or ```sudo apt install python3-pwntools``` (first install python if not installed).

pwntools -->  CTF (Capture The Flag) framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

Once the installation is finished, we download the repository ```git clone https://github.com/Hellsender01/vsftpd_2.3.4_Exploit.git```. Once downloaded we can access the directory created and check the next step, exploiting the vulnerability using the file inside ```python3 exploit.py 172.17.0.2```.

![Image](https://github.com/user-attachments/assets/f49355e9-4c71-4145-861f-b648c01ec44f)

If needed you could use a python virtual environment to use python. Check this two references for more information.
- [Virtual environment](https://docs.python.org/es/3.5/tutorial/venv.html)
- [Source command](https://www.geeksforgeeks.org/source-command-in-linux-with-examples/)

Example (This way you will only install pwntools virtually)
```
python3 -m venv vsftpd2.4
source vsftpd2.4/bin/activate
pip3 install pwntools
```






