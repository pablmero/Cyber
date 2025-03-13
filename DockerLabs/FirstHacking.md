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

### Enumeration

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

