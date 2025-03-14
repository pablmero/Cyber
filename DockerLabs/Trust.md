

# [Trust](https://dockerlabs.es/)


## Deployment
To start the vulnerable machine ```bash auto_deploy.sh trust.tar```
Once deployed, we check connectivity.

![Image](https://github.com/user-attachments/assets/d63f30d6-307d-4bea-8adf-7a15094d372f)

## Enumeration

We start by doing a general scan with the tool nmap against the victims ip, the vulnerable machine. This tool will allow us to check which ports are open.

```nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 172.18.0.2 -oG scanfile```

- -p- : Scan all ports
- --open: Chech just the open ports
- --min-rate 5000: Send packets faster (faster scanning)
- -sS: Sync Scan. Fast and silent scan.
- -sV: Version of the service runnning in the port.
- -vvv: Increase verbosity (more information)
- -n: No DNS resolution (faster scanning)
- -Pn: Ignores if the ip is active or not
    - -oG: Exports the result in a grepable format (to extract more easily the data with tools such as grep, awk)
    - -oN: Export the result to the designated file.

![Image](https://github.com/user-attachments/assets/678a3873-b29e-4bb0-b457-3405736aa03e)

Once the scanning is complete, if there are any ports open we can do further and more detailed checks to gather more information

```nmap -sCV -p22,80 172.18.0.2```

- -sCV: Script scanning and version scanning combined

![Image](https://github.com/user-attachments/assets/c379c3b8-3b0e-445a-8419-432e9bb32fb1)

Once we've stablished the open ports, let's check the common vulnerabilities:

    Port 22 Vulnerabilities (SSH)
    
    Port 22 is commonly used for Secure Shell connections. It is preferred over Telnet because the connection is encrypted. Often used for remote management, Port 22 is a TCP port for ensuring secure remote access. Despite its enhanced security, it still suffers from some basic vulnerabilities:
    
        Leaked SSH keys. If SSH keys are not correctly secured, they can be accessed by an attacker to gain entry without having the required password.
        Brute-forcing Credentials. Open SSH ports are easily discoverable, allowing attackers to guess username and password combinations.


    Ports 80, 443, 8080, and 8443 Vulnerabilities (HTTP and HTTPS)
    
    Anyone who has visited a web page has used the HTTP or HTTPS protocols in their web browser. As mentioned, web ports are commonly targeted by attackers for many types of attacks, including:
    
        Cross-site scripting. Attackers inject malicious scripts into web pages and applications to steal cookies, tokens, or data.
        SQL injections. Attackers insert malicious SQL code into input fields to manipulate a database.
        Cross-site request forgers. An attacker exploits the trust between a user’s web browser and a web application to trick the user into performing actions on a website without their knowledge or consent.
        DDoS attacks

### Web enumeration

Enumeration of port 80 is usually known as web enumeration. To perform this kind of enumeration tools which carry out tasks known as fuzzing are used. Fuzzing is a methodology that consists of sending random or modified data to a web application with the aim of provoking errors or discovering vulnerabilities. This technique can be performed manually, but in this course we will focus on the use of automated tools that facilitate and accelerate the process. Some examples of this tools could be wfuzz, gobuster or dirb.

These tools are a free and open source web content scanner used to find existing (and/or hidden) web objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses.

As port 80 is open (HTTP port) we need to check the ip in the browser (as if it was an URL). This way we can access the apache server through the browser.

![Image](https://github.com/user-attachments/assets/c5bc319e-5f7a-47bc-a409-d420dda1f677)

The brwoser redirects us to the apache default page. But this only the main page of the server, there could be more directories or files hidden within the server, that's why we use fuzzing tools, to discover this hidden content.

In this case we will use Gobuster.
    Gobuster is a tool used to brute-force:
    URIs (directories and files) in web sites.
    DNS subdomains (with wildcard support).
    Virtual Host names on target web servers.
    Open Amazon S3 buckets
    Open Google Cloud buckets
    TFTP servers

```gobuster dir -u http://172.18.0.2/ -w /usr/share/wordlists/dirb/common.txt -t 20 -x html,php,txt,php.bak```
- dir: For directory and file enumerating
- -u: Target URL specification.
- -w /usr/share/wordlists/dirb/common.txt: Select word dictionary located in this address.
- -x html,php,txt,php.bak: Common file formats.

![image](https://github.com/user-attachments/assets/229ea074-0463-465d-afce-883d6f576c6e)

We have found some new files we can access through the port 80. We can check every status 200 but it seems kind of obvious that they want us to check secret.php.

![image](https://github.com/user-attachments/assets/9bee41fd-9a82-4f76-95f5-ec692f3b4e7d)

At first maybe we don't notice anything important in this website, but in cybersecurity, every little detail matters. The name Mario could be a username and if we remember from the nmap results, the ssh port was open too. What if this user could be used to exploit the ssh connection? Maybe Mario is a username that we can try to break the password either by brute force or dictionary.

## Exploiting: Infiltration

Infiltration refers to the act of secretly entering, observing, or extracting sensitive information from a secure system or network. This is typically the objective of cybercriminals or hackers who aim to penetrate protective barriers installed on systems in a bid to scrape sensitive information, corrupt data, disrupt operations, or deliver a damaging payload such as a virus.

To perform this infiltration we can use tools such us hydra or medusa. 
In this case, we will use Hydra, which is an open-source tool designed for performing brute-force attacks on various protocols and services to test the authentication mechanisms.

``` hydra -l mario -P /usr/share/wordlists/rockyou.txt -ssh://172.18.0.2 ```
- -l username: Name of the possible username
- -P: Route fow downloading the rockyou dictionary (wordlist with possible passwords)
- ssh://172.18.0.2: Specify the service (ssh) y and the machine ip
