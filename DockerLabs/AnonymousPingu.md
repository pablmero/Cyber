# AnonymousPingu

This vulnerable machine is perfect to review intrussion and escalation of privilege (and a bit of bash scripting).

## Deployment
Start the vulnerable machine ```bash auto_deploy.sh anonymouspingu.tar ``` and check connectivity. (Before deploying the machine,
we could use ```systemctl restart docker``` to restart docker in case we are deploying the machine after the VM being suspended. This will assure the correct 
functioning of docker)

![imagen](https://github.com/user-attachments/assets/beb38f76-2687-44b1-9f6f-2ca96dd60393)

## Enumeration

We start by doing a general scan with the tool nmap against the vulnerable machine. This tool will allow us to check which ports are open.

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
    - -oG: Exports the result in a grepable format (to extract more easily the data with tools such as grep, awk)
    - -oN: Export the result to the designated file.   

![imagen](https://github.com/user-attachments/assets/e5f8a757-8621-4deb-8b22-981ad3ff70e8)

Once the scanning is complete, if there are any ports open we can do further and more detailed checks to gather more information

```nmap -sCV -p22,80 172.17.0.2```

 - -sCV: Script scanning and version scanning combined

![imagen](https://github.com/user-attachments/assets/0fabcf5c-2d33-4684-8f05-35776ad77584)

The results are a bit strange as we can see. In port 21, anonymous FTP login is allowed so nmap (thanks to -sC) can return all
the files and information accesible. 

Once we've stablished the open ports, let's check the common vulnerabilities:

Port 21 vulnerabilities:
        
        Port 21 is the gateway through which File Transfer Protocol (FTP) clients and servers communicate. 
        It’s used to send commands and receive responses, making it a critical component of the FTP process. 
        However, this same port is also a common target for hackers due to its inherent security weaknesses. 

        Key vulnerabilities of Port 21

            Plain Text Authentication:
                FTP uses plain text for authentication, meaning that usernames and passwords are transmitted without encryption. This makes it easy for attackers to intercept and steal login credentials using simple packet sniffing tools.
            Anonymous Access:
                Many FTP servers allow anonymous access, which can be a significant security risk. Anonymous users can potentially upload malicious files or access sensitive data if the server is not properly configured.
            Directory Traversal:
                FTP servers can be vulnerable to directory traversal attacks, where an attacker manipulates file paths to access files outside the intended directory. This can lead to the exposure of sensitive files and system configurations.
            Buffer Overflow:
                FTP servers can be susceptible to buffer overflow attacks, where an attacker sends more data than the server can handle, causing it to crash or execute arbitrary code. This can lead to server compromise and data theft.
            Malware Uploads:
                If an FTP server is not properly secured, attackers can upload malware or other harmful files. These files can then be used to launch further attacks or to compromise the server and its connected systems.
            Default Configuration Weaknesses:
                Many FTP servers come with default configurations that are not secure. For example, default usernames and passwords, or unnecessary services running, can provide easy entry points for attackers.

 
 
 Ports 80, 443, 8080, and 8443 Vulnerabilities (HTTP and HTTPS)
    
    Anyone who has visited a web page has used the HTTP or HTTPS protocols in their web browser. As mentioned, web ports are commonly targeted by attackers for many types of attacks, including:
    
        Cross-site scripting. Attackers inject malicious scripts into web pages and applications to steal cookies, tokens, or data.
        SQL injections. Attackers insert malicious SQL code into input fields to manipulate a database.
        Cross-site request forgers. An attacker exploits the trust between a user’s web browser and a web application to trick the user into performing actions on a website without their knowledge or consent.
        DDoS attacks

Firstly, let's check port 80. (Browse trough the IP). We encounter a webpage (.html template). Usually we need to investigate
this webpages to obtain more information, but html templates don´t give much info.

### Web enumeration

Enumeration of port 80 is usually known as web enumeration. To perform this kind of enumeration tools which carry out 
tasks known as fuzzing are used. Fuzzing is a methodology that consists of sending random or modified data to a web
application with the aim of provoking errors or discovering vulnerabilities. Further explanation in the Trust.md file.

First let browse the ip and then let's use Gobuster. 

```gobuster dir -u http://172.17.0.2/ -w /usr/share/wordlists/dirb/common.txt -t 20 -x html,php,txt,php.bak```

- dir: For directory and file enumerating
- -u: Target URL specification.
- -w /usr/share/wordlists/dirb/common.txt: Select word dictionary located in this address.
- -x html,php,txt,php.bak: Common file formats.

![imagen](https://github.com/user-attachments/assets/338584b1-1ca0-492b-9984-6a70309d71ac)

Some of the .html files that we found were already visible and accesible from the initial website, so we won't focus on them,
but we do find another files and directories (satus 301) we can access. Let's investigate them. (...). It seems that upload could 
be quite interesting, specially as we have FTP port 21 open. It might allow us to upload files or access others from there, 
potentially enabling a reverse shell. This could be possible as the directory ```/upload``` has the capacity of directory list, so 
we can upload a reverse shell and access it through the web to gain access to the machine.
La subimos al directorio /upload, 
que es el único lugar donde tenemos permisos de escritura.


### FTP enumeration

Once we have investigated possible vulnerabilities in the port 80, let's check port 21. As we can recall, port 21 allowed us 
FTP login with anonymous credentials, which means we can connect to ftp without any password.

![imagen](https://github.com/user-attachments/assets/604c9031-46a9-4c13-93c7-ee7327f417bb)

Let's enumerate the files and directories.

![imagen](https://github.com/user-attachments/assets/5c53ddb3-1873-450a-9dad-ef8d1e538462)

The files and directories lsited are the same found in the website and fuzzing report. Let's access upload just in case
we can find anything new.

![imagen](https://github.com/user-attachments/assets/3ebc0a47-f08e-40aa-87fa-dd0bac5299fa)

It's empty. But as we mentioned earlier it could be an opening for a reverse shell exploitation. To check whether we can 
access it or not, we can sen a PHP file to verify it. ```nano uploadfiletest.php ```

![imagen](https://github.com/user-attachments/assets/4c096c99-0fec-4793-a094-5c19b6ef6dd7)

Once created, let's try to upload it. First change directory to upload and then use command ```put``` and the name of the file.

![imagen](https://github.com/user-attachments/assets/61d87b1e-4235-4371-8744-b8bd1ffe7e19)

It worked! (You can also check in the browser).

![imagen](https://github.com/user-attachments/assets/1f4d16d8-af0f-487e-b5b8-ef5fce183b0c) ![imagen](https://github.com/user-attachments/assets/6e06cbd4-a2fa-4fbb-ab92-d41ab347c330)

The name is displayed on the screen, indicating that we're likely able to establish a reverse shell. We can use the web shell generator to deploy any of its scripts.

### [Reverse shell](https://www.imperva.com/learn/application-security/reverse-shell/)

A reverse shell, also known as a remote shell or “connect-back shell,” takes advantage of the target system’s 
vulnerabilities to initiate a shell session and then access the victim’s computer. The goal is to connect to a remote 
computer and redirect the input and output connections of the target system’s shell so the attacker can access it remotely.

Reverse shells allow attackers to open ports to the target machines, forcing communication and enabling a complete 
takeover of the target machine. Therefore it is a severe security threat. This method is also commonly used in penetration 
tests.

To perform the reverse shell process we can use the typical reverse shell [PentestMonkey.](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
This tool is designed for those situations during a pentest where you have upload access to a webserver that’s running PHP.
Upload this script to somewhere in the web root then run it by accessing the appropriate URL in your browser.  The script 
will open an outbound TCP connection from the webserver to a host and port of your choice.  Bound to this TCP connection 
will be a shell.

This will be a proper interactive shell in which you can run interective programs like telnet, ssh and su.  It differs from
web form-based shell which allow you to send a single command, then return you the output.
We can find the .php in the PentestMoneky website. Download it, upload it to the /upload directory and follow the [instructions](https://pentestmonkey.net/tools/web-shells/php-reverse-shell).
     
      ip -> docker0 ip check it in ```ifconfig```
      port -> any port of your preference to listen to the communication packets

![imagen](https://github.com/user-attachments/assets/ed448608-25f0-4542-988c-f646fe7f71b4)

![imagen](https://github.com/user-attachments/assets/eee22389-42b3-4489-9903-b31b59c398a8)

You can move the file to the directory needed ```mv file folder/file``` in order to be recognised in the ftp process. 
If it is a previous directory, remember the ```..```

![imagen](https://github.com/user-attachments/assets/e0d29dd9-e000-4cf4-b90d-050629ff2c9a)

![imagen](https://github.com/user-attachments/assets/bf07a80e-39fa-451f-a2ab-18f846bf664b)

Start a TCP listener on a host and port that will be accessible by the web server.  Use the same port here as you specified 
in the script. We can use netcat ```sudo nc -nlvp 443```

![imagen](https://github.com/user-attachments/assets/d4b09b25-e9ab-470a-a3dd-e6528f28d2f7)

Using whatever vulnerability you’ve discovered in the website, upload php-reverse-shell.php.  Run the script simply by 
browsing to the newly uploaded file in your web browser (NB: You won’t see any output on the web page, it’ll just hang if 
successful). Let's see what happens if we try to access the reverse shell now ```http://172.17.0.2/upload/shell.php```

![imagen](https://github.com/user-attachments/assets/a6af9444-2cce-43cb-8f8b-95f8331d18cc)

If all went well, the web server should have thrown back a shell to your netcat listener.  
Some useful commans such as w, uname -a, id and pwd are run automatically for you. We are inside the machine! Now we should treat the tty (explained in the bottom of this document)

Let's see who we are ```whoami``` and the privileges we have ```sudo -l```.

![imagen](https://github.com/user-attachments/assets/d5405837-3506-4fde-8c24-543dab99d494)

As we observe, we are www-data and we cant access anything, but the user pingu can execute ```man``` pages. Manual pages of 
the Linux OS.

Let's check the existing users (always located in the home directory). We found three different users. (Ubuntu seemed interesting too, but we've got no permission.)

![imagen](https://github.com/user-attachments/assets/f3f3aaa6-ae60-465a-a12f-57e08641ae0c)

But as we could observe earlier, the user pingu could execute the man pages, so let's investigate that. Now we can try two different ways:
- sudo -u pingu /usr/bin/man <any_command>: Executes the man pages as pingu, and then we can use !/bin/bash inside the man pages and execute it as pingu.
  ```sudo -u pingu /usr/bin/man find  ``` --> Open ```find``` manual, and once inside type ```!/bin/bash```. You are pingu now!
  
  ![imagen](https://github.com/user-attachments/assets/6032aaff-2ba0-4cb5-bb5a-bbc18895bcc2)


- GTFOBins: [Man](https://gtfobins.github.io/gtfobins/man/) for sudo superuser. (Follow the steps shown in the sudo part)

Now that we are pingu let's investigate a bit more. ```ls -la``` lists all of the files, even the hidden ones.

![imagen](https://github.com/user-attachments/assets/5d82643e-51a6-40c5-8cb9-7ec8a9f63b5e)

Nothing interesting, so let's repeat the same process we followed with www-data and list the privileges ```sudo -l```

![imagen](https://github.com/user-attachments/assets/8b1ddabe-d2a9-4222-bfca-30bc22af7ff2)

We have new privileges we can access, this time as the user gladys, so let's try again [GTFOBins](https://gtfobins.github.io/gtfobins/dpkg/)

````sudo -u gladys dpkg -l```

![imagen](https://github.com/user-attachments/assets/8e16046a-c03a-4e72-9660-23adfb72c649)

We are Gladys. Repeat process.

![imagen](https://github.com/user-attachments/assets/e47a08c8-6468-4d5b-83fb-48a37e7a1ed6)


We finally have an oportunity of escalting privileges to root.  ```chown``` will allow us to change the propietary of any file within the machine, resulting in the possibilty of editing any of those files.

We have two main options:
- Follow [GTOBins for chown](https://gtfobins.github.io/gtfobins/chown/).
- Take advantage of ```chown``` properties:
    - Test if you can execute ```chown```
     ![imagen](https://github.com/user-attachments/assets/3680829c-debf-4289-8065-f3231b737941)
    - Use chown to access passwd which is normally property of root. This file is
      ![imagen](https://github.com/user-attachments/assets/f089227b-be53-4831-800b-0c8af569014a) 
    - Open the file ```cat /etc/passwd```. 
      ![imagen](https://github.com/user-attachments/assets/28bed048-d4a3-4e06-a3c5-ce67913debf4)
    - The ```x``` to the right of the different users listed indicates the need for authentication. If we delete that x, and execute ```su <user>``` no password is going to be requested to change to that user. Let's edit the file the ```nano /etc/passwd```
     ![imagen](https://github.com/user-attachments/assets/83de5e94-eea7-4193-a4b7-196eca876239)

      Nooooo!! Nano (nor vim nor vi) it's not found (because it is a small container maybe). This makes things more difficult, but we can solve it. Options:
      - ```sed```: If sed is available it can be used to perform text substitutions ```sed 's/word/substitute/g``` (could be a whole sentence too). For example:
       ![imagen](https://github.com/user-attachments/assets/0f73f98e-34f6-460a-81e4-636643513d10)
        So if we apply this to /etc/passwd file:

        ![imagen](https://github.com/user-attachments/assets/251ffba8-c076-465e-b48d-0b9f427751b1)
 
        The passwd got duplicated so we are going to try to fix that mistake:

        ![imagen](https://github.com/user-attachments/assets/048f9e0c-145b-439d-b8bc-775a44ac7bce)


      - Use echo to append to the end of the file
      


      


 






### Treatment of the TTY (Recommendation) 

[Fully interactive TTY](https://territoriohacker.com/tratamiento-de-la-tty/)

Cuando nos conectamos mediante una reverse-shell con otro equipo, en muchas ocasiones nos encontraremos con que la Shell de la que disponemos no son prácticas, las proporciones no son correctas, no podemos utilizar atajos de teclado, al pulsar (Cntrl + L) perdemos la terminal y una larga serie de inconvenientes.

Para evitar todos estos problemas, una vez hemos establecido la Shell inversa, podemos realizar lo que se conoce como un tratamiento de la TTY, para poder disponer de una Shell completamente funcional.

Para saber si nos encontramos en una TTY:

tty

Si nos reporta not a tty introducimos los siguientes comandos:

script /dev/null -c bash

Luego, pulsamos Cntrl + z para salir de la terminal e introducimos el segundo comando:

stty raw echo; fg

Y debajo de este comando a la derecha, escribimos reset xterm para volver a la terminal ya lista.

reset xterm

En caso de no funcionar aún el Ctrl + l para limpiar la terminal, realizamos también lo siguiente:

export SHELL=bash
export TERM=xterm

💻 Ajustar Proporciones 💻

Para que las proporciones de la terminal sean iguales a las de nuestro sistema debemos ajustar tanto las filas como las columnas. Por ejemplo si abrimos o creamos un archivo con nano este se verá pequeño. Para ajustar estas proporciones primero debemos ir a una de nuestras ventas y ver que proporciones tiene:

stty size

En mi caso mi terminal tiene 52 filas y 189 columnas. Ahora ajustaremos con estos parámetros nuestra Reverse Shell. Para ello escribimos lo siguiente en la terminal de la Reverse Shell:

stty rows 52 columns 189

Ahora ya podríamos utilizar nuestra Shell con completa normalidad y sin peligro de que se cierre o se comporte de forma extraña o limitada y con las proporciones ajustadas.











