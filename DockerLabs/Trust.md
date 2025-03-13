







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

La enumeración del puerto 80, suele ser conocida como enumeración web. Para realizar este tipo de enumeración se utilizan hrramientas y tecnologias que realizan una tarea llamada fuzzing.
Algunas de estas herramientas son gobuster, wfuzz o dirb.
These tools are a free and open source web content scanner used to find existing (and/or hidden) web objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses
