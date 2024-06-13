---
layout: default
title: "Detecting Windows Attacks with Splunk"
nav_order: 14
parent: CDSA

---

# 14) Detecting Windows attacks with Splunk

## A) LEVERAGING WINDOWS EVENT LOGS

### A.1 Detecting Common User / Domain Recon

-> AD domain reconnaissance represents a pivotal stage in the cyberattack lifecycle. During this phase, adversaries endeavor to gather info about the target environment, seeking to comprehend its architecture, network topology, security measures, and potential vulnerabilities.

-> While conducting AD domain reconnaissance, attackers docus on identifying crucial components such as Domain Controllers, user accounts, groups, trust relationships, organizational units (OUs), group policies, and other vital objects.

-> A continuació veurem dos tècniques que podria utilitzar un atacant per fer un 'domain recon' del nostre domini:

1. Recon using native windows executables
	-> Un exemple de domain recon és quan un adversari executa la commanda 'net group' per obtenir la llista de Domain Administrators. Eines/commandes comunment utilitzades pel domain recon son:
		- whoami/all
		- wmic computersystem get domain
		- net user/domain
		- net group "Domain Admins"/domain
		- arp -a 
		- nltest/domain_trust
2. Recon Using BloodHound / Sharphound
	-> BloodHound és una wine de reconeixement de dominis de codi obert creada per analitzar i visualitzar l'entorn Active Directory (AD). BloodHound aprofita la teoria de gràfics i el mapa de relacions per clarificar les relacions de confiança, els permisos i les pertinences a grups dins del domini AD. Sharphound is a C# data collector for BloodHound.

##### DETECTION (w/ Splunk)

1. Detecting Recon by targeting Native Windows Exec
	1. Filtering by Index and Source -> Comencem la búsqueda filtrant els events que ens interessen. L'index és el main i el source és XmlWinEventLog.
	2. EventIDFilter -> Apliquem un altre filtre en la búsqueda. Aquest cop ens interessen els esdeveniments amb EventID = 1; ja que correspon als esdeveniments de creació de processos, els quals registren dades sobre processos de nova creació.
	3. Time Range Filter -> Restringim la cerva a l'interval de temps en el qual succeeixen els esdeveniments.
	4. Process Name Filter -> This step is looking for events that involve certain system or network-related commands, as well as events where these commands were run from a Command Prompt or PowerShell.
	5. Statistics -> The stats command is used to aggregate events based on the fields, parent_process, parent_process_id, dest and user.
	6. Filtering by Process Count -> This step is looking for instances where multiple processes (more than three) were executed by the same parent process.
2. Detecting Recon by Targeting BloodHound
	1. Filtering by Index and Source -> The main index with the source of WinEventLog:SilkServiceLog. This source represents WindowsEventLog data gathered by SilkETW.
	2. Time Range Filter
	3. Path Extraction -> The 'spath' command is used to extract fields from the Message field, which contains structured data such as XML or JSON.
	4. Field Renaming -> This is done for easier references to the fields in later stages of the search.
	5. Tabulating results
	6. Sorting
	7. Search Filter -> This step is looking for events related to LDAP queries with a specific filter condition.
	8. Statistics -> The stats command is used to aggregate events based on the fields ComputerName, ProcessName, ProcessID.
	9. Filtering by EventCount -> This step is looking for instances where the same process on the same computer made more than ten search queries with the specified filter condition.
	10. Time Conversion.

### A.2 Detecting Password Sprying

##### ATTACK PATH

-> Enlloc de provar moltes contrasenyes per a un usuari, el password sprying distribueix l'atac a diversos comptes d'usuari. És a dir, prova poques contrasenyes per a molts usuaris.

##### DETECTION (w/ Splunk)

-> La detecció del password sprying a través dels registres de Windows implica l'anàlisis i seguiment de registres d'esdeveniments específics, per identificar patrons i anomalies indicatius d'aquest atac. Un patró comú son diversos intents d'inici de sessió fallits amb el EventID 4625 - Failed Logon des de diferents comptes d'usuari però que s'originen desde la mateixa adreça IP d'origen en un període de temps curts.

### A.3 Detecting Responder-like Attacks

##### ATTACK PATH

-> Both LLMR and NBT-NS are used to resolve hostnames to IP addresses on local networks when the fully qualified domain name (FQDN) resolution fails. LLMNR/NBT-NS/mDNS Poisoning son atacs a nivell de xarxa que exploten les ineficiències en aquests protocols de resolució de noms. Attackers employ the Responder tool to perform this attack.

![[Pasted image 20240512170627.png|600]]
##### DETECTION (w/ Splunk)

Organizations can mitigate the risk by implementing the following measures: 

1. Deploy network monitoring solutions to detect unusual LLMNR nad NBT-NS traffic patterns.
2. Employ a honeypot approach (name resolution for non-existent hosts should fail)

		video exemple d'una detecció amb splunk

### A.4 Detecting Kerberoasting/AS-REProasting

##### ATTACK PATH (kerberoasting)
Is a technique targeting service accounts in Active Directory environments to extract and crack their password hashes.


1. Identify Target Service Accounts -> The attacker enumerates Active Directory to identify service accounts with `Service Principal Names (SPNs)` set.  The following is a code snippet from `Rubeus` that is related to this step.
	![[Pasted image 20240512172326.png|600]]
2. Request TGS Tickets -> The attacker uses the identified service accounts to request `Ticket Granting Service (TGS)` tickets from the `Key Distribution Center (KDC)`. These TGS tickets contain encrypted service account password hashes. The following is a code snippet from `Rubeus` that is related to this step.
	
	![[Pasted image 20240512172610.png]]
3. Offline Brute-Force Attack -> The attacker employs offline brute-force techniques, utilizing password cracking tools like `Hashcat` or `John the Ripper`, to attempt to crack the encrypted password hashes. 

##### ATTACK PATH (AS-REProasting)
-> Is a technique used in Active Directory environments to target user accounts without pre-authentication enabled.

1. **Identify Target User Accounts** -> The attacker identifies user accounts without pre-authentication enabled. The following is a code snippet from `Rubeus` that is related to this step.
	![[Pasted image 20240512173243.png]]
2. **Request AS-REQ Service Tickets** -> he attacker initiates an AS-REQ service ticket request for each identified target user account.
	
	![[Pasted image 20240512173333.png]]
3. **Offline Brute-Force Attack.** 

##### DETECTION KERBEROASTING (w/ Splunk)

	video explicatiu de la detecció

##### DETECTION AS-REProasting (w/ Splunk)

	video explicatiu de la detecció

### A.5 Detecting Pass-the-Hash

##### ATTACK PATH

-> Is a technique utilized by attackers to autheticate to a networked system using the NTLM hash of a user's password instead of the plain text password.

(+ Attack path/demo)

##### DETECTION (w/ Splunk)

-> From the Windows Event Log perspective, the following logs are generated when the runas command is executed.

- When runas command is executed without the /netonly flag -> EventID 4624(Logon) with LogonType2 (interactive)
- When runas command is executed with the /netonly flag -> Event ID 4624

### A.6 Detecting PassTheTicket
##### ATTACK PATH

-> Is a lateral movement technique used by attackers to move laterally within a network by abusing Kerberos TGT (Ticket Granting Ticket) and TGS (Ticket Granting Service) tickets.

	(attack path)
##### DETECTION (w/ splunk)

- Event ID 4648 -> Explicit Credentials Logon Attempt
- Event ID 4624 -> Logon
- Event ID 4672 -> Special Logon (privileged account)
- Event ID 4768 -> Kerberos TGT Request
- Event ID 4769 -> Kerberos Service ticket Request

	(exemple detecció)

### A.7 Detecting Overpass-the-Hash

##### ATTACK PATH

-> Adversaries may utilize the Overpass-the-Hash technique to obtain Kerberos TGTs by leveraging stolen password hashes to move laterally within an environment or to bypass typical system access controls

	(attack path)

##### DETECTION (w/ Splunk)

-> Mimikat'z Overpass-the-Hash attack leaves the same artifacts as the Pass-the-Hash attack, and can be detected using the same strategies.
	
	(deteccio videoexemple)

### A.8 Detecting Golden Tickets / Silver Tickets

-> A Golden Ticket attack is a potent method where an attacker forges a Ticket Granting Ticket (TGT) to gain unrestricted access to a Windows AD domain administrator. The attacker creates a TGT with arbitrary user credentials and then uses this forged ticket to impersonate domain. The Golden Ticket attack is stealthy and persistent, as the forged ticket has a long validity period and remains valid until it expires or is revoked.

	(attack path)

##### DETECTION (w/ Splunk)

-> Detecting Golden Ticket attacks can be challenging, as the TGT can be forged offline by an attacker, leaving virtually no traces of Mimikatz execution. One option is to monitor common methods of extracting the KRBTGT hash:
- DCSync attack
- NTDS.dit file access
- LSASS memory read on the domain controller (Sysmon Event ID 10)

:CAUTION: From another standpoint, a Golden Ticket is just another ticket for Pass-The-Ticket detection

	(deteccio videoexemple)
### A.9 Detecting Unconstrined/Constrained Delefation Attacks
##### ATTACK PATH (Unconstrined)

-> Unconstrined Delegation is a privilege that can be granted to user accounts or computer accounts in AD environment, allowing a service to authenticate to another resource on behalf of any user. This might be necessary when, for example, a web server requires access to a database server to make changes on a user's behalf.

	(attack path)

##### DETECTION (w/ Splunk)
-> Powershell commands and LDAP search filters used for Unconstrined Delegation discovery can be detected by monitoring PoerShell script blog logging (Event ID 4104) and LDAP request logging.

-> The main goal of an Unconstrined Delegation attack is to retrieve and reuse TGT tickets, so Pass-the-Ticket detection can be used as well.

	(deteccio videoexemple)

##### ATTACK PATH (Constrined)

-> Constrined Delegation is a feature in AD that allows services to delegate user credentials only to specified resources, reducing the risk assoviated with Unconstrined Delegation. Any user or computer accounts that have service principal names (SPNs) set in their msDS-AllowedToDelegateTo propery can impersonate any user in the domain to those specific SPNs.

	(attack path)

##### DETECTION
-> Similar to U. Delegation, it is possible to detect PowerShell commands and LDAP request aimed at discovering vulnerable Constrined Delegation users and computers.

-> To request a TGT ticket for a principal, as well as a TGS ticket using the S4U technique, Rubeus makes connections to the Domain Controller. This activity can be detected as an unusual process network connection to TCP/UDP port 88 (Kerberos)

	(+ Exemple d'una detecció)

### A.10 Detecting DCSync / DCShadow

##### ATTACK PATH (DCSync)

-> DCSync is a technique exploited by attackers to extract password hashes from Active Directory Domain controllers (DCs). This method capitalizes on the Replication Directory Changes permission typically granted to domain controllers, enabling them to read all objects attributes, including hashes.

-> Members of the Administrators, Domain Admins, and Enterprise Admin Groups, or computer accounts on the domain controller, have the capability to execute DCSync to extract password data from Active Directory. This data may encompass both current and historical hashes of potentially valuable accounts, such as KRGTGT and Administrators.

	(+ attack steps / demo)
##### DETECTION DCSync (w/ Splunk)
-> DS-Replication-Get-Changes operations can be recorded with Event ID 4662. However, and additional Audit Policy Configuration is needed since it is not enabled by default (Computer Config / Windows Settings / Security Settings / Advanced Audit Policy Configuration / DS Access )

	( exemple duna detecció )
##### ATTACK PATH (DCShadow)

-> DCShadow is an advanced tactic employed by attackers to enact unauthorized alterations to Active Directory objects, encompassing the creation of modification of objects without producing standard security logs. The assault takes advanttage of the Directory Replicator permission, habitually granted to domain controllers for replication tasks.

-> DCShadow is a clandestine technique enabling attackers to manipulate AD data establish persistence within the network. Registration of a rogue DC necessitates the creation of a new server and nTDSDSA objects in the Configuration partition of the AD schema, which demands Administrator privileges or the KRBTGT hash.

	(attack steps / demo)
##### DETECTION (w/ Splunk)
-> To emulate a Domain Controller, DCShadow must implement specific modifications in Active Directory:
- Add a new nTDSDSA object
-  Append a global catalog ServicePrincipleName to the computer object.
- EventID 4742 (Computer account was changed) logs changes related to computer objects, including ServicePrincipleName

	(exemple d'una detecció)
## B) LEVERAGING SPLUNK'S APPLICATION CAPABILITIES

### B.1 Creating Custom Splunk Applications

-> En aquest apartat veurem com crear una aplicació Splunk personalitzada

1. Access splunk web
2. Go to manage apps
3. Create a new app
4. Enter app details
5. Save the app
6. Explore the Directory Structure
7. View the Navigation File
8. Create Your First Dashboard
9. Configure the Dashboard
10. Dashboard Storage
11. Restart Splunk
12. Grouping Dashboards

		(video explicatiu)


## C) LEVERAGING ZEEK LOGS

### C.1 Detecting RDP BruteForce Attacks

##### ATTACK PATH
-> We often encounter Remote Desktop Protocol brute force attacks as a favorite vector for attackers to gain initial foothold in a network.

-> The concept of an RDP attack is relatively stright forward: attackers attempt to login into a Remote Desktop session by systematically guessing and trying different passwords until they find the correct one. This method exploits weak passwords.

##### DETECTION (w/ Splunk + ZeekLogs)

		(rdp traffic example)

		(videoexemple de detecció)

### C.2 Detecting Beaconing Malware

-> Malware Beaconing is a technique we frequently encounter in our cybersecurity investigations. It refers to the periodic communication initiated by malware-infected systems with their respective command and control (C2) servers. The beacons, tipically small data packets, are snet at regular intervals, much like a lighthouse sends out regular signal.

-> In this section, we will concentrate on detecting the beaconing behavior associated with widely recognized command and control (C2) framework known as Cobalt Strike (in its default config).

##### DETECTION (w/ Splunk + Zeek Logs)

		(videoexplicació duna deteccio)

### C.3 Detecting Nmap Port Scanning

-> In essence, what we're doing with Nmap is probing networked systems for open ports - these are the 'gates' through which data passes in and out of a system. Open ports can be likened to doors that might be unlocked in a building - doors that attackers could potentially use to gain access.

-> When we use Nmap for port scanning, we systematically attempt to establish a TCP handshake with each port in the target's address space. If the connection is successful, it indicates that the port is open and the service listening might return a "banner" - this is essentially a little bit of data that tells us what service is running , and maybe even what version it's running.

-> But let's clear up a misconception - when er are talking abount Nmap sending data to the scanning ports, we're not sending any extra data; we're just trying to initiate connection.

##### DETECTION(w/ Splunk + Zeek Logs)

	(EXEMPLE PRÀCTIC DUNA DETECCIO)

### C.4 Detecting Kerberos Brute Force Attacks

##### ATTACK PATH
-> When adversaries perform Kerberos-based user enumeration, they send and AS-REQ(Authentication Service Request) message to the Key Distribution Center (KDC), which is responsible for handling kerberos authentication. This message includes the username they're trying to validate. They pay attention to the response they recieve, as it reveals valuable info about the existence of the specific user account.

-> A valid username will prompt the server to return a TGT or raise an error like KRB5KDC_ERR_PREAUTH_REQUIRED, indicating that preauthentication is required. On the other hand, an invalid username will be met with a Kerberos error code KRB5KDC_ERR__C_PRINCIPAL_UNKNOWN in the AS-REP (Authentication Service Response) message. By examining the response to their AS-REQ messages, adversaries can quickly determine which usernames are valid on the target system.

##### DETECTION (w/ Splunk + Zeek Logs)

	(exemple practic duna deteccio)


### C.5 Detecting Kerberoasting
-> In 2016, a number of blog posts and articles emerged discussing the tactic of querying Service Principle Name (SPN) accounts and their corresponding tickets an attack that came to be known as Kerberoasting. By possessing just one legitimate user account and its password, an attacker could retrieve the SPN tickets and attempt to break them offline.

-> After examining numerous resources on Kerberoasting, it is evident that RC4 is utilized for ticket encryption behind the scenes. we will exploit this underpinning as a detection point in this section.

	(evidence resource)

##### DETECTION (w/ Splunk + Zeek Logs)

	(exemple duna deteccio)

### C.6 Detecting Golden Tickets

##### ATTACK PATH
-> In a Golden Ticket attack, the attacker generates a forged TGT, which grants them access to any service on the network without having to authenticate with a KDC. Since the attacker has a forged TGT, they can directly request TGS tickets without going through the AS-REQ and AS-REP process.

##### DETECTION (w/ Splunk and Zeek Logs)

	(exemple duna deteccio)

### C.7 Detecting Cobalt Strike's PSExec

##### ATTACK PATH

-> Cobalt Strike's psexec command is on implementation of the popular PsExec tool, which is a port of Microsoft's Sysinternals Suite. It's a lightweight telnet-replacement that lets you execute processes on other systems. Cobalt Strike's version is used to execute payloads on remote systems, as part of the post-exploitation process.

-> When the psexec command is invoked with in Cobalt Strike, the following steps occur:
1. Service Creation -> The tool first creats a new service on the target system. This service is responsible for executing the desired payload. The service is typically created with a random name to avoid easy detection
2. File Transfer -> Cobalt Strike then transfers the payload to the target system, often to the ADMIN$ share.
3. Service execution -> The newly service is then started, which in turn executed the payload. This payload can be a shellcode, an executable, or any other file type that can be executed.
4. Service removal -> After the payload has been executed, the service is stopped and deleted from the target system to minimize traces of the intrusion.
5. Communication -> If the payload is a beacon or another type of backdoor, it will typically establish communication back to the Cobalt Strike team server, allowing for further commands to be sent and executed on the compromised system.

:caution: Cobalt Strike's psexec works over port 445(SMB), and it requires local administrator privileges on the target system. Therefore, it's often used after initial access has been achieved and privileges have been executed. Therefore, it's often used after initial access has been achieved and privileges have been escalated.


##### DETECTION (w/ Splunk)
(soon)

### C.8 Detecting Zerologn

-> The Zerologon vulnerability (CVE-2020-1472), is a critical flaw in the implementation of the Netlogon remote Protocol, specifically in the cryptographic algorithm used by the protocol. The vulnerability can be exploited by an attacker to impersonate any computer, including the domain controller, and execute remote procedure calls on their behalf. Let's dive into the technical details of the flaw.

##### ATTACK PATH 
-> When a client wants to authenticate againts the DC, it uses a protocol called MS-NRPC, a part of Netlogon, to establish a secure channel.

-> During this process, the client and the server generate a session key, which is computed from the machine account's password. This key is then used to derive an initialization vector (IV) for the AES-CFB8 encryption mode. In a secure configuration, the IV should be unique and random for each encryption operation. However, due to the flawed implementation in the Netlogon protocol, the IV is set to a fixed value of all zeros.

-> The attacker can exploit this cryptographic weakness by attempting to authenticate against the domain controller using a session key consisting of all zeros, effectively bypassing the authentication process. This allows the attacker to establish a secure channel with the DC without knowing the machine account's password.

-> Once this channel is established, the attacker can use the NetrServerPasswordSet2 function to change the computer account's password to any value, including a blank password. This effectively gives the attacker full control over the DC and, by extension, the entire Active Directory domain.

:TiAlertTriangle:  The Zerologon vulnerability is particularly dangerous due to its simplicity and the level of access it provides to attackers. Exploiting this flaw requiers only a few Netlogon messages, and it can be executed within seconds.

##### DETECTION

-> How Zerologon looks like from a network perspective:

![[Pasted image 20240611002242.png|600]]

	videoexemple d'una detecció amb Splunk (soon)

### C.9 Detecting Exfiltration (HTTP)

-> Data exfiltration inside the POST body is a technique that attackers employ to extract sensitive info for a compromised system by disguising it as a legitimate web traffic. It involves transmitting the stolen data from the compromised system to an external server controlled by the attacker using HTTP POST request. Since POST requests are commonly used for legitimate purposes, such as form submissions and file uploads, this method of data exfiltration can be difficult to detect.

##### ATTACK PATH
-> To exfiltrate the data, the attackers send it as the body of an HTTP POST request to their command and control (C2) server. They often use seemingly innocuous URLs and headers to further disguise the malicious traffic. The C2 server receives the POST request, extracts the data from the body, and decodes or decrypts it for further analysis and exploitation

##### DETECTION
->  To detect data exfiltration via POST body, we can employ network monitoring and analysis tools to aggregate all data sent to specific IP addresses and ports. By analyzing the aggreggated data, we can identify patterns and anomalies that may indicate data exfiltration attempts.

-> In this section we will monitor the volume of outgoing traffic from our network to specific IP addresses and ports. If we observe unusually large or frequent data transfers to a specific destination, it may indicate data exfiltration.

	videoexemple d'una detecció (soon)

### C.10 Detecting Exfiltration (DNS)

-> Attackers employ DNS-based exfiltration due to its reliability, stealthiness, and the fact that DNS traffic is often allowed by default in network firewall rules. By embedding data within DNS queries and responses, attackers can bypass security controls and exfiltrate data covertly. Below is a detailed explanation of this technique and methods.

##### ATTACK PATH
1. Initial Compromise -> The attackers gains access to the victim's network, typically through malware, phishing or exploiting vulnerabilities.
2. Data Identification and Preparation -> The attacker locates the data they want to exfiltrate and prepares it for transmission. This usually involves encoding or encrypting the data and splitting it into small chunks.
3. Exfiltrate Data via DNS -> The attacker sends the data in the subdomains of DNS queries, using techniques such as DNS tunneling or fast flux.
4. Data Retrieval and Analysis -> After exfiltration, the attacker decodes or decrypts the data and analyzes it.

-> How DNS Exfiltration traffic looks like:

![[Pasted image 20240611004240.png|600]]

	Videoexemple pràctic d'una detecció (soon)

### C.11 Detecting Ransomware

##### ATTACK PATH
1. File Overwrite Approach -> Ransomware employs this tactic by accessing files through SMB protocol, encrypting them, and then directly overwritting the original files with their encrypted versions (again through SMB protocol).
2. File Renaming Approach -> In this approach, ransomware actors use the SMB protocol to read files, they then encrypt them and they finally rename the encrypted files by appending a unique extension (again through SMB protocol), often indicative of the ransomware strain.

##### DETECTION (w/ Splunk + ZeekLogon)

	Videoexemple d'una detecció.

