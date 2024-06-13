---
layout: default
title: "Windows Attacks & Defense"
nav_order: 6
parent: CDSA

---

# 6.0) Windows Attacks and Defense

## A) SETTING THE STAGE

### A.1  Introduction and Terminology

-> [Active Directory](https://www.youtube.com/watch?v=GfqsFtmJQg0&ab_channel=ServerAcademy) (AD) és un un servei de directori per a entorns empresarials de Windows el qual Microsoft va llançar oficialment l’any 2000.

-> Permet la gestió centralitzada dels recursos d’una organització, inclosos usuaris, ordinadors, grups, dispositius de xarxa i recursos compartits de fitxers, polítiques de grup, dispositius de confiança.

-> Active Directory és el servei més crític de qualsevol empresa. Si l’AD es veu compromès pot comportar un accés sense restriccions a tots els sistemes i dades.

-> La pràctica més evident per mantenir la seguretat de l’AD és assegurar-se que hi ha un [Patch Management](https://www.youtube.com/watch?v=vIDG-O_17qA&ab_channel=EyeonTech) adequat.

*[Top Active Directory Attacks: Understand, then Prevent and Detect](https://www.youtube.com/watch?v=wZO-BJAtRPU&ab_channel=RSAConference)* 
### A.2 Overview and Lab Environment

-> En aquest mòdul veurem diferents atacs d’exemple. L’objectiu per a cada atac serà:

1. Describe it.
2. Provide a walkthrough of how ca carry out the attack.
3. Provide preventive techniques and compensating controls.
4. Discuss detection capabilities.
5. Discuss the "honypot" approach of detecting the attack, if aplicable.

		videoexplicació de com connectarse al laboratori

## B) ATTACKS & DEFENSE

### B.1 Kerberoasting

-> L’objectiu dels atacants és obtenir tiquets de servei xifrats de manera feble, coneguts com a “Service Tickets” (TGTs). Aquests tiquets solen associar-se amb comptes de servei al domini. Un cop obtingut, els atacants poden intentar desxifrar el contingut per revelar les credencials del compte administrador de l’AD.

[video explicacio](https://www.youtube.com/watch?v=tRCvagjqx3c&ab_channel=JohnHammond) 

##### ATTACK PATH

1. Identificació des comptes de servei.
2. Obtenció del TGT del compte (rubeus).
3. Exfiltratació del TGT (rubeus).
4. Sol·licitud de tiquets de servei (rubeus).
5. Atac de desxifrat del tiquet de servei (hashcat).
6. Realitzar el accés no autoritzat.

##### PREVENTION

-> L’èxit d’aquest atac depèn de la força de la contrasenya del compte de servei. Tot i que hauríem de limitar el nombre de comptes amb SPN, i desactivar els que ja no s’utilitzen.

##### DETECTION

-> Event Log ID: 4769. Es produeix quna un usuari sol·licita un Ticket Granting Service (TGS). 

![[Pasted image 20240511170059.png|600]]

Tanmateix, AD també genera el mateix ID d'esdeveniment cada vegada que un usuari intenta connectar-se a un servei, la qual cosa significa que el volum d'aquest esdeveniment és gegant. Quan executem 'Rubeus', extreu un tiquet per a cada usuari de l'entorn amb un SPN registrat; això ens permet avisar si algú genera més de deu bitllets en un minut (per exemple, però podria ser menys de deu)

##### HONEYPOT

-> Ha de ser un usuari sense ús real a l’entorn, de manera que no es generin tiquets amb regularitat. En aquest cas, qualsevol intent de generar un TGS per a aquest compte és probablement maliciós i val la pena inspeccionarl-lo.

### B.2 AS-REProasting

-> És un atac similar al anterior (Rubeus). Podem obtenir hashes potencialment crackejables de comptes d’usuari.

##### ATTACK PATH (https://www.youtube.com/watch?v=op-98Bx6cPw&ab_channel=TylerRamsbey)

 1. Obtenim els hashes de les comptes que no requereixen de pre-autenticació Kerberos utilitzant Rubeus.
 2. Utilitzem Hashcat/JTR per crackejar el hash en local.

##### PREVENTION

-> La millor mesura és una contrasenya robusta. També va bé revisar les comptes que tinguin la propietat de NO pre-authenticació

##### DETECTION

-> EventLog ID: 4768

![[Pasted image 20240511170846.png|600]]

##### HONEYPOT

Com en la cas anterior utilitzarem un user honeypot. 

![[Pasted image 20240511173409.png|600]]

### B.3 GPP Password (CPassword)

-> Group Policiy Preferences (GPP) va introduir la capacitat de guardar i utilitzar credencials, les quals son guardades al directori de polítiques dins l’AD. Tot usuari autenticat pot accedir a aquest recurs.

-> La clau d’encriptació dels arxius de polítiques es va filtrar. Això va provocar que qualsevol usuari autenticat pogués desencriptar totes les credencials del AD.

##### ATTACK PATH (https://www.youtube.com/watch?v=sTedpt47t2Y&ab_channel=Conda)

-> S’utilitza l’eina PowerSploit en la funció Get-GPPPasswords. Aquesta rastreja tots els arxius XML en la carpeta de Polítques dins de la carpeta SYSVOL. En busca dels que tenen la propietat “cpassword”.

##### PREVENTION

-> Al 2014 Microsoft va treure un parche (KB2962486) que prevenia la captura de credencials.

##### DETECTION (2 tècniques)

1. Creem un event que ens avisi quan s'accedeixi al arxiu XML. EventLog ID: 4663.
2. Creem un event que ens avisi quan s'intentin utilitzar les credencials robades.

-> EventLogID: 4624(succesful logon), 4625(field logon),4768 (TGT request).

##### HONEYPOT 

-> Creem unes polítiques de grup molt temptadores per l’atacant, com podria ser credencials en text pla. Quan s’intenti utilitzar aquestes credencials no funcionarà perquè son falses i s’activaran els Event ID 4625,4771,4776.

### B.4 GPO Permissions / GPO files

-> Group Policy Object (GPO) és una col·lecció de polítiques de configuració les quals es guarden a l’AD.

-> En principi sol els administradors poden modificar aquests arxius. Però segons estigui configurat, podem trobar delegacions a usuaris menys privilegiats per a que modifiquin les GPOs.

##### ATTACK PATH

No hi ha walkthrough, simplement és editar un arxiu en concret.

##### PREVENTION

- Limitar l'accés al GPO. Sol poden accedir els usuaris indispensables.
- Revisar els permisos de GPO de manera activa i regularment.

##### DETECTION 

-> Strightforward detection: EventLog ID: 5136. Ens avisa que un usuari ha modificat el GPO, si l’usuari qui ho modifica és unexpected serà una senyal d’alarma clara.

### B.5 Credentials Shares

És l’error de configuració més habitual que trobem en l’entorn d’AD.  ⚠️ No deixeu les credencials sense xifrar i els tokens d’autorització escampats per tot arreu.

##### ATTACK PATH

1. Identificar quins "shares" existeixen en l'AD.
2. Utilizem les eines "Invoke-ShareFinder" i SauronEye.
3. Obtenim l'output de les eines: List of non-default shares that the current user acount has at least read accés.

##### PREVENTION

-> Les millors pràctiques per prevenir aquest tipus d’atacs és una bona gestió dels permisos dels shares. Com més restrictius siguin, millor.

##### DETECTION

-> EventLogID : 4624, 4625, 4768 ens reporta que un admin ha fet una acció de login. Si aquesta s’ha fet desde una màquina que no és “Privilege Access Workstation”, aleshores serà clara red flag.

### B.6 Credentials in Object Properties

-> Quan un administrador creava un objecte "usuari" era costum escriure notes amb dades d'interés al camp informació/descripció.

-> El problema radicava que avegades es guardaven credencials i que tots els usuaris del domini poden veure el camp informació/descripció.

##### ATTACK PATH

-> Utilitzem un script en powershell per recorrer tots els camps "informació" de tots els usuaris en busca de strings malicioses, com per exemple: pass, password, cred, credential, etc...

##### PREVENTION

1. Perform continuous assessments to detect the problem of storing credentials in property objects.
2. Educar als administradors per a que no guardin credencials en les propietats dels objectes.
3. Automatitzar la creació d'un objecte "usuari" al màxim.

##### DETECTION

-> Va lligat amb el honeypot.

##### HONEYPOT

-> Utilitzem un usuari honeypot amb credencials falses en el camp de descripció. Si detectem un login d'aquest usuari saltaran les alarmes.

### B.7 DCsync

-> Un atacant pot simular ser un controlador de domini autoritzat i demanar a altres controladors de domini que li enviïn les credencials d'un compte específic, incloent-hi les contrasenyes en forma de hash.

##### ATTACK PATH 
1. Primer necessitem un usuari amb els privilegis necessaris (ReplicatingDirectoryChanges i ReplicatingDirectoryChanges All).
2. Utilitzem l'eina mimikatz per obtenir el hash ntlm de la compta administrador. Amb l'opció /all podem obtenir tots els hashes del AD. 
3. Finalment podem fer un pass-the-hash.

##### PREVENTION
-> The only prevention technique against this attack is using solutions as the RPC Firewall, a third-party product that can block or allow specific RPC calls with robust granularity.

##### DETECTION
-> Detecting DCsync is easy because each Domain Controller replication generates an EventLogID:4662.

### B.8 Golden Ticket

-> El Kerberos Golden Ticket explota les vulnerabilitats en el sistema d'autenticació Kerberos. L'atacant obté un GT el qual li concedeix accés indefinit al sistema. A diferència d'un tiquet de servei, el qual té una validesa limitada, un GT es crea amb la clau secreta del domini, coneguda com clau "krbtgt" (clau maestra de kerberos).

##### ATTACK PATH
-> Utilitzem mimikatz per generar un Golden Ticket.

##### PREVENTION

1. Block privileged users form authenticating to any device.
2. Periodically reset the password of the krbtgt account.
3. Prevent the escalation from a child domain to a parent domain (SIDHistory).

##### DETECTION
-> EventLogIDs 4624, 4625, 4768 ens reporta que un admin ha fet una acció de login. Al analitzar el log, si veiem que el login s'ha fet desde una màquina que no és Privilege Access Workstation, aleshores serè una senyal d'alarma.

### B.9 Kerberos Constrained Delegation

-> El client (usuari o servei) autoritza específicament un servidor per actuar en el seu nom. Aquest servidor delegat, anomenat "middle-tier server", pot demanar i obtenir tiquets de servei per accedir a altres serveis en nom del client.

##### ATTACK PATH
1. We assume that the user "web_service" is trusted for delegation and has been compromised.
2. To login, we will use the Get-NetUser function to enumerate users acounts that are trusted for constrained delegation in the domain.
3. Now we can see that the user web_service is configured for delegating the HTTP service to the Domain Controller DC1. HTTP provides the ability to execute Powershell Remoting. Therefore, threat actor can request a Kerberos ticket for any user in AD and use it to connect to DC1.
4. Then, we will sue Rubeus to get a ticket for the Admin account and the command "klist" to confirm the ticket is active.
5. Finally, we can connect to the DOmain Controller impersonating the Admin account.


##### PREVENTION
1) Configure the property "Account is sensitive and can't be delegated" for all privileged users.
2) Add privileged users to the "Protected Users".

##### DETECTION
EventLogID: 4624 ens reporta que un admin ha fet un login exitós. Al analitzar el Log, si el logn s'ha fet desde una màquina que no és *PAW*, aleshores serà una senyal d'alarma. 

### B.10 Print Spooler and NTLM Relaying

-> Print Spooler és un servei en els sistemes operatius Windows el qual gestiona les tasques d'impressió.
-> Si un atacant aconsegueix explotar una vulnerabilitat en el Print Spooler per executar codi maliciós amb privilegis elevats, podria utilitzar aquest accés per interceptar i redirigir peticions d'autenticació NTLM a altres sistems mitjançant NTLM relaying.
-> Aquesta combinació podria permetre el atacant obtenir credencials d'usuari vàlides.

##### ATTACK PATH

1. Per a que l'atac funcioni "SMB Signing on Domain Controllers" ha d'estar desactivat.
2. To begin, we configure NTML Relayx to forward any connections to DC2 and attempt to perform the DCSync attack.

![[Pasted image 20240606230517.png|600]]
3. Next , we need to trigger the PrinterBug using the Kali box with NTLMRelayx listening.
4. To trigger the connection back we'l use Dementor.
![[Pasted image 20240606230554.png|600]]
5. Now, switching back to the terminal session with NTLMRelayx, we will see thta DCSync was successfull.+

##### PREVENTION
1. Print Spooler should be disabled on all servers that are not printing servers.
2. Domain Controllers and other core servers should never have additional roles/functionalities that open and widen the attack surface toward the core AD infrastructure.
3. Setting the registry key (RegisterSpoolerRemoteRpcEndPoint) to 2 blocks any incoming remote request.
##### DETECTION
EventLogID: 4624. Relayed connection for DC1$ comes from a different IP Address.

### B.11 Coercing Attacks and Unconstrained Delegation

-> Coercing attacks have become a one-stop shop for escalating privileges from any user to Domain Administrator. Nearly every organization with a default AD infraestructure is vulnerable.

-> The Coercer tools was developed to exploit all known vulnerable RPC functions simultaneously.

##### ATTACK PATH
1. We assume that an attacker has gained administrative rights on a server configured for Unconstrained Delegation.
2. We will use the server to capture the TGT, while Coercer will be executed from Kali Machine.
3. Identify systems configured for Unconstrained Delegation (WSOO1, SERVER01).
![[Pasted image 20240606232152.png|600]]
4. We will start *Rubeus* in an administrative prompt to monitor for new logons and extract TGTs
 ![[Pasted image 20240606232450.png|600]]
 
5. Next, we need to know the IP address of WS001 by running ipconfig. Then we can execute Coercer with the IP. 
![[Pasted image 20240606232531.png|600]]
6. Finally, if we switch to WS001 and look at the continuous output that Rubeus provide, there should be a TGT for DC1 availabe.
![[Pasted image 20240606232710.png|600]]
##### PREVENTION

1. Implementing a third-party RPC firewall, such as the one from zero networks, and use it to block dangerous RPC functions.
2. Block Domain Controllers and other core infrastructure servers from connecting to outbound ports 139 and 445, except machines that are required for AD.
##### DETECTION

-> The RPC from zero networks is an excellent method of detecting the abuse of these functions and can indicate immediate signs of compromise.

### B.12 Object ACLs

-> Access Control Lists (ACLs) son taules o llistes simples les quals defineixen les polítiques que determinen qui té dret a accedir o modificar objectes específics en un sistemo o plataforma.

##### ATTACK PATH
1. SharpHound -> generates a ZIP file that can be visualized in BloodHund.
2. BloodHound -> analitza els resultats de SharpHound per visualitzar i analitzar la superfície d'atac potencial.

##### PREVENTION
1. Begin continuous assessment to detect if this is a problem in the AD environment.
2. Educate employees with high privileges to avoid doing this.
3. Automate as much as possible from the access management process.
