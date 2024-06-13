---
layout: default
title: "Intermediate Network Traffic Analysis"
nav_order: 8
parent: CDSA
---

# 8.0) Intermediate Network Traffic Analysis

## A) INTRODUCTION

### A.1 Intermediate Network Traffic Analysis Overview

-> En aquest mòdul, ens centrarem en un ample conjunt d’atacs que interaccionen amb la nostra infraestructura de xarxa. L’objectiu és discernir patrons i tendències en aquests atacs.

-> Aquest enfocament no només reforça la nostra capacitat d’identificació proactiva d’amenaces, sinó que també millora les nostres mesures reactives.

	videoexplicacio Download + setup lab files

## B) LINK LAYER ATTACKS

### B.1 ARP Spoofing and Abnormality Detection

-> ARP Definition, com funciona el protocol ARP

##### ATTACK PATH

1. Consider a network with three machines: the router, the victim’s machine and the attackers machine

2. L’atacant envía paquets ARP maliciosos tant a la màquina víctima (192.168.0.8) com al router (192.168.0.1).

3. A la màquina víctima se li diu que ara el router (192.168.0.1) será la nostra màquina (bb:bb:bb:bb:bb:bb), és a dir, se li assigna la nostra MAC a la direcció IP que pertanyie al router.

4. Al mateix temps se li diu al ruter que la màquina víctima som nosaltres. (192.168.0.8 now is at bb:bb:bb:bb:bb:bb)

5. Ara tota comunicación entra la màquina víctima i el ruter pot pasar per la nostra màquina.

6. Ara que les comunicacions passen per la nostra màquina, el procés de “forwarding” es pot escalar a altres protocols com el DNS, SSL …

##### DETECTION

Utilitzem wireshark amb uns filtres concrets per a detectar els paquets maliciosos.

1.      arp.opcode == 1

2.      arp.duplicate-address-detected && arp.code == 2

També podem utilizar un filtre per a descubrir quina IP està realitzant el spoof.

3.      (arp.opcode) and ((eth.src == MAC X) or (eth.dst == MAC X)

### B.2 ARP Scanning andDenial-of-Service

##### ARP SCANNING SIGNS

1. Broadcast ARP requests sent to sequential IP addressess ( .1, .2, .3, …)

2. Broadcast ARP requests sent to non-existent hosts

3. Potentially, an unusual volumen of ARP traffic from a malicious or compromised host

(+) Captura wireshark d’exemple

##### DENIAL-OF-SERVICE

1. Attacker’s ARP traffic may shift its focus  towards declaring new physical addresses for all live IP addresses

2. Duplicate allocation of 192-168.0.1

(+) Exemple: Captura Wireshark

##### RESPONDING TO ARP ATTACKS

1. Tracing and Identification: La màquina causant del atac ha d’estar físicament en algún lloc de la nostra red.

2. Containment: Considerem aïllar la part de la red afectada utilitzant el switch o ruter.

### B.3) 802.11 Denial of Service

Per tal d’examinar trafic d’aquest protocol necessitarem un sistema WIDS/WIPS, o una Wireless interface que soporti el monitor mode.

##### MONITOR MODE

1. ifconfig wlan0 down

2. iwconfig wlan0 mode monitor

3. ifconfig wlan0 up

##### DEAUTH ATTACK

Ens fem pasar per un “access point” legítim i enviem paquets de DEAUTH a la màquina víctima. Això provoca que aquesta es desconnecti de la red i pugem escalar l’atac, per exemple:

1.      Capturar el WPA handshake per fer forçabruta en local

2.      Per crear condicions de Denial of Service

3.      Per forçar als usuaris que es desconectin de la red i potencialment poder unir-nos a la red amb intencions malicioses

##### DETECTION (Deauth Attack)

Apliquem filtres a wireshark

1.      wlan.bssid == xx : xx : xx : xx : xx

2.      (wlan.bssid == xx : xx : xx : xx : xx) and (wlan.fc.type == 00) and (wlan.fc.type.subtype == 12)

3.      (2) and (wlan.fixed.reason_code == 7)

Els atacants intenten evadir la detecció canviant el reason_code. Així que també tenim que mirar el 1,2,3,…

##### PREVENTION (Deauth Attack)

1. Enable IEEE 802.11w (Management Frame Protocol) if posible.

2. Use WPA3-SAE

3. Modify our WIDS/WIPS detection rules.

### B.4) Rogue Access Point and Evil-Twin-Attack

Consisteix en crear un AccessPoint maliciós però que sigui identic al que l’usuari està conectat. En quan el desconectes de la red amb paquets deauth, aleshores potencialment es conecta al nostre AP maliciós.

## C) Detecting Network Abnormalities

### C.1 Fragmentation Attacks

En aquest nivel de red ens comuniquem amb ‘paquets’, els quals es composen de “fields”. Els atacants modifiquen uns fields específics de manera maliciosa.

## D) APPLICATION LAYER ATTACKS

### D.1 HTTPS/HTTPs Service Enumeration Detection

-> Inicialment, els atacants intentaran fer fuzzing al nostre servidor per recopilar informació abans de llançar un atac. És possible que ja disposem d'un Web Application Firewall per tal d'evitar-ho, però en alguns casos potser no, sobretot si aquest servidor és intern.

##### DETECTION (Directory Fuzzing)

-> Els atacants utilitzen el fuzzing de directoris per trobar totes les pàgines web i ubicacions possibles a les nostres aplicacions web. És simple de detectar ja que deixa senyals clares:
1. A host will repeatedly attempt to access files on our web server which do not exist (404).
2. A host will send it in rapid succession.

##### DETECTION (Other Fuzzing Techniques)

-> These techniques include fuzzing dynamic or static elements of our web pages such as id fields. O enaltres casos, l'atacant buscarà IDOR vulnerabilities, sobretot si utilitzem json parsing. 

-> Per detectar aquestes tecniques ens tenim que fixar en una ip concreta i analitzar les seves peticions:
`http.request and ((ip.src_host == <IP sospitosa>) or (ip.dst_host == <IP sospitosa>))`

-> A més a més, l'atacant farà sevir tècniques per evadir la detecció:

1. Stagger these responses across a longer period of time.
2. Send these responses from multiple hosts or source addresses.

##### PREVENTION

1. Tenir cura de la configuració del nostre virtualhost or web acces per tal que retorni els codis de resposta adequats per tal de confondre aquests escàners.
2. Establish rules to prohibit these IP addresses from accessing our server through our web application firewall.

### D.2 Strange HTTP Headers

-> Headers HTTP que mostren comportaments inusuals pot ser indicatiu d'activitats anòmales a la xarxa:

- Weired Hosts (Host:)
- Unusual HTTP verbs
- Changed User Agents

##### DETECTION (Strange Host Headers)

`http.request and (!(http.host == "192.168.10.7"))`

### D.3 Cross-site Scripting (XSS) and Code Injection Detection

-> Essentially speaking, cross-site scripting works through an attacker injecting malicious javascript or script code into one of our web pages through user input.

##### PREVENTION (XSS and Code Injection)
1. Sanitize and handle user input in an acceptable manner.
2. Do not interpret user input as code.

### D.4 SSL Renegotiation Attacks

-> És un dels atacs basats en HTTPs més comuns. L'atacant negocia la sessió amb el estàndard de xifratge més baix possible.

1. Handshake
2. Encryption
3. Further Data Exchange
4. Decryption

##### TLS and SSL Handshakes
![[Pasted image 20240607224639.png|600]]
1. **Client Hello** -> Initial step. Client sends its hello message to the server:

-  What TLS/SSL versions are supported by the client.
- List of cipher suites (aka encryption algorithms).
- Random data to be used in the following steps.

2. **Server Hello** -> Responding to the client Hello.

- Server's chosen TLS/SSL version.
- It's selected cipher suite from client's choices.
- Additional nonce.

3. **Certificate Exchange** -> El servidor demostra la seva identitat enviant el seu certificat digital al client. Aquest conté la "Server's public key".
4. **Key Exchange** -> El client genera el "premaster secret" i l'encripta amb la public key. Ho envia al servidor.
5. **Session Key Derivation** -> Both the client and the server use the nonces exchanged in the first two steps, along with the premaster secret to comput the session key. (Encriptació Simetrica).
6. **Finished Messages** -> Per verificar el handshake i que els dos tenen la key.

- The hash of all previous handshake messages.

7. **Secure Data Exchange** -> Client i servidor poden intercanviar data per un canal encriptat.


##### DETECTION
1. Multiple Client Hellos
2. Out of Order Handshake Message

-> Es genera una gran quantitat de tràfic DNS. És per això que les anomalies poden passar desapercebudes. Tanmateix, entendre i analitzar tràfic DNS és important en els nostres anàlisis de red.

##### DNS QUERIES
- Request -> Where is academy.hackthebox.com?
- Response -> Well its at 192.168.10.6

![[Pasted image 20240607230421.png|600]]

1. Query Initiation
2. Local Cache Chek
3. Recursive Query
4. Root Servers
5. TLD Servers
6. Authoritative Servers
7. Domain Name's Authoritative Servers
8. Response

##### DNS REVERSE QUERIES

- Request -> What is your name 192.168.10.6?
- Response -> Well its academy.hackthebox.com

![[Pasted image 20240607230523.png|600]]
1. Query Initiation
2. Reverse Lookup Zone
3. PTR Record Query
4. Response

##### DNS RECORD TYPES
- A (Address)
- AAAA (IPv6 Address)
- CNAME (Canonical Name)
- MX (Mail Exchange)
- NS (Name Server)
- PTR (Pointer)
- TXT (Text)
- SOA (Start of Authority)

##### DETECTION (DNS Enumeration Attempts)
-> We might notice a significant amount of DNS traffic from one host when we start to look at our raw output in wireshark.

##### DETECTION (DNS Tunneling)
-> We might notice a good amount of text records from one host. Attackers append the data they would like to exfiltrate as a part of the TXT file.

##### ATTACK PURPOSE
1. Data Exfiltration.
2. Command and Control.
3. Bypassing Firewalls and Proxies.
4. Domain Generation Algorithms (DGAs)

### D.6 Strange Telnet and UDP connections

. : : SOON : : . (ultim apartat)
