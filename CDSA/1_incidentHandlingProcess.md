---
layout: default
title: "Incident Handling Process"	
nav_order: 1
parent: CDSA
---

# 1.0) Incident Handling Response

## A) INTRODUCTION

### A.1 Definicions
- **Event:** Acció que passa en un sistema. Exemple: Un usuari envia un correu electrònic, un clic del ratolí, un firewall autoritzant una connexió.

- **Incident:** És un event amb repercussions negatives. Exemple: Dades robades, accés sense autorització, instal·lació i execució de malware.

- **Incident Handling:** Conjunt d'accions prèviament definides amb claredat amb l'objectiu de gestionar els incidents de seguretat en una empresa (xarxa).

⚠️ Un dels recursos més utilitzats en IH és el document [NIST’s Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf).

### A.2 Cyber Kill Chain

A.k.a the attack lifecycle descriu com els atacs es manifesten en un sistema. Consta de 7 fases:

- Fase 1: **Recon.** És la fase inicial i consisteix en recopilar informació i triar el target. Pot esser pasiva o activa.
    
- Fase 2: **Weaponize**. Es desenvolupa el malware que serà utilitzat per a guanyar accés. Aquest és incorporat en un exploit i/o payload amb l’objectiu d’aconseguir accés remot a la màquina target de manera “indetectable” pel EDR i persistent.
    
- Fase 3: **Delivery**. L’exploit o el payload és lliurat a la victima. Normalment es fa mitjançant phishing, però hi han altres tècniques com la de deixar un USB maliciós, la intrusió fisica, etc…
    
- Fase 4: **Exploitation**. S’activa el payload o exploit lliurat.
    
- Fase 5: **Installation**. The initial stager is executed and is running on the compromised machine
    
- Fase 6: **Command Control**. L’atacant estableix la connexió remota amb la màquina compromesa.
    
- Fase 7: **Action and Objectives**. L’atacant executa l’objectiu de l’atac, ja sigui exfiltració de dades, ransomware, escalada de privilegis, etc.
    
⚠️ El nostre objectiu és que l’atacant no progressi en aquesta cadena.

[Video explicació Cyber Kill Chain](https://www.youtube.com/watch?v=II91fiUax2g&ab_channel=TheCISOPerspective)

## B) THE INCIDENT HANDLING PROCESS

### B.1 Incident Handling Process Overview

Defineix la capacitat que té una organització per preparar-se, detectar i respondre a events maliciosos. Segons el NIST(link) consta de 4 fases:

- Fase 1: **Preparation (1)**. Té l’objectiu d’establir la capacitat de gestionar incidents en una organització. A més a més, també s’estableix protecció de manera preventiva. Requisits: Treballdors qualificats, Programa d’entre …
    
- Fase 1: **Preparation (2)**. Aquí enfatitzem la protecció contra incidents. Mesures de protecció recomanades: DMARC(email), Endpoint Hardening(EDR), Network protection, privilege identity management / MFA / Passwords, Vulnerability Scanning, User Awarness Training, Active Directory Security Assessment, Purple Team exercises.
    
⚠️ En aquest punt ja tenim un protocol establert contra incidents.

- Fase 2: **Detection and Analysis (1)**: Aquesta fase implica tots els aspectes relacionats amb la detecció d’un incident. És molt recomanable crear nivells de detecció categoritzant la nostra red :
	- Network Perimeter -> firewall, DMZ, etc
	- Network internal level -> local firewalls, host intrusion detection system, etc
	- Endpoint level -> antivirus, EDR
	- Application level -> Application logs, service logs, etc
- Fase 2: **Detection and Analysis (2)**: Quan es comença una investigació l’objectiu és detectar què i com ha passat. La investigació comença amb la informació que ha fet detectar l’incident. Amb aquesta info iniciarem un 3-step cyclic process, el qual anirem iterant.

	IMAGE

- Fase 3: **Containment, Erradicarion and Recovery**. Quan la investigació és completada i ja entenem quin tipus d’incident estem tractant és el moment de contenir. És a dir, prevenir que l’incident faci més mal.
	- Contenció: Prenem acció per a que l’incident no s’escampi més
	- Erradicació: Un cop contingut l’incident passem a eliminar allò que ha provocat l’incident i ens assegurem que l’atacant està completament fora del sistema.
	- Recuperació. Tornem el sistema un altre cop a la normalitat. Incrementem la protecció i el monitoreig dels dispositius/sistems atacats.

- Fase 4: **Post-Incident Activity**. En aquesta fase el nostre objectiu és documentar l’incident de manera que l’empresa pugui prendre mesures i millorar les defenses. Això es fa mitjançant un report tècnic i reunions amb els equips. En aquesta fase podem aprofitar per formar nous treballdors.

[Videoexplicació incident handling process](https://www.youtube.com/watch?v=ToVVhMyU3dQ&ab_channel=CyberGrayMatter)






















