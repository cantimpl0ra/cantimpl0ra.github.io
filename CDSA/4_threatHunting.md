---
layout: default
title: "Threat Hunting & Hunting with Elastic"
nav_order: 4
parent: CDSA

---

## A THREAD HUNTING and THREAT INTELLIGENCE

### A.1 Threat Hunting Fundamentals

-> Per tal de detectar les intrusions abans, es pren la decisió de realitzar una búsqueda activa per part de l’equip de seguretat.

-> El procés comença amb la identificació dels assets que puguin ser objectius valuosos. Seguidament, analitzem els TTPs en funció dels assets trobats. Finalment, reforcem la seguretat per a fer front a aquests TTPs determinats.

##### INCIDENT HANDLING vs THREAT HUNTING

- **Preparation** : L’equip de TH estableix unes normes clares i robustes. És a dir, estableix un protocol d’actuació.
- **Detection and Analysis** : Por ajudar a detectar artefactes o indicadors de compromís addicionals.
- **Containment, Erradication and Containment** : Queda recollit en els protocols les funcions de l’equip TH.
- **Post-incident activity** : L’equip de TH pot oferir recomanacions per a fortificar la seguretat general de l’organització

##### TEAM’S STRUCTURE

- Threat Hunter
- Threat Intelligence Analyst
- Incident Responder
- Forensics Expert
- Data Analyst/Scientits
- Security Engineer/Architects
- Network Security Analyst
- SOC Manager

-> Tot i que el threat hunting es realitza constantment, hi ha situacions on s’ha d’intensificar la feina:

- Quan es descobreixen noves vulnerabilitats o adversaris.
- Quan nous indicadors son associats a un adversari conegut.
- Quan es detecten diverses anomalies en la red.
- Durant el “Incident Response Activity”.
- Accions proactives periòdiques.

##### RISK ASSESSMENT vs THREAT HUNTING

-> La informació recopilada pel Risk Assessment ens pot ajudar de diverses formes:

- Prioritzar els recursos de hunting en els assets crítics
- Entendre millor el threat landscape
- Highlighting vulnerabilities
- Ens informa sobre l’ús de threat intelligence
- Ens ajuda a tenir un millor Incident Response plan
- Millora els controls de ciberseguretat en global

### A.2 Threat Hunting Process

1. **Setting the Stage** : Engloba la planificació i preparació. Estableix objectius clars basats en una comprensió profunde del “threat landscape”, els nostres coneixmentes de “threat intelligence” i els requeriments de la nostra empresa.

2. **Formulating Hypotheses** : Realitzem prediccions educades que ens guiaran en el camí del threat hunting. Ens podem basar en un threat intelligence recent, actualitzacions en la industria, alertes de seguretat o la nostra intuïció professional.

3. **Designing the Hunt** : Un cop feta la hipòtesis necessitem establir una estratègia que resolgui quines son els fonts específiques a analitzar, les metodologies i eines a fer servir i els IoCs particulars a fer-lis hunting.

4. **Data Gathering and Examination** : És la part activa on l’equip recopila i analitza les dades.

5. **Evaluating Findings and Testing Hypotheses** : En aquesta fase l’equip evalua els resultats dels anàlisis realitzats per a confirmar o regusar la hipòtesis feta anteriorment.

6. **Mitigating Threads** : Fase on es realitzen accions immediates per tal de mitigar les infeccions. Aillem, els sistemes infectats, de la red i reforcem la protecció ens els endpoints.

7. **After Hunt** : Un cop el hunting cycle és finalitzat, l’equip documenta tota la informació rellevant. Actualitzen el threat intelligence amb els nous IoCs trobats. Finalment, actualitzen els protocols per a millorar la seguretat global de l’empresa.

8. **Continuous Learning and Enhancement** : Each threat hunting cycle should feed into the next, proporcionant una constant millora i creixement

### A.3 Threat Hunting Glossary

 - Adversary

- Advanced Persistent Thread (APT)

- Tactics, Techniques and Procedures (TTP)

- Indicator

- Threat (intent, capability and opportunity)

- Campaign

- Indicators of Compromise (IoC)

- Pyramid of Pain

- Diamond Model

### A.4 Threat Intelligence Fundamentals

Cyber Threat Intelligence (CTI) representa un asset molt important en les nostres defenses. Ens permet utilitzar estratègies més proactives.

Conceptes clau:
- Rellevancia
- Temps 
- Accionabilitat
- Precisió

##### Threat Intelligence vs Threat Hunting

- **Threat Intelligence :** (Predictiva) L’objectiu aquí és anticipar els moviments de l’adversari, determinar els seus objectius i discernir els sous mètodes d’adquisició d’informació

- **Threat Hunting :** ( Reactiu i Proactiu ) Un esdeveniment o incident inicial fa que el nostre equip comenci una operació per comprovar si hi ha un adversari a la xarxa o si n’hi havia un i va evitar la detecció.

## B THREAD HUNTING WITH THE ELASTIC STACK

### B.1 Hunting for Stuxbot

(+) EXEMPLE LLARG

l video amb l'exemple i els exercisis l
