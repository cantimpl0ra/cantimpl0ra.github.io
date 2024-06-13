---
layout: default
title: "Security Monitoring and SIEM Fundamentals"
nav_order: 2
parent: CDSA

---


## A) SIEM and SOC FUNDAMENTALS

### A.1 SIEM definition and Fundamentals

-> Security Information and Event Management (SIEM) engloba l’utilització de software el qual proporciona solucions i capacitats de gestionar la seguretat de les dades i la supervisió de events.

-> El SIEM neix el 2005 de la fusió del SIM i el SEM

-> El SIEM recopila informació de diferents dispositius, la qual és analitzada pels professionals per tal de detectar potencials incidents.

##### REQUISITS + USOS

- Log Aggregation and Normalization
- Threat Alerting
- Contextualization and Response
- Compliance

##### DATA FLOWS

1. SIEM “ingereix” registres de diverses fonts.
2. Les dades són processades i normalitzades per a q es pugin entendre en els diferents eines del SIEM.
3. SOC teams utilitza aquestes dades ja processades per a crear “normes de detecció”.

### A.2 Introduction to ElasticStack

-> *ELK Elastic Stack explained: [https://www.youtube.com/watch?v=4X0WLg05ASw](https://www.youtube.com/watch?v=4X0WLg05ASw)*

-> Framework open-source que s’utilitza per l’exploració i anàlisis en temps real dels logs. Consta principalment de 3 applicacions:

 1. BEATS + LOGSTASH : Ingest
 2. ELASTICSEARCH : Emmagatzema, busca i analitza
 3. KIBANA : Visualització

##### KIBANA QUERY LANGUAGE (KQL)

[https://www.youtube.com/watch?v=wfqItAlUy8g](https://www.youtube.com/watch?v=wfqItAlUy8g)

-> És el llenguatge de consulta utilitzat per Kibana. Aquest permet als usuaris realitzar consultes avançades a les dades indexades a Elasticsearch per filtrar i buscar informació específica. Té les següents característiques:

- **Estructura bàsica** : Les “quèries” de KQL estan fetes principalment per field:value. Ex: event.code:4625

- **Free text search** : Podem buscar per string, sense especificar el camp “field”

- **Logical Operators**

- **Wildcards and Regular Expressions**

### A.3 SOC Definition and Fundamentals

-> Un Security Operations Center (SOC) és un conjunt de professionals i tecnologies, que treballen conjuntament, amb l’objectiu de millorar constantment la seguretat.

##### ROLS

- SOC Director
- SOC Manager
- Tier 1,2,3 Analyst
- Detection Engineer
- Incident Responder
- Threat Intelligence Analyst
- Security Engineer
- Compliance and Governance Specialist
- Security Awarness and Training Coordinator

##### [SOC 1 vs SOC 2 vs SOC 3](https://www.youtube.com/watch?v=SXqG_gqVk1g)

IMAGEN !!!!!!

### A.4 MITRE ATT&CK and SECURITY OPERATIONS

-> Adversarial Tactics, Techniques and Common Knowledge ([ATT&CK](https://www.youtube.com/watch?v=GYyLnff2XRo)) és un recurs, constantment actualitzat, de les tècniques i procediments (TTPs) utilitzades pels “cyber threats actors”.

##### USE CASES

 - Detection and Response
 - Security evaluation and Gap Analysis
 - SOC Maturity Assessment
 - Threat Intelligence
 - Cyber Threah Intelligence Enrichment
 - Behavioral Anlytics Development
 - Red Teaming and Penetration Testing
 - Training and Education

### A.5 SIEM Use Case Development

-> Els *"Use Cases"* estan dissenyats per a il·lustrar situacions on un producte o servei pugui ser utilitzat

##### DEVELOPMENT LIFECYCLE

1. Requirements
2. Data Points
3. Log Validation
4. Design and Implementation
5. Documentation
6. Onboarding
7. Periodic Update/Fine-tuning


## B) SIEM VISUALIZATION DEVELOPMENT

	*Video amb la resolució dels exercisis.*

## C) ALERT TRIAGING
### C.1 Triaging Process

1. Initial Alert Review
2. Alert Classification
3. Alert Correlation
4. Enrichment of Alert Data
5. Risk Assessment
6. Contextual Analysis
7. Incident Response Planning
8. Consultation with IT Operation
9. Response Execution
10. Escalation
11. Coninuous Monitoring
12. De-escalation

*[Videoexplicació del procés de triatge d'una alerta.](https://www.youtube.com/watch?v=KQKo-NV9Iag)*
