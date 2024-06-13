---
layout: default
title: "Understanding Log Sources & Investigating with Splunk "
nav_order: 5
parent: CDSA

---

# 5.0) Understanding Log Sources & Investigating with Splunk

## A) Splunk Fundamentals

### A.1 Introduction to Splunk and SPL

-> Splunk és un software (escalable, versàtil i robust) d’anàlisis de daes de forma massiva. És a dir, processa les dades generades per totes les màquines del sistema.

##### ARQUITECTURA

-> Consisteix en diferentes capes que treballen conjuntament per a recollir, indexar, buscar, analitzar i visualitzar dades.

1. Forwarders: Collect and Send
2. Indexer: Data Store/Processing
3. Search Head: Splunk’s UI
4. Deployment Server
5. Cluster Master
6. License Master

##### COMPONENTS

- Splunk Web Interface
- Search Processing Language (SPL)
- Apps and Add-ons
- Knowledge Objects

-> Splunk juga un rol crucial com a “SIEM solution.

-> SPL és la columna vertebral de l’anàlisis de dades amb Splunk.

##### SPL EXAMPLES

1. Basic searching
2. Fields and Comparison Operators
3. Fields command
4. Table command
5. Rename command
6. The dedup command
7. The sort command
8. The stats command
9. The chart command
10. The eval command
11. The rex command
12. The lookup command
13. The input lookup command
14. Time range
15. The transaction command
16. Subsearches

(+) EXAMPLES 1 i 2 - video amb els exemples

### A.2 Using Splunk Applications

-> Gràcies a les aplicacions podem afegir capacitats addicionals en funció del software que vulguem gestionar.

*l Tutorial de com descargar , afegir i utilitzar una aplicació amb Splunk l*

## B INVESTIGATING WITH SPLUNK

-> Tenim tres exemples pràctics que ens ajudaran a aprendre a utilitzar Splunk

B.1 Intrusion detection w/ Splunk

B.2 Detecting Attacker Behavior w/ Splunk based on TTPs

B.3 Detecting Attacker Behavior w/ Splunk based on Analytics

*l video amb els exercisis l*
