---
layout: default
title: "Javascript Deobfuscation"
nav_order: 11
parent: CDSA

---

# 11) Javascript Deobfuscation

### A) INTRODUCTION

-> Sovint ens trobem amb codi ofuscat que vol amagar determinades funcionalitats, com ara programari maliciós el qual utilitza Javascript ofuscat.

-> En aquest mòdul començarem aprenent l'estructura general d'una pàgina HTML i després localitzarem el codi JS dins d'ella. Un cop ho fem, aprendrem què és l'ofuscament, com es fa i on s'utilitza. També veurem tècniques per desofucsar.

####  A.2 Source code

-> HTML is used to determine the website's main fields and parameters, and CSS is used to determine its design, JS is used to perform any functions necessary to run the website.

## B) OBFUSCATION

#### B.1 Code Obfuscation

-> L'ofuscament és una tècnica utilitzada per a fer que unguió sigui més difícil de llegir pels humans però permet que funcioni igual desde un punt de vista tècnic.

-> Normalment, això s'aconsegueix automàticament mitjançant una eina d'ofuscament, la qual pren el codi com a input.

#### B.2 Basic Obfuscation

-> Existeixen diverses tècniques i eines automatitzades les quals realitzen aquesta tasca però els cibercriminals o els dessarrolladors professionals creen les seves propies eines d'ofuscació.

#### B.3 Advanced Obfuscation

-> Hi han eines més avançades d'ofuscació com per exemple:
- Obfuscator (obfuscator.io)
- JSF (https://jsfuck.com/)
- AA encode (https://utf-8.jp/public/aaencode.html)
- JJ encode (https://utf-8.jp/public/jjencode.html)

#### B.4 Deobfuscation

-> De la mateixa manera que hi han eines per ofuscar el codi, també n'hi ha que tel desofusquen automàticament.

###### BEAUTIFY
-> Utilitzem firefox + CTRL,SHIFT,Z

**DEOBFUSCATE**
-> UnPacker



## C) DEOBFUSCATION EXEMPLES

#### C.1 Code Analysis

(+) Exemple on s'analitza codi javascript (secret.js)

#### C.2 HTTP Requests

-> In the previous section, we found out that the secret.js main function is sending an empty POST request to /serial.php. In this section, we will attempt to do the same using cURL to send a POST request to /serial.php

-> curl http:/ SERVER_IP:PORT/serial.php -X POST -d "param1=sample"

#### C.3 Decoding

Quan detectem codi encriptat, lo primer és saber quina encriptació han fet servir. Per saber això ens podem fixar en determinats detalls característics:

- Base64 -> Spotting Base64 (=)
- hex -> Spotting hex (0-9 i a-f)
- rot13 -> Spotting rot13 (http ://www = uggc ://jjj)

-> If you face any similar types of encoding, first try to determine the type of encoding, and then look for online tools to decode it.(cypher identifier is an example)
