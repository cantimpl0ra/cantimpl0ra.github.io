---
layout: default
title: "YARA and Sigma for SOC Analysts"
nav_order: 12
parent: CDSA
---

# 12) YARA and SIGMA for SOC ANALYST

## A) INTRODUCTION

### A.1) Introduction to YARA and SIGMA

-> YARA and SIGMA are two essential tools used by SOC analyst to enhance their threat detection and incident response capabilities.

-> YARA excels in file and memory analysis, as well as pattern matching, where Sigma is particularly adept at log analysis and SIEM systems.

###### IMPORTANCE OF YARA AND SIGMA

1. Detecció d'amenaces millorada -> Aquestes regles permeten als analistes discernir patrons, comportaments o indicadors relacionats amb amenaces de seguretat, i axií els permeten detectar i abordar de manera proactiva possibles incidents.
2. Efficient Log Analysis -> Utilitzant les relges de Sigma, els analistes poden filtrar i correlacionar les dades de registre de fonts dispars, concentrant-se en els esdeveniments rellevants per al control de seguretat. Això minimitza les dades irrellevants i permet als analistes prioritzar els seus esforços d'investigació, donant lloc a una resposta als incidents més eficient i eficaç.
3. Collaboration and standarization -> YARA and Sigma offer standarized formats and rule structures, fostering collaboration among SOC analyst and tapping into the collective expertise of the broader cybersecurity community.
4. Integration with Security Tools -> YARA and Sigma rules can be integrated seamlessly with a plethora of security tools, including SIEM platforms, log analysis systems, and incident response platforms.
5. Malware Detection and Classification -> Leveraging YARA rules, analysts can create specific patterns or signatures that correspond to known malware traits or behaviors.
6. Indicator of Compromise (IOC) Identification

## B) LEVERAGING YARA

### B.1 YARA and YARA Rules

##### USAGE OF YARA
- Malware detection and classification
- File analysis and classification
- IOC detection
- Community-driven rule sharing
- Create custom security solutions
- Custom YARA signatures/rules
- Incident response
- Proactive threat hunting

##### HOW YARA WORKS

(+) DIAGRAMA EXPLICATIU

1. Set of Rules -> Aquestes regles defineixen patrons (strings, RE, byte sequence, etc) els quals després buscarem coincidencies en els fitxers.
2. Set of Files -> Es proporcionen un conjunt de fitxers com a input al motor d'escaneig YARA.
3. YARA Scan engine -> Utilitza mòduls YARA(conjunt d'algoritmes i tècniques) per comprar de manera eficient el contingut dels fitxers amb els patrons especificats a les regles.
4. Scanning and Matching -> Analitza els fitxers byte a byte.
5. Detection of Files -> Quan un fitxer coincideix amb els patrons i condicions especificats en una regla YARA, es considera un fitxer detectat.

##### YARA RULE STRUCTURE

0. Keywords reserved
1. Header -> the rule header provides metadata and identifies the rule.
2. Meta -> The rule meta section allows for the definition of additional metadata for the rule
3. Body -> The rule body contains the patterns or indicators to be matched within the files
4. Conditions -> Rule conditions define the context or characteristics of the files to be matched

### B.2 Developing YARA Rules

-> Let's dive into the world of YARA rules using a sample named svchost.exe. We want to understand the process behind crafting a YARA rule, so let's get our hands dirty.

**EXAMPLE 0: svchost.exe**
1. String analysis on our malware samples: `strings svchost.exe`
2. From the first few strings, it is evident that the file is packed using the UPX (Ultimate Packer for eXecutables) packer. Given this discovery, we can incorporate UPX-related strings to formulate a basic YARA rule targeting samples packed via UPX: `rule UPX_packed_executable`
3. Our UPX_packed_executable rule scans for the strings UPX0, UPX1, and UPX2 inside a file. If the rule finds all three strings, it raises an alert, hinting that the file might be packed with the UPX packer.

**EXAMPLE 1: dharma_sample.exe + yarGen**

1. Strings analysis.
2. yarGen is our go-to tool when we need and automatic YARA rule generator. What makes it a gem is  its ability to churn out YARA rules based on strings found in malicious files while side stepping strings common in benign software.

	(+) Installation + Tutorial of yarGen

**EXAMPLE 2: ZoxPNG RAT + Manually Developing**

-> We want to develop a YARA rule to scan for a specific variation of the ZoxPNG RAT used by APT17 based on:
- A sample named legit.exe
- A post from Intezer
- String analysis
- Imphash
- Common sample file size

1. String analysis
2. Let's then use the hashes mentioned in Intezer's post to indentify common sample sizes. The sample's Imphash can be calculated as follows, using the imphash_calc.py: `python3 imphash_calc.py legit.exe`
3. Ja tenim tota la info per desarrolar la YARA rule.

### B.3 Hunting Evil with YARA(Windows)
##### ON DISK(executables)

-> With custom YARA rules or established ones at our disposal, we can pinpoint suspicious or potentially malicious files based on distinct patterns, traits, or behaviors.

(+) EXEMPLE DEL PROCES:

1. We'll first examine the malware sample inside a hex editor.

![[Pasted image 20240511182455.png|600]]
2. Going forward, we will craft a rule grounded in these patterns and then utilize the YARA utility to scour the filesystem for similar executables

```yara
rule ransomware_dharma {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"

    strings:
        $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }

        condition: all of them
}
```
##### RUNNING PROCESSES

-> To ascertain if malware lurks in ongoing processes, we will unleash the YARA scanner on the system's active processes.

-> Let's demonstrate using a YARA rule that targets Metasploit's meterpreter shellcode, believed to be lurking in a running process.

```yara
rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        5 of them
}
```

![[Pasted image 20240511182935.png]]

##### EVENT TRACING for WINDOWS (ETW) DATA

-> In this section we'll circle back to ETW data, highlighting how YARA can be used to filter or tag certain events

-> SilkETW is an open-source tool to work with Event Tracing for Windows (ETW) data. SilkETW provides enhanced visibility and analysis of Windows events for security monitoring, threat hunting, and incident response purposes.

(+) EXEMPLE amb silkETW -- *video exemple*

##### EXAMPLE 1: YARA rule scanning on Microsoft-windows-Powershell ETW Data

##### EXAMPLE 2: YARA rule scanning on Microsoft-DNS-client ETW Data

### B.4 Hunting Evil with YARA (Linux)

-> Com a security analyst ens trobarem amb la situació que salta l'alarma a una màquina remota a la qual no hi tenim accés directe. Però això no vol dir que no podem fer-hi res; ens poden enviar una captura de la memòria i així rebre una instantània de tot allò que passa al sistema en un moment concret.

-> We can run YARA-based scans directly on these memory images. It's like having x-ray vision: we can peer into the state of the system, looking for signs of malicious activity or compromised indicators.

##### WITHIN MEMORY IMAGES

1. Create YARA Rules.
2. Compile YARA Rules.
3. Obtain memory images -> Per tal de capturar instantànies de la memòria utilitzarem eines com DumpIt, MemDump, Belkasoft RAM capturer, Magnet RAM Capture, FTK Imager, LiME.
4. Memory scanning with YARA.


-> El  "Volatility Framework" és una potent eina forense de memòria de codi obert que s'utilitza per analitzar imatges de memòria de diversos sistemes operatius. YARA es pot integrar al framework de Volatility com un connector anomenat yarascan que permet l'aplicació de regles YARA a l'anàlisis de memòria.

### B.5 Hunting Evil with YARA (web edition)

-> Unpac.Me is a tool tailored for malware unpacking. The great thing about Unpac.Me is that it grants us the capability to run our YARA rules over their amassed database of malware.

-> For individuals and organizations with limited resources, Unpac.Me and similar platforms can serve as stepping stones to enhance their malware analysis and detection capabilities, enabling them to make meaningful contributions to the field of cibersecurity.

## C) LEVERAGING SIGMA
### C.1 Sigma and Sigma rules

-> Sigma is a generic signature format used for describing detection rules for log analysis and SIEM systems.

-> Permet als SOC analysts crear i compartir regles (normalment escrites en format YAML) que ajudin a identificar patrons o comportaments especifics indicatius d'amenaces de seguretat o activitats malicioses.

-> SOC analysts use Sigma rules to define and detect security events by analyzing log data generated by various systems, such as firewalls, intrusion detection systems, and endpoint protection platforms.

-> The main advantage of Sigma rules is their probability and compability with multiple SIEM and log analysis systems, enabling analysts to write rules once and use them across different platforms.

-> With "sigmac", we can take a rule written in the Sigma format and translate it for ElasticSearch, QRadar, Splunk, and many more, almost instantaneously.

⚠️  pySigma is increasingly becoming the go-to option for rule translation, ad sigmac is now considered obsolote.

##### USES OF SIGMA
- Universal Log Analytics Tool
- Community-driven Rule Sharing
- Incident response
- Proactive threat hunting
- Seamless Integration with automation Tools
- Customization for Specific Environments
- Gap identification


##### SIGMARULE STRUCTURE

- Title -> Title of the rule showing what the rule is supposed to dectect.
- Id -> Globally Unique Identifier (randomly generated UUIDs)
- Status -> State of the rule (i.e. Stable, test, experimental, deprecated, unsupported)
- Description and References: More info on the objective of the rule and the activity that can be detected.
- Author, Date
- Tags: Context and info to categorize the rule
- Logsource: Describes the log data on which detection rule is meant to be applied to.
- Detection: Set of search-identifiers that represent properties of searches on log data
- False Positives: Known false positives taht may occur.
- Level: Describes the criticality of triggered role.

(+) SIGMA RULE DEVELOPMENT BEST PRACTICES.
