---
layout: default
title: "Windows Event Logs & Finding Evil"
nav_order: 3
parent: CDSA

---

## A) INTRODUCTION

### A.1 Windows event logs

-> Son una part intrínseca del sistema operatiu i proporcionen informació dels events que succeeixen per tal que l’equip de seguretat la pugi investigar i detectar intrusions

-> Els logs son fitxers “.evtx” els quals es poden visualitzar mitjançant el “Event Viewer” de Windows.

##### TIPUS DE LOGS

- Aplication
- Security
- Setup
- System
- Forward Events

##### ANATOMY OF AN EVENT LOG

1. Log Name
2. Source
3. Event ID
4. Task Category
5. Level (severity of the event
6. Keywords (molt útil per a filtrar)
7. User
8. Opcode
9. Logged
10. Computer
11. XML Data

-> Podem crear "XML quèries" per identificar events relacionats, utilitzant el “Logon ID” com a punt de partida.

[Exemple d'un log.](https://www.youtube.com/shorts/YUvzfhvZbA4)

##### WINDOWS EVENT LOGS

- Windows System Logs
	- [Event ID 1074](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock) `(System Shutdown/Restart)`
	- [Event ID 6005](https://superuser.com/questions/1137371/how-to-find-out-if-windows-was-running-at-a-given-time) `(The Event log service was started)`
	- [Event ID 6006](https://learn.microsoft.com/en-us/answers/questions/235563/server-issue) `(The Event log service was stopped)`
	- [Event ID 6013](https://serverfault.com/questions/885601/windows-event-codes-for-startup-shutdown-lock-unlock) `(Windows uptime)`
	- [Event ID 7040](https://www.slideshare.net/Hackerhurricane/finding-attacks-with-these-6-events) `(Service status change)`
- Windows Security Logs
	- [Event ID 1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102) `(The audit log was cleared)`
	- [Event ID 1116](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus malware detection)`
	- [Event ID 1118](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus remediation activity has started)`
	- [Event ID 1120](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus remediation activity has failed)`
	- [Event ID 4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624) `(Successful Logon)`
	- [Event ID 4625](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625) `(Failed Logon)`
	- [Event ID 4648](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4648) `(A logon was attempted using explicit credentials)`
	- [Event ID 4656](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4656) `(A handle to an object was requested)`
	- [Event ID 4672](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4672) `(Special Privileges Assigned to a New Logon)`
	- [Event ID 4698](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4698) `(A scheduled task was created)`
	- [Event ID 4700](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4700) & [Event ID 4701](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4701) `(A scheduled task was enabled/disabled)`
	- [Event ID 4702](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4702) `(A scheduled task was updated)`
	- [Event ID 4719](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4719) `(System audit policy was changed)`
	- [Event ID 4738](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4738) `(A user account was changed)`
	- [Event ID 4771](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4771) `(Kerberos pre-authentication failed)`
	- [Event ID 4776](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4776) `(The domain controller attempted to validate the credentials for an account)`
	- [Event ID 5001](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) `(Antivirus real-time protection configuration has changed)`
	- [Event ID 5140](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5140) `(A network share object was accessed)`
	- [Event ID 5142](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5142) `(A network share object was added)`
	- [Event ID 5145](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5145) `(A network share object was checked to see whether client can be granted desired access)`
	- [Event ID 5157](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5157) `(The Windows Filtering Platform has blocked a connection)`
	- [Event ID 7045](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=7045) `(A service was installed in the system)`

[Recovering Windows Event Logs from a Memory Dump](https://www.youtube.com/watch?v=8fykZocCRqo&ab_channel=Moss%C3%A9CyberSecurityInstitute)

##### EXERCISIS
l video amb els exercisis (soon) l

### A.2 Analyzing Evil with Sysmon and Event Logs

-> Per a millorar la nostra cobertura de “EventLogs” podem ampliar les capacitats incorporant SYSMON, el qual ofereix capacitats addicionals de “Event Logging”

-> És un servei del sistema i un controlador de dispositiu, de Windows el qual es manté tot i reiniciar el sistema. Monitoreja i registra l’activitat del sistema al “Windows event log”.
##### COMPONENTS

- Windows service for monitoring System activity.
- A device driver that assists in capturin the System activity data.
- An event log to display captured activity data.

-> SYSMON categoritza les diferentes activitats del sistema amb ids: “EventID X”. Per exemple aquí veiem el EventID 10:

![[z(3) LogExample.png|600]]

[Full list of sysmon event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

Detection Example 1: Detecting DLL Hijacking

Detection Example 2: Detecting Unmanaged Powershell/C-Sharp Injection

Detection Example 3: Detecting Credential Dumping
##### PRACTICAL EXERCISES
l video amb els exercisis l

## B) Additional Telemetry Sources

### B.1 Event Tracing for Windows (ETW)

-> És una utilitat de propòsit general que proporciona el SO. Realitza un seguiment a alta velocitat ja que està implementat al Kernel.

-> L’[ETW](https://www.youtube.com/shorts/iaeWVzEBaUY) proporciona informació addicional a la clàssica que ofereixen els logs.

-> És molt lleuger i casi no gasta recursos del sistema. A més a més, s’adapta moltbé als proveïdors d’esdeveniments.

##### ARCHITECTURE and COMPONENTS

![[z(3) Diagrama ETW.png|600]]

- **Controladors** : assumeix el control de les operacions.
- **Proveidors** : encarregats de generar i transmetre diversos events.
- **Consumers**: és on es transmet la info generada per el proveïdor. Normalment un arxiu .etl.
- **Channels** : organitzen els events
- **ETL files** : tipus d’arxiu on s’escriuen els events.

-> “Logman.exe” és una utilitat pre-instalada a Windows per a gestionar l’ETW. Tot i que també existeixen alternatives com la interfície gràfica de "Montiro de Recursos" o el [EtwExplorer](https://github.com/zodiacon/EtwExplorer).

### B.2 Tapping into ETW

**Detection Example 1: Strange Parent-Child Relationship***

**Detection Example 2: Malicious .NET Assembly Loading***

##### PRACTICAL EXERCISES
l video amb els exercisis l



## C ANALYZING WINDOWS EVENT LOGS EN MASSE

### C.1 Get-WinEvent

-> És una eina indispensable per a analitzar una gran quantitat de logs. Ens proporciona la capacitat de filtarr els logs d’una manera molt sofisticada.

[Video exemple.](https://www.youtube.com/watch?v=qip9heIiB2w&ab_channel=TechSnipsbyATALearning)
##### PRACTICAL EXERCISES
l video amb els exercisis 1-8 l

