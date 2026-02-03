# roadmap-for-cyber-security-becase-software-engineering-is-dead

# 🔴 ULTIMATE 18-MONTH RED TEAM ENGINEER ROADMAP 🔴
## From ITSM Engineer to Elite Red Team Operator

**Target:** Land a Red Team Engineer/Offensive Security Engineer role
**Time Commitment:** 10 hours/day, 5 days/week (50 hours/week)
**Total Hours:** ~3,900 hours of pure red team training
**Philosophy:** Learn by DOING, break things, build things, become dangerous

---

## 📋 QUICK NAVIGATION
- [Phase 1: Foundation (Months 1-4)](#phase-1-foundation-months-1-4)
- [Phase 2: Offensive Operations (Months 5-9)](#phase-2-offensive-operations-months-5-9)
- [Phase 3: Advanced Red Team (Months 10-14)](#phase-3-advanced-red-team-months-10-14)
- [Phase 4: Expert & Job Ready (Months 15-18)](#phase-4-expert--job-ready-months-15-18)
- [Essential Tools & Resources](#essential-tools--resources)

---

## PHASE 1: FOUNDATION (Months 1-4)
*Build the absolute fundamentals - No shortcuts here*

### MONTH 1: Linux Warfare & Network Mastery

**Week 1-2: Linux Deep Dive**
- **TryHackMe**:
  - Linux Fundamentals Part 1: https://tryhackme.com/room/linuxfundamentalspart1
  - Linux Fundamentals Part 2: https://tryhackme.com/room/linuxfundamentalspart2
  - Linux Fundamentals Part 3: https://tryhackme.com/room/linuxfundamentalspart3
  - Linux Privilege Escalation: https://tryhackme.com/room/linprivesc
  - Linux PrivEsc: https://tryhackme.com/room/linuxprivesc
- **Hack The Box Academy** (Tier 0 - FREE):
  - Linux Fundamentals: https://academy.hackthebox.com/course/preview/linux-fundamentals
  - Linux File System: https://academy.hackthebox.com/module/details/18
- **Practice**:
  - Set up Kali Linux as your main OS
  - Build a home lab with VirtualBox/VMware
  - Install: Ubuntu, Kali, ParrotOS, Debian
  - Master: vim, tmux, ssh, netcat, socat
- **Reading**:
  - The Linux Command Line (free PDF): http://linuxcommand.org/tlcl.php
  - Linux Journey: https://linuxjourney.com/

**Week 3-4: Networking for Hackers**
- **TryHackMe**:
  - Introductory Networking: https://tryhackme.com/room/introtonetworking
  - What is Networking?: https://tryhackme.com/room/whatisnetworking
  - Intro to LAN: https://tryhackme.com/room/introtolan
  - Protocols and Servers: https://tryhackme.com/room/protocolsandservers
  - Network Services: https://tryhackme.com/room/networkservices
  - Network Services 2: https://tryhackme.com/room/networkservices2
  - Wireshark 101: https://tryhackme.com/room/wireshark
- **HTB Academy**:
  - Introduction to Networking: https://academy.hackthebox.com/course/preview/introduction-to-networking
- **Hands-on**:
  - Capture packets with Wireshark
  - Build network diagrams
  - Set up VLANs in home lab
  - Practice port forwarding, tunneling
- **Book**: TCP/IP Illustrated Vol 1 (read first 5 chapters)

**Daily Structure:**
- 6:00-9:00 AM: Theory (TryHackMe/HTB courses)
- 9:00-12:00 PM: Hands-on labs
- 12:00-1:00 PM: Break
- 1:00-4:00 PM: Home lab building
- 4:00-6:00 PM: Documentation & writeups

---

### MONTH 2: Programming & Scripting Arsenal

**Week 1-2: Python for Hackers**
- **TryHackMe**:
  - Python Basics: https://tryhackme.com/room/pythonbasics
  - Python for Pentesters: https://tryhackme.com/room/pythonforsecurity
- **Free Resources**:
  - Automate the Boring Stuff: https://automatetheboringstuff.com/ (free online)
  - Python for Hackers Course: https://www.youtube.com/watch?v=5O_ZiBCyz9w (Heath Adams)
  - Violent Python PDF: https://github.com/reconSF/python-for-security/blob/master/Violent%20Python.pdf
- **Projects**:
  - Build a port scanner
  - Create a simple keylogger
  - Write a password cracker
  - Develop a reverse shell
  - Make a directory brute-forcer

**Week 3: Bash/Shell Scripting**
- **TryHackMe**:
  - Bash Scripting: https://tryhackme.com/room/bashscripting
- **HTB Academy**:
  - Introduction to Bash Scripting: https://academy.hackthebox.com/course/preview/introduction-to-bash-scripting
- **Practice**:
  - Automate enumeration
  - Create log parsing scripts
  - Build backup automation
  - Write cleanup scripts

**Week 4: PowerShell for Red Team**
- **TryHackMe**:
  - Hacking with PowerShell: https://tryhackme.com/room/powershell
  - PowerShell for Pentesters: https://tryhackme.com/module/powershell-for-pentesters
- **Resources**:
  - PowerShell for Pentesters Course: https://www.youtube.com/playlist?list=PLjG9EfEtwbvIFIuL9GkCp-0rF9F6c5gKi
  - PowerSploit GitHub: https://github.com/PowerShellMafia/PowerSploit
  - Nishang GitHub: https://github.com/samratashok/nishang
- **Projects**:
  - Write PowerShell enumeration scripts
  - Create credential harvesters
  - Build persistence mechanisms
  - Develop AV bypass scripts

---

### MONTH 3: Core Penetration Testing

**Week 1: Reconnaissance & Information Gathering**
- **TryHackMe**:
  - Passive Reconnaissance: https://tryhackme.com/room/passiverecon
  - Active Reconnaissance: https://tryhackme.com/room/activerecon
  - Content Discovery: https://tryhackme.com/room/contentdiscovery
  - Subdomain Enumeration: https://tryhackme.com/room/subdomainenumeration
  - OSINT: https://tryhackme.com/room/ohsint
  - Google Dorking: https://tryhackme.com/room/googledorking
- **Tools to Master**:
  - nmap, masscan, rustscan
  - gobuster, ffuf, feroxbuster
  - subfinder, assetfinder, amass
  - theHarvester, recon-ng
  - Shodan, Censys

**Week 2: Exploitation Fundamentals**
- **TryHackMe**:
  - Metasploit: Introduction: https://tryhackme.com/room/metasploitintro
  - Metasploit: Exploitation: https://tryhackme.com/room/metasploitexploitation
  - Metasploit: Meterpreter: https://tryhackme.com/room/meterpreter
  - Exploiting Vulnerabilities: https://tryhackme.com/room/exploitingvulnerabilities
- **HTB Academy**:
  - Using the Metasploit Framework: https://academy.hackthebox.com/course/preview/using-the-metasploit-framework
  - Getting Started: https://academy.hackthebox.com/course/preview/getting-started

**Week 3-4: Web Application Hacking Foundations**
- **PortSwigger Web Security Academy** (FREE - ESSENTIAL):
  - All SQL Injection labs: https://portswigger.net/web-security/sql-injection
  - All XSS labs: https://portswigger.net/web-security/cross-site-scripting
  - All Authentication labs: https://portswigger.net/web-security/authentication
  - Complete 100+ labs minimum
- **TryHackMe**:
  - OWASP Top 10: https://tryhackme.com/room/owasptop10
  - OWASP Top 10 - 2021: https://tryhackme.com/room/owasptop102021
  - Burp Suite Basics: https://tryhackme.com/room/burpsuitebasics
  - Burp Suite Repeater: https://tryhackme.com/room/burpsuiterepeater
- **Practice Apps**:
  - DVWA: http://www.dvwa.co.uk/
  - bWAPP: http://www.itsecgames.com/
  - WebGoat: https://github.com/WebGoat/WebGoat

---

### MONTH 4: Windows Exploitation & Privilege Escalation

**Week 1-2: Windows Fundamentals**
- **TryHackMe**:
  - Windows Fundamentals 1: https://tryhackme.com/room/windowsfundamentals1xbx
  - Windows Fundamentals 2: https://tryhackme.com/room/windowsfundamentals2x0x
  - Windows Fundamentals 3: https://tryhackme.com/room/windowsfundamentals3xzx
  - Windows PrivEsc: https://tryhackme.com/room/windows10privesc
  - Windows Privilege Escalation: https://tryhackme.com/room/windowsprivesc20
- **HTB Academy**:
  - Windows Fundamentals: https://academy.hackthebox.com/course/preview/windows-fundamentals
  - Windows Privilege Escalation: https://academy.hackthebox.com/course/preview/windows-privilege-escalation

**Week 3-4: Privilege Escalation Deep Dive**
- **Resources**:
  - PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  - HackTricks: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
  - Tib3rius Windows PrivEsc Course: https://www.udemy.com/course/windows-privilege-escalation/
- **Practice**:
  - Complete 20+ Windows machines on HTB
  - Use: WinPEAS, PowerUp, PrivescCheck
  - Practice manual enumeration
  - Document every privilege escalation path

---

## PHASE 2: OFFENSIVE OPERATIONS (Months 5-9)
*Time to get dangerous - Real attack techniques*

### MONTH 5: Active Directory Domination - Part 1

**Week 1: AD Fundamentals**
- **TryHackMe**:
  - Active Directory Basics: https://tryhackme.com/room/winadbasics
  - Attacktive Directory: https://tryhackme.com/room/attacktivedirectory
  - AD Certificate Templates: https://tryhackme.com/room/adcertificatetemplates
- **Resources**:
  - AD Security by Sean Metcalf: https://adsecurity.org/
  - HarmJ0y Blog: https://blog.harmj0y.net/
  - The Dog Whisperer's Handbook: https://github.com/BloodHoundAD/BloodHound/wiki
- **Build Your Lab**:
  - Set up Windows Server 2019/2022
  - Create domain forest
  - Add multiple DCs, workstations
  - Configure OUs, GPOs, trusts
  - Use: https://github.com/Orange-Cyberdefense/GOAD (Game of Active Directory)

**Week 2: AD Enumeration**
- **TryHackMe**:
  - Breaching Active Directory: https://tryhackme.com/room/breachingad
  - Enumerating Active Directory: https://tryhackme.com/room/adenumeration
- **Tools**:
  - BloodHound: https://github.com/BloodHoundAD/BloodHound
  - SharpHound: https://github.com/BloodHoundAD/SharpHound
  - PowerView: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
  - ADRecon: https://github.com/sense-of-security/ADRecon
  - PingCastle: https://www.pingcastle.com/

**Week 3: AD Attacks - Initial Access**
- **TryHackMe**:
  - Exploiting Active Directory: https://tryhackme.com/room/exploitingad
  - Post-Exploitation Basics: https://tryhackme.com/room/postexploit
- **Techniques**:
  - LLMNR/NBT-NS Poisoning (Responder)
  - SMB Relay attacks
  - IPv6 DNS takeover
  - Password spraying
  - AS-REP Roasting
  - Kerberoasting

**Week 4: AD Attacks - Lateral Movement**
- **TryHackMe**:
  - Lateral Movement and Pivoting: https://tryhackme.com/room/lateralmovementandpivoting
- **Techniques**:
  - Pass-the-Hash
  - Pass-the-Ticket
  - Overpass-the-Hash
  - Pass-the-Certificate
  - RDP hijacking
  - WMI/DCOM exploitation
  - PSRemoting abuse

---

### MONTH 6: Active Directory Domination - Part 2

**Week 1-2: AD Persistence & Domain Dominance**
- **TryHackMe**:
  - Persisting Active Directory: https://tryhackme.com/room/persistingad
  - Red Team Fundamentals: https://tryhackme.com/room/redteamfundamentals
- **Techniques**:
  - Golden Ticket attacks
  - Silver Ticket attacks
  - DCSync attacks
  - DPAPI abuse
  - GPO abuse
  - ACL abuse
  - DCShadow attacks
  - Skeleton Key attacks

**Week 3: AD Certificate Services Exploitation**
- **Resources**:
  - Certified Pre-Owned: https://posts.specterops.io/certified-pre-owned-d95910965cd2
  - Certipy: https://github.com/ly4k/Certipy
  - PSPKIAudit: https://github.com/GhostPack/PSPKIAudit
- **Practice**:
  - ESC1-ESC8 attacks
  - Certificate template abuse
  - NTLM relay to ADCS

**Week 4: Forest & Domain Trusts**
- **Resources**:
  - HarmJ0y on Trusts: https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/
  - Trust relationship attacks
- **Tools**:
  - Rubeus: https://github.com/GhostPack/Rubeus
  - Mimikatz: https://github.com/gentilkiwi/mimikatz
  - Impacket: https://github.com/fortra/impacket

---

### MONTH 7: Red Team Tradecraft & OPSEC

**Week 1: Red Team Fundamentals**
- **TryHackMe**:
  - Red Team Fundamentals: https://tryhackme.com/room/redteamfundamentals
  - Red Team Engagements: https://tryhackme.com/room/redteamengagements
  - Red Team Threat Intel: https://tryhackme.com/room/redteamthreatintel
  - Red Team OPSEC: https://tryhackme.com/room/opsec
- **Reading**:
  - Red Team Development and Operations: https://redteam.guide/docs/
  - MITRE ATT&CK Framework: https://attack.mitre.org/
  - Red Team Ops book by Joe Vest

**Week 2: Command & Control (C2) - Fundamentals**
- **Resources**:
  - C2 Matrix: https://www.thec2matrix.com/
  - Havoc Framework Setup: https://github.com/HavocFramework/Havoc
  - Havoc Documentation: https://havocframework.com/docs/
  - Sliver Documentation: https://github.com/BishopFox/sliver/wiki
- **Practice**:
  - Set up Havoc C2
  - Deploy Sliver Framework
  - Create custom listeners
  - Generate payloads
  - Practice post-exploitation
  - Use redirectors

**Week 3: C2 - Advanced Usage**
- **Frameworks to Master**:
  - **Sliver** (Primary): https://github.com/BishopFox/sliver
  - **Havoc** (Alternative): https://github.com/HavocFramework/Havoc
  - **Mythic**: https://github.com/its-a-feature/Mythic
  - **Empire/Starkiller**: https://github.com/BC-SECURITY/Empire
  - **Merlin**: https://github.com/Ne0nd0g/merlin
  - **PoshC2**: https://github.com/nettitude/PoshC2
- **Practice**:
  - BOF (Beacon Object Files)
  - Custom modules
  - Pivoting through C2
  - Data exfiltration
  - OPSEC considerations

**Week 4: Phishing & Initial Access**
- **TryHackMe**:
  - Phishing: https://tryhackme.com/room/phishingyl
  - Phishing Emails in Action: https://tryhackme.com/room/phishingemails1tryoe
  - Phishing Analysis Fundamentals: https://tryhackme.com/room/phishingemails2rytmuv
- **Tools**:
  - GoPhish: https://github.com/gophish/gophish
  - King Phisher: https://github.com/rsmusllp/king-phisher
  - Social-Engineer Toolkit: https://github.com/trustedsec/social-engineer-toolkit
  - EvilGinx2: https://github.com/kgretzky/evilginx2
- **Practice**:
  - Create convincing phishing campaigns
  - Credential harvesting pages
  - Payload delivery methods
  - Email spoofing

---

### MONTH 8: Evasion & Defense Bypass

**Week 1-2: AV/EDR Evasion Fundamentals**
- **TryHackMe RED TEAM PATH**:
  - Obfuscation Principles: https://tryhackme.com/room/obfuscationprinciples
  - Signature Evasion: https://tryhackme.com/room/signatureevasion
  - Bypassing UAC: https://tryhackme.com/room/bypassinguac
  - Runtime Detection Evasion: https://tryhackme.com/room/runtimedetectionevasion
  - Evading Logging and Monitoring: https://tryhackme.com/room/evadingloggingandmonitoring
  - Introduction to Antivirus: https://tryhackme.com/room/introtoav
  - AV Evasion: Shellcode: https://tryhackme.com/room/avevasionshellcode
  - Windows Internals: https://tryhackme.com/room/windowsinternals
- **Resources**:
  - Bypass AMSI: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
  - EDR Evasion repo: https://github.com/Mr-Un1k0d3r/RedTeamCCode
  - Red Team Notes: https://www.ired.team/
- **Tools**:
  - DefenderCheck: https://github.com/matterpreter/DefenderCheck
  - ThreatCheck: https://github.com/rasta-mouse/ThreatCheck
  - AMSITrigger: https://github.com/RythmStick/AMSITrigger

**Week 3: Living Off The Land (LOLBAS/GTFOBins)**
- **TryHackMe**:
  - Living Off the Land: https://tryhackme.com/room/livingofftheland
- **Resources**:
  - LOLBAS: https://lolbas-project.github.io/
  - GTFOBins: https://gtfobins.github.io/
  - LOLDrivers: https://www.loldrivers.io/
- **Practice**:
  - Command execution via LOLBins
  - File operations
  - Credential access
  - Defense evasion

**Week 4: Advanced Evasion Techniques**
- **TryHackMe**:
  - Sandbox Evasion: https://tryhackme.com/room/sandboxevasion
- **Techniques**:
  - Process injection methods
  - DLL hijacking
  - COM hijacking
  - Process hollowing
  - Process doppelgänging
  - Module stomping
  - Reflective DLL injection

---

### MONTH 9: Infrastructure & Tooling

**Week 1-2: Red Team Infrastructure**
- **Resources**:
  - Red Team Infrastructure Wiki: https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
  - Cobalt Strike Community Kit: https://github.com/Cobalt-Strike/community_kit
  - Terraform for Red Team: https://github.com/redcode-labs/RedTeamInfra
- **Build**:
  - VPS setup (DigitalOcean/Vultr/AWS)
  - Domain fronting
  - Redirectors (Apache/Nginx)
  - Proper OPSEC infrastructure
  - Logging and monitoring
  - Automated cleanup

**Week 3: Cloud Red Teaming - AWS**
- **TryHackMe**:
  - AWS Cloud Pentesting: https://tryhackme.com/room/awscloud101
  - Breaching the Cloud: https://tryhackme.com/room/breachingthecloud
- **Resources**:
  - Rhino Security Labs AWS Tools: https://github.com/RhinoSecurityLabs/pacu
  - HackTricks Cloud: https://cloud.hacktricks.xyz/pentesting-cloud/aws-security
  - AWS Pentesting Tools: https://github.com/toniblyx/prowler
- **Practice**:
  - S3 bucket exploitation
  - IAM privilege escalation
  - Lambda function abuse
  - EC2 compromises

**Week 4: Cloud Red Teaming - Azure**
- **Resources**:
  - Azure AD Attack Tools: https://github.com/dirkjanm/ROADtools
  - HackTricks Azure: https://cloud.hacktricks.xyz/pentesting-cloud/azure-security
  - Azure Attack Paths: https://github.com/NotSoSecure/azure-attack-paths
  - AADInternals: https://github.com/Gerenios/AADInternals
- **Practice**:
  - Azure AD enumeration
  - Privilege escalation in Azure
  - Service principal abuse
  - Managed identity exploitation

---

## PHASE 3: ADVANCED RED TEAM (Months 10-14)
*Elite operator level - Build custom tools*

### MONTH 10: Malware Development - Fundamentals

**Week 1-2: C/C++ for Malware**
- **Resources**:
  - Malware Development Course by Sektor7: https://institute.sektor7.net/courses (Study materials available publicly)
  - MalDev Academy: https://maldevacademy.com/
  - Malware Development repo: https://github.com/malsearchs/Pure-Malware-Development
  - Cocomelonc Blog: https://cocomelonc.github.io/
- **YouTube Channels**:
  - Sektor7 Institute: https://www.youtube.com/@sektor7institute
  - MalDev Academy: https://www.youtube.com/@maldevacademy
  - CryptoCat: https://www.youtube.com/@_CryptoCat
- **Practice**:
  - Write simple dropper
  - Create shellcode runner
  - Build process injector
  - Develop simple RAT

**Week 3: Windows API & Internals**
- **Resources**:
  - Windows Internals Book (Part 1&2)
  - Windows API documentation: https://learn.microsoft.com/en-us/windows/win32/api/
  - Windows API Index: https://www.pinvoke.net/
  - Ired.team: https://www.ired.team/
- **Study**:
  - PE file structure
  - Process creation
  - Memory management
  - Thread management
  - DLL injection methods

**Week 4: Shellcode Development**
- **Resources**:
  - Shellcode Development: https://github.com/FULLSHADE/Windows-Shellcode-Development
  - Custom Shellcode Guide: https://www.ired.team/offensive-security/code-injection-process-injection/writing-and-compiling-shellcode-in-c
  - Win32 Shellcode: https://github.com/peterferrie/win-exec-calc-shellcode
- **Projects**:
  - Write MessageBox shellcode
  - Create download and execute shellcode
  - Build reverse shell shellcode
  - Develop staged shellcode

---

### MONTH 11: Malware Development - Advanced

**Week 1: Encryption & Obfuscation**
- **Resources**:
  - Encryption in Malware: https://github.com/vxunderground/MalwareSourceCode
  - String Obfuscation: https://dr4k0nia.github.io/posts/String-Obfuscation-The-Malware-Way/
- **Techniques**:
  - XOR encryption
  - AES encryption
  - RC4 encryption
  - String obfuscation
  - Control flow obfuscation
  - API hashing

**Week 2: Process Injection Techniques**
- **Resources**:
  - Process Injection Bible: https://github.com/3xpl01tc0d3r/ProcessInjection
  - Injection Techniques: https://www.ired.team/offensive-security/code-injection-process-injection
- **Implement**:
  - Classic DLL injection
  - Reflective DLL injection
  - Process hollowing
  - Thread execution hijacking
  - APC injection
  - Early Bird injection
  - Process Doppelgänging
  - Module stomping

**Week 3-4: Building a Custom C2 Agent**
- **Resources**:
  - C2 Development in C#: https://training.zeropointsecurity.co.uk/courses/c2-development-in-csharp (Study outline available)
  - Building C2: https://github.com/cribdragg3r/Alaris
  - C2 Development: https://github.com/malwaremusings/csharp-c2
- **Project**: Build your own C2 framework
  - HTTP/HTTPS implant
  - Encrypted communications
  - Command execution
  - File operations
  - Persistence mechanisms
  - Anti-debugging features
  - Self-deletion capabilities

---

### MONTH 12: Exploit Development Foundations

**Week 1-2: Buffer Overflow Deep Dive**
- **Resources**:
  - Corelan Team: https://www.corelan.be/index.php/articles/
  - Exploit Development 101: https://github.com/FULLSHADE/WindowsExploitationResources
  - FuzzySecurity: https://www.fuzzysecurity.com/tutorials.html
- **TryHackMe**:
  - Buffer Overflow Prep: https://tryhackme.com/room/bufferoverflowprep
  - Brainpan 1: https://tryhackme.com/room/brainpan
- **Practice**:
  - Stack buffer overflows
  - SEH overflows
  - Egghunters
  - Bad character analysis
  - Return address overwriting

**Week 3: Return Oriented Programming (ROP)**
- **Resources**:
  - ROP Primer: https://github.com/nnamon/linux-exploitation-course
  - Exploit Exercises: https://exploit.education/
- **Tools**:
  - ROPgadget: https://github.com/JonathanSalwan/ROPgadget
  - Ropper: https://github.com/sashs/Ropper
  - pwntools: https://github.com/Gallopsled/pwntools
- **Practice**:
  - Build ROP chains
  - Bypass DEP
  - Bypass ASLR
  - Bypass stack cookies

**Week 4: Windows Exploit Development**
- **Resources**:
  - Windows Exploit Development: https://github.com/FULLSHADE/WindowsExploitationResources
  - Corelan Windows Exploits: https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/
- **Tools**:
  - WinDbg: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/
  - Immunity Debugger: https://www.immunityinc.com/products/debugger/
  - x64dbg: https://x64dbg.com/
  - mona.py: https://github.com/corelan/mona
- **Practice**:
  - CVE reproduction
  - 1-day exploit development
  - Vulnerability research
  - Fuzzing basics

---

### MONTH 13: Container & Kubernetes Red Teaming

**Week 1-2: Docker Security**
- **Resources**:
  - HackTricks Docker: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security
  - Docker Pentesting: https://github.com/stealthcopter/deepce
  - Container Escape Techniques: https://github.com/cdk-team/CDK
- **Practice**:
  - Docker escape techniques
  - Privileged container abuse
  - Socket mounting attacks
  - Volume mounting exploits

**Week 2-3: Kubernetes Pentesting**
- **Resources**:
  - Kubernetes Pentesting: https://github.com/kelseyhightower/kubernetes-the-hard-way
  - K8s Attack Matrix: https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
  - HackTricks K8s: https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security
- **Tools**:
  - kubectl: https://kubernetes.io/docs/tasks/tools/
  - kubeletctl: https://github.com/cyberark/kubeletctl
  - kube-hunter: https://github.com/aquasecurity/kube-hunter
  - kubesploit: https://github.com/cyberark/kubesploit

**Week 4: CI/CD Pipeline Attacks**
- **Resources**:
  - CI/CD Goat: https://github.com/cider-security-research/cicd-goat
  - Pipeline Attack Techniques: https://github.com/rung/threat-matrix-cicd
- **Practice**:
  - GitHub Actions exploitation
  - Jenkins attacks
  - GitLab CI exploitation
  - Supply chain attacks

---

### MONTH 14: Advanced Persistence & Forensics Evasion

**Week 1-2: Advanced Persistence Mechanisms**
- **Resources**:
  - Windows Persistence: https://github.com/Karneades/awesome-malware-persistence
  - Persistence Techniques: https://attack.mitre.org/tactics/TA0003/
  - Advanced Persistence: https://github.com/netbiosX/Checklists/blob/master/Red-Team-Infrastructure-Wiki.md
- **Techniques**:
  - WMI event subscriptions
  - Scheduled task abuse
  - Service creation
  - Registry run keys
  - COM hijacking
  - Application shimming
  - Netsh helper DLLs
  - Boot/Logon autostart

**Week 3: Anti-Forensics**
- **Resources**:
  - Anti-Forensics: https://github.com/yasserfarouk/AntiForensics
  - Log Evasion: https://www.ired.team/offensive-security/defense-evasion
- **Techniques**:
  - Log tampering
  - ETW bypass
  - SYSMON evasion
  - Timestomping
  - File destruction
  - Memory wiping
  - Artifact removal

**Week 4: Rootkit Fundamentals**
- **Resources**:
  - Rootkit Development: https://github.com/m0nad/Diamorphine
  - Windows Rootkits: https://github.com/bytecode77/r77-rootkit
- **Study**:
  - Kernel-mode rootkits
  - User-mode rootkits
  - DKOM techniques
  - Hook techniques

---

## PHASE 4: EXPERT & JOB READY (Months 15-18)
*Certification prep, portfolio building, job hunting*

### MONTH 15: Certification Preparation - Part 1

**Focus: Study for OSCP/PNPT while continuing practice**

**Week 1-2: OSCP Preparation**
- **TryHackMe Paths**:
  - Complete Offensive Pentesting Path
  - Complete Cyber Defense Path for Blue Team knowledge
- **HTB Machines**:
  - Complete TJ Null's OSCP-like list: https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159
  - Minimum 50 machines rooted
  - Document every machine
- **Proving Grounds**:
  - Practice on OffSec's PG Practice
  - Complete 30+ boxes

**Week 3-4: Active Directory Labs**
- **Practice Networks**:
  - HTB Pro Labs (pay for 1 month if possible, ~$100):
    - Dante
    - RastaLabs
  - TryHackMe:
    - Wreath Network
    - Throwback Network
  - VulnLab: https://www.vulnlab.com/ (Free tier available)

---

### MONTH 16: Certification Preparation - Part 2

**Week 1-2: Red Team Focused Training**
- **TryHackMe**:
  - Complete ENTIRE Red Team Learning Path
  - Red Team Capstone: https://tryhackme.com/room/redteamcapstone
- **Resources**:
  - Study CRTO materials (publicly available resources)
  - Review all RTO GitHub repos: https://github.com/h3ll0clar1c3/CRTO
  - Practice with Havoc/Sliver extensively

**Week 3-4: Build Comprehensive Portfolio**
- **GitHub Repositories**:
  - Custom tools developed
  - Exploit scripts
  - Automation scripts
  - C2 agents
  - Malware samples (for educational purposes)
  - Red Team scripts
- **Blog/Website**:
  - 20+ detailed machine writeups
  - Red Team engagement methodology
  - Tool development posts
  - Evasion technique articles
- **Projects to Showcase**:
  - Custom C2 framework
  - AV evasion tool
  - AD enumeration tool
  - Privilege escalation checker
  - Phishing framework

---

### MONTH 17: Real-World Simulation & CTF Mastery

**Week 1-2: Red Team Simulations**
- **Practice**:
  - Set up complete enterprise environment
  - Conduct full red team engagements
  - Practice entire kill chain
  - Document everything professionally
  - Time yourself
  - Practice report writing
- **Resources**:
  - Red Team Report Templates: https://github.com/tjnull/TJ-JPT
  - MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

**Week 2-3: CTF Competitions**
- **Platforms**:
  - CTFtime: https://ctftime.org/
  - Hack The Box CTFs
  - TryHackMe CTFs
- **Participate in**:
  - 5-10 CTFs
  - Focus on pwn, crypto, forensics, web
  - Join a team
  - Network with other players

**Week 4: Bug Bounty Introduction**
- **Platforms**:
  - HackerOne: https://www.hackerone.com/
  - Bugcrowd: https://www.bugcrowd.com/
  - Intigriti: https://www.intigriti.com/
- **Resources**:
  - Bug Bounty Hunting methodology
  - Practice on VDP programs
  - Learn disclosure process
  - Build reputation

---

### MONTH 18: Job Search & Interview Preparation

**Week 1: Resume & LinkedIn Optimization**
- **Resume**:
  - Highlight technical skills
  - Showcase projects
  - Include certifications (if obtained)
  - Quantify achievements
  - Link to GitHub, blog
- **LinkedIn**:
  - Professional headshot
  - Detailed experience
  - Skills endorsements
  - Connect with InfoSec professionals
  - Post technical content
  - Engage with community

**Week 2-3: Interview Preparation**
- **Technical Interview Prep**:
  - Practice common interview questions: https://github.com/Leander-s/Awesome-Cybersecurity-Interview-Questions
  - Do mock technical interviews
  - Explain your projects clearly
  - Practice live hacking demonstrations
  - Be ready to discuss methodology
- **Resources**:
  - Red Team Interview Questions: https://github.com/WebBreacher/offensiveinterview
  - Practice on Pramp: https://www.pramp.com/

**Week 4: Active Job Hunting**
- **Job Boards**:
  - LinkedIn Jobs
  - Indeed
  - Glassdoor
  - AngelList
  - Cybersecurity specific boards
- **Apply to**:
  - Security Engineer roles
  - Junior Red Team positions
  - Penetration Tester positions
  - Security Consultant roles
  - SOC Analyst (as backup)
- **Target**: 10-15 applications per week
- **Network**:
  - Attend local security meetups
  - BSides conferences
  - DEF CON groups
  - OWASP chapters
  - Cybersecurity Discord servers

---

## ESSENTIAL TOOLS & RESOURCES

### Core Platforms
- **TryHackMe**: https://tryhackme.com/ (Primary learning platform)
- **Hack The Box**: https://www.hackthebox.com/ (Machines & challenges)
- **Hack The Box Academy**: https://academy.hackthebox.com/ (Structured courses)
- **PortSwigger Academy**: https://portswigger.net/web-security (Web security)
- **Proving Grounds**: https://www.offsec.com/labs/ (OSCP-style practice)
- **VulnHub**: https://www.vulnhub.com/ (Downloadable VMs)
- **PentesterLab**: https://pentesterlab.com/ (Web exploitation)

### C2 Frameworks (All FREE)
- **Sliver**: https://github.com/BishopFox/sliver (Primary)
- **Havoc**: https://github.com/HavocFramework/Havoc (Alternative)
- **Mythic**: https://github.com/its-a-feature/Mythic
- **Metasploit**: https://www.metasploit.com/
- **Empire/Starkiller**: https://github.com/BC-SECURITY/Empire
- **PoshC2**: https://github.com/nettitude/PoshC2
- **Merlin**: https://github.com/Ne0nd0g/merlin
- **Covenant**: https://github.com/cobbr/Covenant
- **Brute Ratel**: (Commercial but study architecture)

### Essential Tool Repositories
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks**: https://book.hacktricks.xyz/
- **Red Team Notes**: https://www.ired.team/
- **LOLBAS**: https://lolbas-project.github.io/
- **GTFOBins**: https://gtfobins.github.io/
- **Revshells**: https://www.revshells.com/
- **CrackStation**: https://crackstation.net/
- **CyberChef**: https://gchq.github.io/CyberChef/

### Active Directory Resources
- **BloodHound**: https://github.com/BloodHoundAD/BloodHound
- **PowerView**: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- **Impacket**: https://github.com/fortra/impacket
- **Rubeus**: https://github.com/GhostPack/Rubeus
- **Mimikatz**: https://github.com/gentilkiwi/mimikatz
- **SharpCollection**: https://github.com/Flangvik/SharpCollection
- **GOAD Lab**: https://github.com/Orange-Cyberdefense/GOAD

### Malware Development Resources
- **MalDev Academy**: https://maldevacademy.com/
- **Sektor7 Materials**: https://institute.sektor7.net/
- **Cocomelonc**: https://cocomelonc.github.io/
- **Ired.team**: https://www.ired.team/
- **VX Underground**: https://vx-underground.org/
- **Pure Malware Dev repo**: https://github.com/malsearchs/Pure-Malware-Development

### YouTube Channels (FREE Learning)
- **IppSec**: https://www.youtube.com/c/ippsec (HTB walkthroughs)
- **John Hammond**: https://www.youtube.com/c/JohnHammond010
- **The Cyber Mentor**: https://www.youtube.com/c/TheCyberMentor
- **HackerSploit**: https://www.youtube.com/c/HackerSploit
- **LiveOverflow**: https://www.youtube.com/c/LiveOverflow
- **STÖK**: https://www.youtube.com/c/STOKfredrik
- **NetworkChuck**: https://www.youtube.com/c/NetworkChuck
- **David Bombal**: https://www.youtube.com/c/DavidBombal
- **Sektor7**: https://www.youtube.com/@sektor7institute
- **MalDev Academy**: https://www.youtube.com/@maldevacademy
- **CryptoCat**: https://www.youtube.com/@_CryptoCat
- **13Cubed**: https://www.youtube.com/c/13Cubed

### Books (FREE PDFs Available)
- **The Hacker Playbook Series** by Peter Kim
- **Red Team Field Manual (RTFM)** by Ben Clark
- **Blue Team Field Manual (BTFM)** by Alan White
- **Penetration Testing** by Georgia Weidman
- **The Web Application Hacker's Handbook** by Dafydd Stuttard
- **Black Hat Python** by Justin Seitz
- **Violent Python** by TJ O'Connor
- **Metasploit: The Penetration Tester's Guide**
- **Red Team Development and Operations** by Joe Vest

### Communities & Forums
- **Reddit**:
  - r/netsec: https://www.reddit.com/r/netsec/
  - r/AskNetsec: https://www.reddit.com/r/AskNetsec/
  - r/cybersecurity: https://www.reddit.com/r/cybersecurity/
  - r/HowToHack: https://www.reddit.com/r/HowToHack/
  - r/redteamsec: https://www.reddit.com/r/redteamsec/
- **Discord Servers**:
  - TryHackMe Official
  - Hack The Box Official
  - NetSecFocus
  - The Cyber Mentor
  - InfoSec Prep
- **Twitter/X**:
  - Follow #infosec, #redteam, #pentesting
  - Key accounts: @HackingDave, @mubix, @harmj0y, @gentilkiwi

### Certification Roadmap (Optional but Recommended)
**Free/Study Only:**
1. **Months 1-4**: Focus on foundational knowledge
2. **Months 5-9**: Build practical skills
3. **Months 10-14**: Develop advanced capabilities
4. **Months 15-18**: Save money for certifications

**Certification Order (if budget allows):**
1. **CompTIA Security+** (~$370) - Study with Professor Messer (FREE)
2. **eJPT** (~$200) - Good beginner cert
3. **OSCP** (~$1,649) - Industry standard (SAVE FOR THIS)
4. **CRTO** (~$499) - Excellent red team cert
5. **CRTP** (~$249) - AD focused
6. **OSEP** (~$2,499) - Advanced red teaming

---

## WEEKLY SCHEDULE TEMPLATE

### Monday - Friday (10 hours/day)
**6:00 AM - 9:00 AM**: Theory & Course Material
- TryHackMe/HTB Academy courses
- Reading documentation
- Watching tutorial videos

**9:00 AM - 12:00 PM**: Hands-on Practice
- Lab exercises
- Machine exploitation
- Tool development
- Active practice

**12:00 PM - 1:00 PM**: Break
- Lunch
- Physical exercise
- Mental reset

**1:00 PM - 4:00 PM**: Project Work
- Build tools
- Develop scripts
- Create malware (educational)
- C2 development
- Portfolio projects

**4:00 PM - 6:00 PM**: Documentation & Community
- Write writeups
- Update blog
- Contribute to GitHub
- Engage with community
- Review day's learning
- Plan tomorrow

### Weekend (Rest Days)
**Saturday**:
- Light review of week's material
- Watch conference talks
- Read security blogs
- Catch up on any incomplete work
- 2-3 hours maximum

**Sunday**:
- Complete rest
- No technical work
- Recharge for next week

---

## PROGRESS TRACKING

### Monthly Checkpoints
**End of Each Month**:
- [ ] Completed all scheduled rooms/courses
- [ ] Documented all machines/exercises
- [ ] Updated GitHub repositories
- [ ] Created new blog posts
- [ ] Practiced new techniques
- [ ] Reviewed and refined methodology

### Skill Milestones
**Month 4**: ✅ Root 50+ machines, comfortable with basics
**Month 9**: ✅ Domain admin 10+ times, AD mastery
**Month 14**: ✅ Built custom C2, developed malware
**Month 18**: ✅ Professional portfolio, ready for jobs

### Portfolio Metrics
- **GitHub**: 500+ contributions by Month 18
- **Writeups**: 30+ detailed machine writeups
- **Blog Posts**: 20+ technical articles
- **Projects**: 5+ major red team tools
- **Machines Rooted**: 100+ total
- **CVEs**: Attempt to discover 1-2 (bonus)

---

## FINAL TIPS FOR SUCCESS

### 1. Document EVERYTHING
- Keep detailed notes
- Create writeups immediately
- Use tools like Obsidian, Notion, or simple markdown
- Your documentation is your proof of learning

### 2. Build in Public
- Share your learning journey
- Write blog posts
- Create YouTube videos (optional)
- Contribute to open source
- Help others in forums

### 3. Network Actively
- Join Discord servers
- Attend virtual conferences
- Connect on LinkedIn
- Follow industry leaders
- Participate in discussions

### 4. Stay Consistent
- 10 hours every day, no excuses
- Rest on weekends (important!)
- Don't burn out
- Maintain work-life balance
- This is a marathon, not a sprint

### 5. Leverage Your ITSM Background
- You understand ticketing systems
- You know incident management
- You have documentation skills
- You understand IT operations
- These are HUGE advantages in security

### 6. Think Like an Attacker
- Always ask "how can I break this?"
- Study real-world attacks
- Read threat intel reports
- Follow breach disclosures
- Understand attacker mindset

### 7. Master the Basics
- Don't skip fundamentals
- Deep understanding > surface knowledge
- Master one thing at a time
- Build strong foundations
- Advanced skills come naturally

### 8. Practice, Practice, Practice
- Theory without practice is useless
- Break things in your lab
- Try techniques multiple ways
- Fail fast and learn faster
- Hands-on is everything

---

## ENCOURAGEMENT

You're about to embark on an incredible 18-month journey that will transform you from an ITSM engineer into a skilled Red Team Operator. This roadmap is aggressive, comprehensive, and designed to make you job-ready.

**Key Points to Remember:**
- This is 100% achievable with dedication
- You have the time (10 hours/day is perfect)
- Everything here is FREE (except optional certs)
- Your ITSM background is an advantage
- The cybersecurity industry needs skilled people like you
- Red teaming is one of the most exciting career paths
- You'll be learning skills that are in HIGH demand

**By Month 18, you will have:**
- Mastered Linux, Windows, networking, and programming
- Become an Active Directory domination expert
- Built custom malware and C2 frameworks
- Developed exploit development skills
- Created a professional portfolio
- Rooted 100+ machines
- Developed real-world applicable skills
- Become job-ready for Red Team positions

**This is your roadmap. Own it. Execute it. Become elite.**

---

## ADDITIONAL RESOURCES

### Free Certifications to Consider
- **Google Cybersecurity Certificate** (Coursera - 7 day free trial)
- **Microsoft Security, Compliance, and Identity Fundamentals** (SC-900 study materials free)
- **Fortinet NSE 1-3** (completely free)

### Conference Talks (FREE)
- **DEF CON**: https://www.youtube.com/user/DEFCONConference
- **Black Hat**: https://www.youtube.com/c/BlackHatOfficialYT
- **BSides**: Various YouTube channels
- **SANS Internet Storm Center**: https://isc.sans.edu/

### Blogs to Follow
- **Krebs on Security**: https://krebsonsecurity.com/
- **Schneier on Security**: https://www.schneier.com/
- **Troy Hunt**: https://www.troyhunt.com/
- **Daniel Miessler**: https://danielmiessler.com/
- **SpecterOps**: https://posts.specterops.io/

---

**GOOD LUCK ON YOUR JOURNEY TO BECOMING AN ELITE RED TEAM OPERATOR! 🔴🔥**

*Remember: The only difference between you and a professional Red Teamer is time, practice, and dedication. You've got this!*
