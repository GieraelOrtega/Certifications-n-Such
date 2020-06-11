[CompTIA Cybersecurity Analyst CySA+ CS0-001 Crash Course][CrashCourse]
=================
> Cybersecurity is one of the hottest fields to be in and the new CompTIA Cybersecurity Analyst CSA+ CS0-001 is the certificate to prove you have what it takes to be a cyber analyst. This exam is internationally recognized and vendor-neutral. It was designed to test your capabilities to prevent, detect and combat cybersecurity threats. The challenge is knowing how to prepare for it.

What You'll Learn
-----------------
- Threat Management concepts including reconnaissance, response and counter measures
- Incident Response and investigation practices
- Vulnerability management techniques
- Security architecture principles and common toolsets

Prerequisites
-------------
- Fundamental knowledge of computers & computer security concepts
- 2+ years of IT experience focused on security (Suggested: 5+ years)

Resources
---------
- [CompTIA Cybersecurity Analyst CySA+ CS0-001 Crash Course by Joseph Muniz][CrashCourse]
- [CompTIA Cybersecurity Analyst CSA+ (CS0-001) O'Reilly Course][OReillyTraining]

***

Schedule/Layout
===============
- DAY 1
    - Segment 1: Reconnaissance, response and counter measures
        - Introduction to the exam
        - Attack Kill Chain 101
        - Physical and virtual reconnaissance
        - Social engineering and phishing
        - Exploitation
        - Attacks (man-in-the-middle, rootkits, etc)
        - Cross-site scripting, session hijacking

    - Segment 2 Information Security Vulnerability Management Process
        - Frameworks
        - Common Policies
        - Controls, and Procedures
        - Regulatory requirements
        - Common Standards
        - Continuous Monitoring

    - Segment 3 Security Architectures and securing corporate environments
        - Defense in Depth
        - Reading Logs
        - System hardening
        - Sandbox and honeypots
        - Sinkholes

    - Segment 4 Common Vulnerabilities and Analyzing vulnerability scans
        - Common vulnerabilities
        - Reading Vulnerability Reports
        - Assessments, Audits and Pen Testing
        - Security Data Analytics
        - Remediation recommendations

- DAY 2
    - Segment 5 Determine Impact of an Incident
        - Network and Host Symptoms
        - Understanding point-in-time data analysis
        - Traffic and NetFlow Analysis
        - Wireless analysis techniques
        - Packet captures and log reviews

    - Segment 6: Incident Reporting, Communications and post incident response
        - Forensic Tools and Investigation
        - Incident Reponses Symptoms and Recovery Techniques
        - Communication and stakeholders
        - Risks of remediation
        - Incident Summary Report

    - Segment 7 Access Control and Access Management Remediation
        - Segmentation principles
        - Automated Network Access Control
        - Threat Containment
        - Context-based authentication
        - TACACTS+ and Radius
        - Single Sign-on

    - Segment 8 Cybersecurity Tools, Technologies and Software Developer Life Cycle (SDLC) best practices
        - Software design best practices
        - Manual peer review
        - Stress testing and secure regression
        - SDLC
        - Preventive, Collective and Analytical security.



Day 1 Notes
===========

General Notes
-------------
- "Find your weakest area and hit it the hardest"
- Kali Linux + Metasploit + Metasploitable for Labs

***

Risk Management
---------------
- ~1-2 exam question(s) on the CIA Triad (e.g. What is the A. in CIA?)
    - (C)onfidentiality = Protect sensitive data
    - (I)ntegrity       = Ensure no unauthorized modifications
    - (A)vailability    = Authorized people can see it
    
- ~1-2 exam question(s) on scenario affecting CIA (e.g. which is impacted by DDoS)

- ~1-2 questions on the order of Risk Assessement such as NIST SP 800-39
    - Prepare for Assesssment
    - Conduct Assessment
        1. Identify Threat Sources & Events
        2. Identify Vulnerabilities and Predisposing Conditions
        3. Determine Likelihood of Occurrence
        4. Determine magnitude of impact
        5. Determine Risk
    - Communicate Results
    - Maintain Assessement

- Threats
    - Adversarial   = Individuals, groups, orgs. such as Anonymous
    - Accidental    = Mistake such as config error
    - Structural    = Equipment/software failure
    - Environmental =  Natural/man-made disasters

- Persistent Level
    - Smash n Grab                     = Automated, not-targeted
    - Advanced Persistent Threat (APT) = Continued, focused, and specific

- Known and Unkown Threats
    - Known   = Attack has been seen/characterized
    - Unknown = Attack not known and characterized
        - Zero Day: Attack/Vulnerability that's not known. Has no signature

- Threat Classification
    - External/Removable Media
    - Attrition (Brute Force)
    - Web (XSS)
    - Email (Attachments)
    - Impersonation (MITM)
    - Improper Usage (Policy violation)
    - Loss/Theft
    - Unknown
    - Other

- Ransomware's Growth
    - Bitcoin + Better Tech such as Tor/Cloud/etc. + Fear = Increase in Ransomware's prevalence
    - Exploit Kits
        1. User clicks link/malvertising
        2. Malicious code launches
        3. Malicious infrastructure
        4. Ransomware payload

- Attack Vectors
    - Physical
        - Keyboards
        - System backdoors
        - Network backdoors
        - Lockpicking
            - Physical Lockpicks
            - Proxmark3.com - Badges/tags
    - Digital
        - Nmap       = Open ports
        - Nexpose    = Vulns
        - Metasploit = Delivering attack
    - Social
        - Social Engineering Tool Kit (SET)

- Types of Data (VERY IMPORTANT AND SPECIFIC ON TEST)
    ```
    - PHI                    = Personal Health Information
    - PII                    = Personal Identifiable Information
    - PCI                    = Payment Card Information
    - Intellectual Property  = Work/invention with rights/protections
    - Corporate Confidential = Sensitive to corporation such as merger/accounts
    ```
    
- Risk (Risk = Threat x Vulnerability)
    - Main factors = Risk, Cost, and Likelihood
    - Defense = Risk Reduction

- Impact (Outcome of a risk)
    ```
    - Potential Downtime         = Systems unavailable
    - System Process Criticality = Rating importance of a process to avoiding downtime
    - Recovery Time              = Time to recover and resume operations
    - Data Integrity             = Maintaining assurance of accuracy/consistency of data
    - Economic                   = Effect an event has on the economy
    - Type of data               = Corporate vs. confidential
    ```

- Risk Actions
    ```
    - Risk Reduction      = Implement countermeasure
    - Risk Transfer       = Purchase Insurance
    - Risk Acceptance     = Accept a possible loss
    - Risk Rejection      = Pretend there isn't a risk
    - ~Risk Exploitation~ = Abusing the risk on purpose (Not official)
    ```

- Validation
    ```
    - Scanning    = Looking for existing vulns
    - Patching    = Fixing/updating systems with vulns
    - Permissions = Ensure least privilege concept
    - Logging     = Ensure events being captured properly
    ```

***

Vulnerability Management
------------------------
- CVE  = Common Vulnerabilities and Exposures

- CVSS = Common Vulnerability Scoring System
    - Access Vector
    - Access Complexity
    - Authentication
    - Confidentiality
    - Integrity
    - Availability
    - Critical = 10 | High = 6+ | Medium = 4+ | Low = < 4

- Vulnerability Assessment
    - Positive = Identified | Negative = Rejected
    - Types
        ```
        - True Positive  = Correctly Identified   (e.g. sick person seen as sick)
        - False Positive = Incorrectly Identified (e.g. healthy person seen as sick) 
        - True Negative  = Correctly Rejected     (e.g. health person seen as healthy)
        - False Negative = Incorrectly Rejected   (e.g. sick person seen as healthy)
        ```

- SANS Vulnerability Management
    1. Asset Inventory
    2. Information Management
    3. Risk Assessment
    4. Vulnerability Assessment
    5. Report and Remediate
    6. Respond

- Scan Types
    - Credential Scan
        - Host Scan
        - Logging in and accessing the asset to test
        - Only need Read-only Access!
    - Non-Credential Scan
        - Network Scan
        - "Think attacker's POV"
        - Potential false positives
    - Study when to use Centralized vs. Distributed?

- Reverse Engineering Threats
    ```
    - Communication      =  Blacklist malicious remote sources
    - Attach Techniques  = Specific exploit/port used
    - Reconnaissance     = Seeking other sources
    - CnC/Botnet Lists   = Threat intelligence hits
    - Hash of file/parts = Signature of threat
    - Network Traits     = Specific behavior
    - Static Analysis    = Viewing source code to analyze
    - Dynamic Analysis   = Running and observing to analyze
    ```

- Patch Management Best Practices
    ```
    - Develop Inventory        = Systems, Applications, etc.
    - Standardize              = Easier to build policies
    - Existing Controls        = Document existing security
    - Reported Vulnerabilities = Consolidate found vulnerabilities, assessment findings, etc.
    - Classify Risk            = Develop plan to roll out patching
    ```

***

Reconnaissance Techniques
-------------------------

- Footprinting (Discovering a Topology)
    - Passive Scanning   = Research with NO ACTIVE PROBES
    - Active Scanning    = Engaging the target (e.g. port scanning)
    - Social Engineering = Manipulate individuals into divulging info

- OS Fingerprinting
    - Active Fingerprinting  = Actively transmit/send packets
    - Passive Fingerprinting = Slowly, passively analyze collected packets on the network

- Nmap
    ```
    -sS = TCP SYN
    -sT = Connect()
    -sA = ACK
    -sW = Window
    -sM = Maimon
    -sU = UDP Scan
    -sN = TCP Null
    -sF = FIN
    -sX = Xmas scans5
    -sO = IP protocol scan
    ```

- Important Ports
    - HTTP:   80 | Telnet: 23 | FTP:   21 <- Unencrypted
    - HTTPS: 443 | SSH:    22 | RDP: 3389 <- Encrypted

- *STUDY: Blue Team's perspective: Syn scans, 3-way handshake, fin scan, etc.*

- Data Analysis
    ```
    - Anomaly Analysis   = Differences in established patterns
    - Trend Analysis     = Predicting behavior such as congestion
    - Signature Analysis = Detecting known events (IPS, antivirus)
    - Heuristic/Behavior = Detecting malicious behavior
    ```

- Terminology
    - Email Harvesting = Gathering email addresses
    - DNS Harvesting   = Gathering public, published DNS and server names
        - Whois
        - Anti-DNS Techniques:
            - Blacklisting network
            - Rate limiting
            - CAPTCHAs
            - Anything that prevents a lot of searching
    - Phishing Techniques = Used after email and DNS
    - DNS Zone Transfers  = Transfer DNS info between DNS Servers. Can pass useful info
        - DNS Poisoning   = Redirecting to wrong site

***

Point in Time Analysis
----------------------
- Security Event Indicators (NIST 800-61) **MEMORIZE NIST 800-61 = SEC EVENT INDICATORS**
    - Alerts = Alarms coming from sec tools such as IPS and AV
    - Logs   = Document containing various types of alerts
    - Publicly available vuln data
    - People

- Point-in-time Data Analysis
    - Data frozen in time
    - Types
        - Packet Captures
            - Pcaps & NetFlow
                ```
                - Pcap    = Logging network data (Think full phone call)
                - NetFlow = Logging network records (Think call history)
                ```
            - Tools
                ```
                - Wireshark        = Capture Realtime or view pcap files
                - TCPdump/Windump  = Dump data to file
                - Snort            = Intrusion detection/prevention
                - NGFW/IPS         = Intrusion detection/prevention
                - NetFlow Analyzer = Baseline and look for anomalies
                ```
        - Configurations
        - Memory Analysis
        - Drive Captures

- Specific Tools
    ```
    - Rmon     = Monitor LAN on layers 1-4
    - TCP Dump = CLI packet analyzer
    - Netstat  = Gather local host net info and behavior
    - Snort    = IPS and internal monitoring. Detect port scans
    - Top      = Top processes (Similar to atop, htop)
    - Ps       = Running processes
    - Perfmon  = Host controllers, mem usage
    - Pstree   = View running processes
    - Df       = Disk space
    ```

- System Logs **IMPORTANT: Usually reading syslogs on the exam**
    - Operating System Logs
    - Application Logs
    - Secure Software Logs 

- Authentication Logs **IMPORTANT: Usually reading auth logs on exam**
    - Timestamp
    - User
    - Application
    - Event
    - Result
    - Access Device
    - Additional Factors

- Event Logs
    - Event or notification
    - Categories
        ```
        0 = Emerg   = High priority and must be attended to  
        1 = Alert   = Requires immediate attention  
        2 = Crit    = Critical condition that could be a system failure  
        3 = Err     = Service malfunction  
        4 = Warning = Potential minor issue  
        5 = Debug   = Troubleshooting messages  
        6 = Notice  = Event that might require attention  
        7 = Info    = General Information
        ```

- SNMP = Simple Network Management Protocol (v1 = unsecure, v3 = recommended)
    - SNMPv3 Adds: Encryption, Authentication, and User Accounts **IMPORTANT**

- SIEM = Security Information and Event Management
    - Collect logs/data streams and correlate to cyber security events

- Firewall Logs & Rules
    - NAT Rules         = Translating private IP to public UPs
    - Access Rules      = Allowing access from remote connections to systems passing data through the firewall
    - Ingress Filtering = INBOUND data being monitored/restricted from entering
    - Egress Filtering  = OUTBOUND data being monitored/restricted that fail to meet requirements

***

Vulnerability Discovery
-----------------------
- Compliance
    - PCI DSS = Paymment Cards
        - Approved Algorithms:
            - Diffie-Hellman with 2048 bits
            - HMAC-SHA2
            - SHA2 256
            - RSA 2048 bits
            - AES 128 bits
            - PBKDF2, Scrypto, Bcrypt
    - HIPAA = Healthcare
    - Gramm-Leach-Bliley Act = Financial Institutions
    - Sarbanes-Oxley Act = Spending

- NIST Penetration Testing Process
    - Discovery Phase
    - Attack Phase
        1. Gaining Access
        2. Escalating Privileges
        3. System Browsing
        4. Install Additional Tools

- Assessment vs. Penetration Test
    - Assessment       = Using automated tools to identify potential vulnerabilities
    - Penetration Test = Executing attacks against identified vulnerabilities

- Statement of Work
    - Time             = When the testing time starts and ends
    - Assumptions      = Clarify what was provided pre-assessment
    - Scope            = What the goal and limitation is
    - Associated Risks = Definition of sensitive systems and if they may be altered
    - Authorization    = Proper data owner autorization

***

Web Applications
================
- OWASP Top 10
    - Cross Site Scripting (XSS)
        - Inserting malicious scripts into the site
    - Injection Flaws (SQL Injection)
        - Inserting/Abusing logic into the query
        - OR '1'='1
    - Malicious File Execution
    - Insecure Direct Object Reference
    - Cross Site Request Forgery
    - Information Leakage and Improper Error Handling
    - Broken Authentication and Session Management
        - Ability to hijack sessions
    - Insecure Cryptographic Storage
    - Insecure Communications
        - SSL is no longer considerd secure (2.0, 3.0, etc.)
        - TLS 1.2 is still considered secure but prior is NOT
    - Failure to Restrict URL Access

- Common Attacks
    ```
    - Buffer Overflow      = Attacker placing more data in memory than allocated
    - Privilege Escalation = Attacker increases level of access on target
    - SQL Injection        = Exploitation of a web app vulnerability
    - Cross-Site Scripting = Injection with malicious scripts into the site
    - Denial of Service    = Disrupting services
    ```


- Threat Containment
    ```
    - Segmentation = Separate sensitive systems from regular users
    - Isolation    = Place risky systems on a separate network (e.g. Guest networks)
    - Remove       = Automated/Manual reaction to identified threat. Removing connection.
    ```

***

Day 2
=====

General Notes
-------------

- Sample Questions:
    ```
    - What type of attack would look like '1'=='1? 
        - SQL Injection
    - Which type of traffic would you see in a mail server?
        - 25, SMTP, POP, web traffic
    - Which CVSS is the highest priority?
        - 10
    - What's open: 22/TCP, 443/TCP
        - SSH and HTTPS
    - In CVSS3#AV:N/AC:M/Au:S/C:P/I:H/A:NC, whats the attack vector and integrity?
        - Network-Based, High
    - What if a systems is beaconing over an unusuaul port but nothing is triggered?
        - Zero Day
    - Joe notices the web server is redicrecting to a malicious source. What did the attacker use?
        - XSS
    - Joey moves guest to a separate network what is this tactic?
        - Segmentation
    - Which port shouldn't be used for a jumpbox? (22, 23, 443, 3389)
        - 23 = Telnet. Not secure
    - When compromised, which should be fixed first? Admin laptop, server, NTP system, or DMZ?
        - NTP! Time is critical
    - Explain the difference between Ingress and Egress
        - Ingress = INBOUND data entering the network
        - Egress  = OUTBOUND data leaving the network
    - What flag for nmap to identify OS?
        - -o / -A
    - Which Cisco log level is most critical? (0,1,7,20)
        - 0
    - Which log most likely has file deletion info
        - Security Logs
    - Which process uses TCP stack response, TCP option support, initial sizing?
        - Application Scanning
    -  What type of account should be used for credentialed scans?
        - Read-Only
    - Which CVSS metric represents the potential for total compromise?
        - C = Complete
    - Which is active monitoring? (Netflow, SNMP, Pinging, Monitoring)
        - Pinging Systems
    - What features come with SNMPv3?
        - Encryption, User accounts, and Authentication
    - What is it called to probe a firewall for rules?
        - Fire walking
    - What is PII and PHI?
        - PII = Personal Identifiable Information
        - PHI = Personal Health Information
    - Which should be dealt with first: Stolen cert, DDoS, Buffer overflow with executable code, Web Vuln?
        - Buffer Overflow as it can lead to code execution
    - Which protocols are PCI DSS approved?
        - AES, SHA2, RSA
    - Which are PKI X.508 Compliant?
        - DES, AES, IDEA, 3DES, CAST
    ```

Security Architectures
----------------------
- Defense in Depth = Latering defenses

- Identifying Threats
    ```
    - Signature Analysis  = Known threats
    - Trend Analysis      = Large-scale changes to baseline
    - Heuristic Analysis  = Behavior focused for unknowns
    - Regression Analysis = Statistical modeling
    - Anomaly Analysis    = Difference from established patterns
    ```

- Whitelisting vs. Blacklisting
    ```
    - Blacklisting = Block specific software. Easier but less secure
    - Whitelisting = Allow specific software only. Harder but more secure
    ```

- Firewalls
    ```
    - Packet Filter       = Simply check characters in each packet vs. rules
    - Stateful Inspection = Beyond packet filter. Also view state
    - Next Gen (NGFW)     = Beyond stateful, include app, users, context
    - Web App Firewall    = Specialized for web app attacks such as SQL and XSS

    - IMPORTANT: Difference between Network, Host, Web App Firewalls:
        - Network = Stateful. Port protection, packet filtering, proxy, etc.
        - Host    = Program control, host security policies
        - Web App = Requests/Responses and inspecting layer 7
    ```

- Known vs. Unknown Threats
    - Known = Seen and characterized
        - Signatures for detection
        - Behavior trigger
        - Domains blocked
    - Unknown

[CrashCourse]: https://learning.oreilly.com/live-training/courses/comptia-cybersecurity-analyst-cysa-cs0-001-crash-course/0636920453383/
[OReillyTraining]: https://learning.oreilly.com/videos/comptia-cybersecurity-analyst/9780134772066