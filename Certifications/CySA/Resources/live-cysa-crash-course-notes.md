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
    - Unknown = Attack not known or characterized
        - Signature does NOT exist
        - Must use behavioral/anomoly detection
            - Sandboxing/Honeypots/etc.

- Intrusion Detection and Prevention
    ```
    - Signature Detection = Looking for known attack patterns
    - Threat Detection    = Looking for malicious behavior
    - Anomaly Detection   = Looking for unusual behavior

    - Intrusion DETECTION System  = Passive (doesn't block attacks. Can be inline or off mirror port)
    - Intrusion PREVENTION System = Active (CAN block attacks. Must be inline)
    ```

- Viruses and Malware
    - Viruses = Code capable of copying itself and damages the computer
        - Antivirus
            - File Based signatures = Known Malicious Files
            - File Behavior = Some file analytics
            - File Modification Detection = Limited encoding detection
    - Malware = Umbrella term for various malicious software
        - Antimalware
            - Protects vs. worms, trojans, keyloggers

- Proxies
    - Open Proxy = Accessible by anybody on the internet
        - Can conceal the user's IP
    - Reverse Proxy = Proxy which appears to clients as ordinary server
        - Requests are forwarded to one or more server
    - Man-in-the-middle = Attacker captures traffic via ARP posioning, spoofing, etc

- MBSA = Microsoft Baseline Security Analyzer

***

Identity
--------

- Key Concepts of Identity (AAA)
    - Authentication (Who are you?)
    - Authorization (What can you access?)
    - Accounting (Record of what you do)

- MFA = Multi-Factor Authentication
    - Something You Know
        - Passwords
        - Pins
    - Something You Have
        - Token
        - Certificates
    - Something You Are
        - Fingerprint
        - Eye Scan

- Identity Repositories
    - Directory Services = Centralized repo for service distributions
    - TACACS+ = Family of protocols handling remote auth
    - RADIUS = Central authentication, authorization, and accounting
    - Kerberos = Ticket based authorization system

- SSO = Single Sign-On
    - LDAP and CAS = Central Authentication Service
    - OpenID = Open source standard for decentralized auth
    - OAuth = Open authorization standard
    - OpenID Connect = Authentication layer
    - Facebook Connect = Sharing Facebook login to other system

- Identity Attacks
    - Impersonation = Abusing OAuth Open Redirect to take access
    - Session Hijack = Copying an auth'd session and using on their browser
    - Golden Ticket = Kerberos attack getting a lifetime ticket granting ticket
    - XSS = Placing script on site that sends auth. session to attacker
    - Pass the Hash = Session hijacking as a MITM

- STUDY LINUX FILE PERMISSIONS!

- Password Attacks
    - Dictionary Attack
    - Brute Force Attack
    - Rainbow Table Attack
    - Phishing
    - Social Engineering
    - Malware
    - Offline Cracking
    - Guess

- **NOTE: Questions related to tools are typically more broad/general**

- Context-Based Authentication
    - User Roles
    - IP Address Reputation
    - Time of Day
    - Location check
    - Frequency of access
    - Device based

***

Access Control
--------------
Evaluating systems that access the network

- Terminology
    - Port Security = Manually enabling port controls
    - Automated Access Control = Automatically adjusting security
    - Profiling = Examining traffic to fingerprint devices
    - Posture = Evaluating endpoints for risk

- Remediation
    - Quarantine = Limit or deny network access
    - Isolation  = Put into a separate VLAN or remove from the network
    - Patch/Upgrade = Windows/ AV Update
    - Software Link = Offer software

- Context-Based Challenges
    - Time       = What time the devices is accessing
        - Daily Spike Times
        - Seasonal Spike Times
        - Events
    - Location   = What part of the network (LAN, VPN, Wireless)
        - Separated AD Forests
        - Remote vs. Local
        - Wireless Roaming
    - Frequency  = How often is access needed
        - Rapid Requests
        - Heartbeat Technologies
        - Delayed Requests
    - Behavioral = User trends (Traveling, data access, etc.)
        - Policy Exceptions
        - Road Warriors
        - Privilege Changes
        - IoT

- DHCP Fingerprinting = Detect end device's OS based on DHCP exchange packets

- Nmap
    ```
    -sV        = Version Detection
    -A         = Enables additional information
    --allports = Scan all ports instead of default 1024
    -O         = OS
    ```

***

Policy + Controls
-----------------

- Policies
    - High level, REQUIRED
    - Contains standards, procedures, and guidelines
    - Security Policies
        - Information security policy – High-level authority and guidance
        - Acceptable use policy (AUP) – What is permitted
        - Data ownership – Ownership of information and usage
        - Data classification policy – How data is classified
        - Data retention policy – How long data is held and destroyed
        - Account management policy – User account lifecycle
        - Password policy – Password rules
- Standards
    - Mandatory requirements aimed at enforcing policies
- Procedures
    - Specific security documents. Think Playbook
    - Step-by-step document
- Guidelines
    - OPTIONAL. Think "helpful advice"

- Data retention: Typically 3 years

- Controls
    - Physical Controls
        - Fences
        - Man Traps
        - Doors and Locks
        - Motion Sensors
    - Logical/Technical Controls
        - Encryption
        - Logical Segmentation
        - Authentication
        - Access Control Lists (ACLs)
    - Administrative Controls
        - Training
        - Disaster preparedness

***

Compliance
----------

- Frameworks
    - GLBA  = Gramm-Leach-Bliley Act (Financial Institutions)
    - SOX   = Sarbanes-Oxley (Financial records of publicly traded companies)
    - FERPA = Family Education Rights and Privacy Act (Educational institutions)
    - NIST  = National Institute of Standards and Technology (Cybersecurity)
    - ISO   = International Organization for Standardization
        - ISO 27001 = Information Security Management
    - COBIT = Control Objectives for Information and Related Technologies
        - Framework, Process Descriptions, Control Objectives, Management Guidelines, Maturity Models
        - Maturity Levels
            - 0 = Nonexistent (Lack progress)
            - 1 = Initial/Ad Hoc (Recognize issues exist)
            - 2 = Repeatable but intuitive (Process developed by different people doing the same task)
            - 3 = Defined Process (Standardized and documented procedures)
            - 4 = Managed and measurable (Measure compliance with procedures)

    - SABSA = Sherwood Applied Business Security Architecture
        - Framework/methodology for sec architecture/service management
    - TOGAF = The Open Group Architecture Framework
        - Framework providing planning for enterprise architecture
    - ITIL = Informaiton Technology Infrastructure Library
        - Standardize selection, planning, dev of IT services to business

- Framework Recap
    - NIST = Government approved cyber framework
    - ISO = Approach to manage and secure sensitive company information
    - COBIT = Set of controls over information technology
    - SABSA = Framework and methodology for enterprise security architecture and service management
    - TOGAF = Framework providing designing, planning, implementing and governing enterprise information technology architecture
    - ITIL = Standardize selection, planning, delivery and support of IT services

***

Processees
----------

- Separation of Duties = No one person should be able to affect a breach of security
- Dual Control = Require two people for one action (Form of sep. of duties)
- Cross Training = Training in more than one role/skill
- Mandatory Vacation = Forcing employee to take week+ off to identify fraud/collusion
- Succession Planning = Identifying replacements to take over roles

- Change Control Process
    ```
    - Identify  = What changes to make
    - Assess    = What is impact of change
    - Approve   = Project management and leadership should get approval
    - Implement = Execute plan
    - Follow-up = Verify work is done and re-assess impact of changes

***

Incident Response
-----------------

- Process
    ```
    - Preparation    = Prepare for potential incidents
    - Identification = Determine if a security incident occurred
    - Containment    = Isolate the incident to prevent further damage
    - Remediation    = Identify root cause and remove impacted systems
    - Recovery       = Return systems back to product that are no longer a threat
    - Learn          = Benefit from incident to improve security in the future
    ```
    
- NIST SP 800-61 = The Incident Response Detection & Analysis
    - Preparation
        - Build CSIRT
    - Detect and Analysis
        - Alerts = Alarms from security tools
        - Logs = Documents containing various alerts
        - Publicly Available Vuln. Data
        - People = Trained eyes that flag an incident
    - Contain, Eradicate, and Recovery
        - Scope = Choose containment strategy
        - Contain = Prevent breach from spreading
            - Segmentation = Least privilege for each segment
            - Isolation    = Completely cut off the attacker from the network
            - Removal      = Sanitization, reconstruction/reimaging, secure disposal
        - Eradicate = Remove contained threat
        - Recovery = Return back to operational state

- NIST 800-88 = Secure Disposal
    ```
    - Clear   = Using common read/write commands or using factory restore
    - Purge   = Overwrite with 0's, block erasing, etc.
    - Destroy = Drill the drive, melting, etc.
    ```

***

Digital Forensics
-----------------

- Chain of Custody = Chronological documentation/paper trail of electronic/physical evidence

- Powered on stays on and Powered off stays off = DO NOT CHANGE THE DEVICE'S STATE
    - On  = Collect the RAM information and see running processes
    - Off = Leave off

- Data Acquisition
    - Static = Device powered off. Non-volatile
    - Live   = Running. Volatile such as registries, cache, ram.

- Important Locations
    - Temporary applications in AppData
    - Password files in Shadow/Passwd/SAM
    - COredumps and hibernation files for encryption keys (in mem)

***

Secure Development
------------------

- SDLC = Secure Software Development Life Cycle

- Models
    - Waterfall
    - Spiral
    - Agile
    - Rapid

- Testing and Analysis
    - Static Code Analysis
        - Data Flow Analysis = Collect run-time info about data while in static
        - Taint Analysis = Identify variables that are tainted with user controllable input
    - Fuzzing
        Sending random and excessive data during blackbox testing
    - Fault Injection
        - Inserting faults into error handling paths
    - User Acceptance Testing
        - Getting feedback from targeted audience/customer
    - Stress Testing/Load Testing
        - Observing availability under extreme conditions
    - Regression Testing
        - Ensuring older programming still works with new changes
    - Input Validation
        - Ensuring proper testing for any input given
    - Parameterized Queries
        - Using pre-made SQL statements to prevent SQL attacks

- Preventative Security = Designed to block attacks and reduce vuln. exposure
- Collective Security   = Centralized data collection and correlation
- Analytical Security   = Proactively identify vulnerabilities to enforce better security practices

***

Concept Review
--------------

- Sample Questions
    ```
    - When deploying vuln scanner across the network but afraid of sensitive data from being seen, what do you do?
        - Encrypt between systems. Host agents
    - What does Chmod 777 -Rv do?
        - Removes security. Read, write, view everything
    - What is the term for sending ranodm data at something to test?
        - Fuzzing
    - What protocols can be used to profile a system?
        - Netflow, DHCP, DNS, SNMP
    - Server is vulnerable but can't be patched. What can you do?
        - Secure around it (The networ)
    - Where is data found that is fragments between files?
        - Slack Space
    - What is the tool you CAN'T use to create a forensic copy? (DD, FTK, RW, Encase)
        - RW
    - What is the first step for forensics after you collect a system?
        - Make a forensic copy
    - How would you start a response to an incident
        - Preparation/Identification
    - Which tool is best to prevent a rootkit? IPS, AntiVirus, File Integrity/Breach Detection, Content Filter?
        - File Integrity/Breach Detection
    - What is a data source that is made up of multiple customer data that can enhance security
        - Threat Intelligence
    - Which comes first for the SDLC?
        - Requirement Gathering
    - What is a WAF?
        - Web Application Firewall. Attempts to block web-based attacks such as SQL injection
    - Which provides a single point of failure? Load balancing, Consolidation, HA?
        - Consolidation
    - Which would not be in a security policy? Statement regarding security, requirement to use AES-256, delegation of authority, designation of responsible exec?
        - AES-256. Too specific for a policy
    - What is the term when one person codes and explains while the other observes/documents?
        - Over-the-shoulder Review
    - What practice ensures patches don't break services?
        - Regression Testing
    - What type of control is a fire extinguisher?
        - Physical
    - Which auth. protocol is best for untrusted networks?
        - Kerberos
    - Which software dev. module uses a four phase linear dev?
        - Spiral
    - Which threat analysis detection is best for unknown threats? (Trend, Signature, Heuristic, Regression)
        - Heuristic
    Which tactic blocks software not permitted on host desktops?
        - Whitelisting
    - What file format does dd give?
        - RAW
    - Which is a step of the recovering stage? (Rebuild, Scan, Destroy, Report)
        - Scanning
    - Which NIST publication covers cybersecurity incident handling?
        - SP 800-61
    - Which is not a purging activity? (Factory Reset, Block Erase, Crypto Erase)
        - Factory Reset
    - Which ISO standard covers security management controls?
        - 27001
    - What is a background check policy considered?
        - Administrative
    - Which model would you recommend for describing 5 activities associated with IT service management?
        - ITIL
    - What tier of NIST cybersecurity framework is policy adaptive?
        - T4
    - Joey is writing a document listing acceptable rules for VPN access? What is this?
        - A standard
    - What would not help in phishing? (Training, SIEM monitoring logins, NGFW, MFA)
        - NGFW
    ```
[CrashCourse]: https://learning.oreilly.com/live-training/courses/comptia-cybersecurity-analyst-cysa-cs0-001-crash-course/0636920453383/
[OReillyTraining]: https://learning.oreilly.com/videos/comptia-cybersecurity-analyst/9780134772066