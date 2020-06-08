[//]: # (TODO: UPDATE LINKS, IMAGES, AND ToC)

![CySA+ Logo](CySA+_Logo.PNG)

CySA+ Super Study Guide - Markdown Version (WIP)
=======================
**Compiled by Gierael Ortega**

**References/Sources Used:**
- Linux Academy CySA+ Guide
- Daniel Arsenault&#39;s CySA+ Guide
- Reddit User u/stigmatas&#39;s Documents
- Chapple &amp; Seidl&#39;s CySA+ Sybex Textbook
- Jeremy Stretch&#39;s Port Number Cheat Sheet
- Lakhan &amp; Muniz&#39;s Online O&#39;Reilly CySA+ Training

# Table of Contents

**[CySA+ CSO-001 Overview/Exam Details 2](#_Toc42285075)**

**[Domain I: Threat Management 3](#_Toc42285076)**

[Broad Strokes 3](#_Toc42285077)

[Risk Assessment 5](#_Toc42285080)

[Risk Controls 7](#_Toc42285084)

[Recon and Intelligence 13](#_Toc42285090)

**[Domain II: Vulnerability Management 21](#_Toc42285096)**

[Regulatory Requirements 21](#_Toc42285097)

[Scanning 22](#_Toc42285098)

[Remediation 24](#_Toc42285099)

[Analyzing Vulnerability Scans 26](#_Toc42285100)

[Common Vulnerabilities 29](#_Toc42285103)

**[Domain III: Cyber Incident Response 31](#_Toc42285109)**

[Security Incidents 31](#_Toc42285110)

[Network Event Monitoring 37](#_Toc42285114)

[Digital Forensics 42](#_Toc42285117)

**[Domain IV: Security Architecture and Tool Sets 47](#_Toc42285121)**

[Policy Frameworks 47](#_Toc42285122)

[Defense In Depth 50](#_Toc42285127)

[Identity 55](#_Toc42285129)

[Software Development Life Cycle 61](#_Toc42285132)

[Specific Tools 66](#_Toc42285133)

**[Performance Based Question Review 71](#_Toc42285134)**

# CySA+ CSO-001 Overview/Exam Details

- &quot;CompTIA Cybersecurity Analyst (CySA+) is an IT workforce certification that applies behavioral analytics to networks and devices to prevent, detect and combat cybersecurity threats through continuous security monitoring.&quot; -CompTIA
- CySA+ focuses on the candidate&#39;s ability to not only proactively capture, monitor, and respond to network traffic findings, but also emphasizes software and application security, automation, threat hunting, and IT regulatory compliance, which affects the daily work of security analysts.&quot; -CompTIA&#39;s explanation
- Number of questions: Maximum of 85 questions
- Length of test: 165 minutes
- Passing Score: 750 (On a scale of 100-900)
- Four Domains
  - Threat Management
    - 27% of the exam
  - Vulnerability Management
    - 26% of the exam
  - Cyber Incident Response
    - 23% of the exam
  - Security Architecture and Tools
    - 24% of the exam

# Domain I: Threat Management

## Broad Strokes

- Identifying Threats
- Network Security Measures
- Understanding Response and Countermeasures
- Threats, Vulnerabilities, and Risk
- Footprinting and Recon
- Threats to Confidentiality, Integrity, and Availability
- Controls to secure networks and endpoints
- Evaluation of Security Controls
- Information Gathering (passive and active)

### CIA Triad – A Balance Between Confidentiality, Integrity, and Availability

- **Confidentiality** _(How secure is info?)_
  - How secure does it need to be?
    - Public data should be public, but PII needs to be secure
  - Physical Protection
    - Doors, fences, security guards and cameras
  - Electronic Protection
    - Encryption, passwords, authentication, and firewalls
- **Integrity** _(How correct is the information?)_
  - Has it been modified or corrupted?
    - Hashing and checksums help monitor and verify
- **Availability** _(Is data always user-accessible)_
  - Redundancy in storage, power, and transit helps improve availability
  - Backup strategies and disaster recovery alleviate problems
- **Security v. Operations**
  - Security can interfere with functionality.
  - Sometimes you must increase risk to improve usability - again, focus on the system&#39;s needs. Think: how useful is a &quot;secure&quot; cement cube under the ocean?

![](RackMultipart20200608-4-10inig7_html_fac74d9b595c8031.png)

### Risk Consideration

- Various Risk &quot;Calculations&quot;
  - Risk = Assets x Vulnerabilities
  - Risk = Assets x Vulnerabilities x Threats
  - Risk = Assets x Vulnerabilities x Consequences
    - If you have nothing worth stealing, you&#39;ve got no risk.
    - If your system is flawless (cement cube in the ocean), there are no vulnerabilities.
    - If nobody wants your assets or has the means to go after them, you&#39;re free from threats.
- **Assets**
  - Information or Data
  - Network equipment
  - Servers/Computers
  - Software
  - Personnel
  - Processes
- **Vulnerabilities**
  - Any weakness in a system design, such as a bug, that allows an attacker physical or digital access
  - These weaknesses are internal factors. Patches, or additional security guards, can cover those weaknesses.
    - Sometimes a weakness is out of your control - such as when using proprietary software.
    - Your job is to compensate for those weaknesses
- **Threats**
  - Any condition that can cause harm, loss, damage, or compromise of an asset
  - Natural disasters, cyber-attacks, or malware
  - These threats do not have to be intentional - mother nature is dangerous as well, and accidents happen.
  - Your job is to cover vulnerabilities appropriate to your threats - NOT to defeat the threat itself.
    - You don&#39;t have to worry about Quantum Computers brute force hacking through your system… yet.

## Risk Assessment

- Should be performed regularly to understand existing threats, vulnerabilities, and the appropriate mitigations.
- **NIST SP 800-30** is a framework to properly perform these assessments based on current technology
  - Prepare for Assessment
  - Conduct Assessment
    - Identify Threats and Events
    - Identify Vulnerabilities
    - Determine Likelihood of Occurrence
    - Determine Magnitude of Impact
    - Determine _Risk_
  - Communicate Results
  - Maintain Assessment

### Identifying Threats

- **Adversarial Threats**
  - Consider capability, intent, and likelihood
  - Customers, foreign governments, suppliers, and competitors can all be considered
- **Accidental Threats**
  - Mistakes that hurt the security of the system
  - Fat-fingering (mistyping)
  - Accidentally taking a device home
  - Accidentally hitting a kill-switch, power button, fire-alarm, etc.
- **Structural Threats**
  - Equipment, software, or environmental control failure
  - Hard drive failure, overheating, bugs and crashes
  - ST&#39;s are the reason redundancy is key!
- **Environmental Threats**
  - Natural or man-made disasters
  - Fires, floods, storms, loss of power, wire-cuts, etc.
  - Another good reason for backups and redundancy
- Remember: Threats go beyond &quot;attackers.&quot; Disgruntled employees, accidents, and bugs can all cause asset loss or compromise security
- Risks change!
  - Quantum Computers aren&#39;t a threat now, but they may be in a few years, and they&#39;ll drastically shift vulnerabilities.

### Identifying Vulnerabilities

- Largely internal
- If you have a threat without a vulnerability - it isn&#39;t a risk.
  - Snowstorms are a threat… but not in Florida.
  - A Windows XP vulnerability is a threat… but not to a company that only uses IOS.

### Likelihood, Impact, Magnitude, and Risk

- What is the likelihood a vulnerability will be exploited, and how bad will it be when it is?
  - Low, Medium, High, or Critical
  - These judgements are **qualitative, not quantitative**
    - You cannot always put numbers to the issue, but you need to have an idea of how likely, or severe, risk is.
    - **ALE - Annual Loss Expectancy**
      - Cost x Occurrences = ALE
      - Calculated per year.
      - What is the cost of mitigating the risk, vs. the ALE?

## Risk Controls

- **Technical Controls**
  - Firewalls, IDS, IPS, antivirus, and endpoint security
- **Operational Controls**
  - Policies, pentest, SOPs, settings, and configurations
- &quot; **Dealing&quot; with Risk**
  - **Acceptance**
    - When risk is low, and/or countermeasures are expensive
      - A high risk that has been largely mitigated can then be accepted
  - **Avoidance**
    - When risk is too expensive, and you completely avoid vulnerability
      - XP is no longer supported, so you move your company to Windows 10.
  - **Mitigation**
    - Minimizing risk down to acceptable levels
      - Closing vulnerable ports, patching bugs, etc.
      - Every time you drive, you take some risk. But if you wear your seatbelt and drive the speed limit, you&#39;ve mitigated the risk.
  - **Transference**
    - The risk is unavoidable, but you don&#39;t want it
      - Insurance companies, basically.
        - Data Breach Protection Insurance - get paid back if you fall victim of cyber attack

### Network Perimeter Security

- **Firewalls**
  - Rests at network boundary
  - Triple-Homed Devices - connected to Internet, DMZ, and intranet
  - Filters the information as it passes between each &quot;home&quot;
- **DMZ - Demilitarized Zone**
  - Semi-trusted zone
  - Often home for servers that get traffic from the internet, but prevents internet from communicating directly to the intranet or trusted network
- **ACL - Access Control List**
  - Rules that define what traffic can pass through the firewall
  - Secure posture relies on **Implicit Deny** / **Explicit Allow**
    - **Blacklisting** : Block listed, permit all else _(Less secure, less work)_
    - **Whitelisting** : Permit listed, block all else _(More secure, more work)_
    - **Sinkhole** : Route traffic to null interface
- **Firewall Types**
  - Packet Filtering
    - Check each packet against ACL rules for IP and Port
  - Stateful Inspection
    - Maintain information about the _state_ of each connection
  - **NGFWs**** - Next Generation Firewalls**
    - Contextual information - recognizes users, apps, and processes to make decisions
    - Layer 7 of OSI model
  - **WAFs - Web Application Firewalls**
    - Protect web apps from SQL and Cross-Site Scripting attacks (SQL/XSS)
    - Placed right in front of web application server
- **Network Segmentation**
  - Separate networks by security levels
  - Can be divided by physical location as well

![](RackMultipart20200608-4-10inig7_html_d200cf5a263be208.png)

### NAC - Network Access Control

- Limits access to authorized individuals and systems
- Ensures systems have proper antiviral, settings, and authentication
- **802.1x**
  - Common protocol for NAC
  - Supplicant **** Authenticator **** Radius Server
  - Supplicant **** Authenticator **** Radius Server
  - Agent-based, requires supplicant to use special software to communicate
  - Out-of-Band
- **Agentless NAC**
  - Conducted in web browser
  - Puts you in an isolated network segment until you authenticate
    - _Think Starbucks WiFi where you accept the ToS_
- **In-Band**
  - Uses dedicated appliances between your device and the services
- **Out-of-Band**
  - Relies on existing network and has device communicate to authenticate
  - 1x
- **NAC Criteria**
  - Time of Day
  - User Role
  - User Location
  - System Health Status
    - Antivirus definitions, security patches, etc.

### Defense Deception Methods

- Honeypots
  - Designed to look lucrative or vulnerable
  - Wastes attackers time, or gathers their info
  - Can be used to improve defenses
- DNS Sinkholes
  - Provides false DNS info to malicious software
  - Detects suspicious requests, and redirects attacker to a dead-end
  - Useful for preventing an infected host on your network from doing more damage

### Secure Endpoint Management

- Hardening System Configuration
  - Disable unnecessary services and ports
  - Verify secure configs
  - Centrally control device settings (so user can&#39;t mess it up)
- Patch Management
  - Keep patches up to date to stay ahead of attackers
  - **SCCM** Microsoft System Center Configuration Manager
    - Central service that pushes patches to your devices
- Compensating Controls
  - Stop-gap measures
  - If you cannot patch a service, you could disable it, or block a relevant port at the firewall
- **GPO - Group Policies / Group Policy Objects**
  - Allows Admins to manage system and security configs across many devices over a network
    - Require firewall usage
    - Run scripts at logic
    - Activate share drive
- **Endpoint Security Software**
  - Software that allows security analysts to enforce security policies across user devices, and often gather data from them as well
  - Antimalware or antivirus
  - HIDS or HIPS
- Additional Controls
  - **MAC - Mandatory Access Control**
    - Sets all permissions centrally, users cannot adjust them
  - **DAC - Discretionary Access Control**
    - Only the owner of a file or resource can control the permissions
    - MAC is secure, but an admin nightmare
      - Good for Need-To-Know style data
      - SE Linux
  - **RBAC**  **-**  **Role-Based Access Control**
    - Access restricted to certain groups based on role

### Penetration Testing

- Simulated cyber-attack to test your defenses and vulnerabilities
- Goal is to gain access to your systems and report findings
- Pentest Teams:
  - **White Team** : Team managing a pentest (Defines the ROE)
  - **Red Team** : Pentest team using exploits to attack the network with permission
  - **Blue Team** : Network defenders blocking exploiters and keeping the system up
- Phases
  - **Planning**
    - Read through resumes
    - News articles, open source content, etc.
    - Do not touch the network
    - **ROE - Rules of Engagement**
      - Logistics: Contacts, schedule location, tools
      - Communication: Who, schedule, CSIRT awareness
      - Targets: Applications, networks, addresses, other info.
      - Execution: Specific tests to conduct
      - Reporting: Delivery type, frequency
      - Signatures: C-level sign off, &quot;Get out of jail card&quot;
    - Establish the type of pentest
      - **Black box** : Simulate outside attacker, more recon work
      - **Grey box** : Simulate insider attacker, some info/some recon
      - **White box** : Simulate insider attacker, internal knowledge/no recon
  - **Discovery**
    - Port scanning, enumeration, vulnerability scanning, web app scanning
    - Plan around vulnerabilities
  - **Attack (Exploitation)**
    - Exploit vulnerabilities, loop back to discovery for further vulnerabilities
    - Gain Access
    - Escalate Privileges
    - Jump from System to System
    - Install Additional Tools
  - **Reporting**
    - Explain your findings after you&#39;ve gone deep as you can
    - Describe successful tests, and possible solutions
    - List secure assets as well!
    - Prioritized based on risk posed by vulnerability

#### Reverse Engineering

- Taking a finished product and dismantling it until you understand its inner workings and components
- **Dynamic Analysis**
  - Launch malware in virtualized environment and see what it does
  - What ports does it communicate on?
  - What websites does it reach for?
  - Some Automated systems can use dynamic analysis to check for malware in attachments, emails, etc.
  - Quickest way to discover the EFFECTS of malware
- **Static Analysis**
  - Analysis of the code of the malware
  - Easy if the code is in interpreted language like Python or Ruby
  - Difficult with compiled code like C/C++ or Java
    - Requires a decompiler or binary for compiled code
- **Hardware Reverse Engineering**
  - Difficult due to device firmware
  - Usually use dynamic analysis
  - Hardware should come from a trusted source to ensure security
  - Refurbished or second-hand devices can be compromised with bad firmware

## Recon and Intelligence

### Footprinting the Network

- Create a map of network, systems, and company infrastructure
- NIST SP 800-115 and **OSSTMM** (Open Source Security Testing Methodology Manual) house instructions on this process
- **Active Reconnaissance**
  - Utilizes host scanning tools such as **NMAP** to gather info about systems, services, and vulnerabilities in network
  - NMAP can rely on responses to TCP/IP stack fingerprints to generate an Operating System Fingerprint
    - Identifying an OS by its response to TCP calls
  - Only identification, not methods of exploitation
  - Permission must be sought before conducting active recon
    - Scans can indicate an attack
    - Contract with proper scope-of-work is your protection
- **Network Mapping**
  - Utilizes **TTL- Time to Live** , **Traceroute** and other responses to gather information
  - **Zenmap** converts NMAP info into graphical data
- **Challenges to net mapping**
  - Firewalls and Layer 3 Switch ACLs can block Nmap queries such as ping
  - Wireless devices can pop in and out at different locations
  - Virtualized devices may be hidden behind the physical device
  - Cloud services could be unscannable
- **Port Scanning**
  - Host Discovery
  - Port and Service identification
  - Service Version ID
  - Operating System ID
  - Useful for inventory tasks and security audits - confirming what&#39;s running, accessible, etc.
- **Service Scanning**
  - Looks at the banners or packet responses of data to identify what is running and on which port
  - Judging by responses to known signatures, you can sometimes identify specific versions of individual services
  - Where you scan from matters - external scans will be blocked from more issues by NAT, ACLs, and firewalls
    - Pentests are best conducted from the outside
    - Vulnerability tests are best conducted from inside
  - The more information you get - such as version of the service - you can isolate specific vulnerabilities much easier.
- **Alternate Port Scanners**
  - Angry IP
    - Multiplatform
    - Graphical
    - Provides less OS and service info by default than NMAP/Zenmap
  - Metasploit
  - Qualys Vulnerability Management
  - Tenable&#39;s Nessus Vulnerability Scanner
  - Nmap
    - -sS (SYN scan) = Default scan type
    - -sT (TCP Connect) = Default when SYN scan unavailable

![](RackMultipart20200608-4-10inig7_html_935e1d4eb9118740.png)

### Passive Reconnaissance

- More difficult than active recon, requires more data-digging
  - Utilizes logs, packet captures, etc.
  - Data may be out of date
  - Useful for responding to a cyber incident without alerting the attacker that you&#39;re analyzing the attack
- Log and Configuration Analysis
  - Local data can be read through, or parsed, to create a network map
  - Log files, system config files, etc.
  - Much of this is manual labor
- **Network Devices**
  - Log activities, status, and events
  - Include traffic patterns and utilization
    - You can potentially see where the attacker is, and what they are doing
  - Helpful to have a centralized location that gathers the log files from all available devices, possibly through SNMP
- Logging Fault Levels - **Log Levels**
  - 0 - Emergencies - Failure causing a shutdown
  - 1 - Alerts - Immediate Action Required (Overheating)
  - 2 - Critical - Software Failure
  - 3 - Errors - Interface up/down
  - 4 - Warning - Config Change
  - 5 - Notifications - Protocol up/down
  - 6 - Information - ACL violation
  - 7 - Debugging
  - The higher level you log, the more data you&#39;ll fill up, but the more you&#39;ll have to work with when troubleshooting an incident
  - **Remember: 0 is worst, 7 is informational**
- Go get an example of reading through a log!!
  - **Important Info to Parse:**
    - Allow or Deny
    - Type of Traffic: TCP/UDP
    - Source
    - Destination
- **Configuration Files**
  - Identify all routes and devices in detail
  - Provides details of SNMP and SYSLOG servers on the network
  - User and Admin accounts
  - ACLs
- **Netflow** Data
  - Captures IP traffic info to provide flow and volume
  - IP, source, destination, and class of service
  - Does not provide packet details, but lets you easily monitor changes such as increased data volume/traffic
- **Netstat**
  - Identify active TCP/UDP connections
  - Identify process using a connection
  - Stats on sent/received data
  - Route Table Info
  - **Netstat - a**
    - Provides active TCP/UDP connections
  - **Netstat -0**
    - Identify process using a connection
    - Allows you to correlate malicious process to malicious host
  - **Netstat -e**
    - Volume of flow over ethernet
  - **Netstat -r**
    - Routing table information
- **DHCP Logs**
  - Dynamic Host Configuration Protocol
  - IP Address, Default Gateway, Subnet Mask, and DNS server
  - Combined with firewall logs and network logs, you can tell which hosts are using which IPs, and how often those IPs are changing
- **Firewall Logs and Configs**
  - Configs
    - What is allowed through and what is blocked
    - Clearer than log files
  - Logs
    - Use levels to categorize info and debug messages
    - Date/Time Stamp &amp; Details
    - Designed for human readability
- **System and Host Log Files**
  - Provide info on system config, applications, and user accounts
  - You need access to the system to gather these logs
  - **Windows System Logs**
    - Application Logs
    - Security Logs
      - Login events, resource usages, files created/deleted
    - Setup Logs
      - Installs
    - System Logs
      - Events from Windows OS
    - Forwarded Event Logs
      - Any activity performed remotely
  - **Linux System Logs**
    - /var/log directory

- **DNS Harvesting**
  - DNS info is publicly available
  - **Whois** can tell you who registered a domain, their address, email, etc.
  - **Hostnames** can tell you about the server itself
  - **Nslookup**
    - Provides IP addresses
  - **DNS Records**
    - MX - Mail records
    - A - Address Records
    - AAAA - IPv6 address
    - C - Canonical Records
    - PTR - Pointer Records
  - **Tracert - Trace Route**
    - Shows each hop from a host to a destination
- **Domain Names and IP Range Review**
  - Human Readable names used to locate servers
  - Top level domains
    - .com .net .org .edu .mil .goc
  - Country Code domains
    - .com.uk .edu.it
  - Five Regional Authorities
    - AFRINIC - Africa
    - ARIN - US/Canada/Antarctica/Caribbean
    - APNIC - Asia/Australia/New Zealand
    - LACNIC - Latin America, Caribbean
    - RIPE - Europe/Russia/Middle East
    - Each authority provides Whois services for their IP space
- **DNS Zone Transfers**
  - Replicate DNS databases between two DNS servers
  - This is vulnerable, so most only allow zone transfers to trusted servers
  - **Dig** can allow you to perform the transfer
    - &#39; **Dig axfr&#39;** is the command for a zone transfer - LOTS of data
  - **DNS Brute Forcing**
    - Using manual or scripted DNS queries for each IP of an organization to gather data
- **Whois and Host commands**
  - Whois searches a database for domain names and IP blocks
    - Provides detailed registration information such as names, phone numbers, and physical addresses
    - This information can be blocked, generalized, or falsified
    - Historical whois data can be helpful
  - **Host**
    - Provides info about a systems ipv4 and ipv6 addresses and servers
    - Search domain, get related info

### Info Gathering and Aggregation

- Packet Captures
  - Requires an intruder to gain access to a network first
  - Treasure trove of info
  - Utilizes tools like Wireshark
- theHarvester
  - Gathers emails, domains, hostnames, employee names, etc. across a network
- Maltego
  - Build relationship maps between people using Facebook and other publicly available info
  - Allows you to use social engineering to phish up and up a company&#39;s ladder
- Shodan
  - Helps locate internet-of-things devices and identifies their vulnerabilities
  - If attacker can identify a vulnerable device of someone they&#39;ve identified, they have a toehold
  - Can they access someone&#39;s webcam and watch them type a password?

### Organizational Intelligence (Social Engineering and Real-World Monitoring)

- Locations of facilities and buildings
  - Physical security posture from google earth
  - Business hours
- Work routine of organization
- Organizational charts
  - Departments and hierarchies
- Documents
  - Metadata - author&#39;s name and software version
  - EXIF Data - geolocation coordinates on photos
  - Scrub metadata and exif before making anything public
  - Outdated docs can be found on the internet archive, time travel service, google cache, etc.
    - These docs may still contain vulnerable metadata
- Financial Data
- Employee personal info
  - **Immersion**
    - MIT app that allows you to go through emails to figure who someone talks to, how often they talk to them, etc.
  - Social Media
    - People are too free with info, and too willing to make friends
  - Public Record Search
    - Credit scores, background checks, home address, etc
- All this data can be used to improve attacker&#39;s credibility during phishing and social engineering exploits

![](RackMultipart20200608-4-10inig7_html_38e2575f6c462b23.png)

### Detecting, Preventing, and Responding to Recon

- Recon does not guarantee a successful attack
- **Detecting Recon**
  - Perform Data Collection for analysis
  - **Anomaly Analysis**
    - What&#39;s different, what&#39;s abnormal?
  - **Trend Analysis**
    - Identify future problems based on past data
  - **Signature Analysis**
    - Fingerprint or hash used to detect threats
  - **Heuristic Analysis**
    - Detect threats based on behavior
    - Identify unknown threats
  - **Manual Analysis**
    - Human expertise trolling through logs
- **Preventing Recon**
  - Employ firewalls and network defenses
  - Limit external exposure of services
  - Utilize an IPS to limit or stop scanners
  - Utilize monitors and alerts for signature/heuristic/anomalous activity
  - Control info release
  - Blacklist abusive services
  - Use CAPTCHAs to prevent scripts and bots
  - Utilize third-party registration for your domains and IPs
  - Set rate limits for lookups and searches
  - Avoid publishing zone files
  - Educate your users about social media risks

# Domain II: Vulnerability Management

- Broadly: How do you scan for vulnerabilities and respond to them within the context of your company.
- &quot;Identification, prioritization, and remediation of vulnerabilities before a threat can exploit them.&quot;

## Regulatory Requirements

- HIPAA, GLBA, FERPA - govern info storage and processing
- PCI DSS, FISMA - require vulnerability management program
- All set out requirements based on the kind of business you do and the data you handle
- Corporate Policy can mandate additional requirements

#### PCI DSS - Payment Card Industry Data Security Standard

- Security controls for credit card processors and merchants
- Most specific of any vulnerability management
- Vendor-driven, not legally mandated
- EX:
  - Internal and external scans must be conducted
  - **Scanned at least quarterly, and after all major changes**
  - Internal scans by qualified personnel
  - External scans by approved scanning vendor
  - High-risk vulnerabilities must be remediated until a &quot;clean&quot; report is achieved
- **PoS Malware - Point of Sale Malware**
  - Malware that circumvents encryption by stealing credit card info directly from memory

#### FISMA - Federal Information Security Management Act

- Security controls for govt, or anyone handling govt data
- Systems are classified as low, moderate, or high impact
  - Requirements based on those classifications
- Objectives designed around CIA Triad
- EX:
  - Scan system when new threats emerge
  - Utilize interoperable tools and techniques
  - Analyze scan reports from assessments
  - Remediate vulnerabilities based on risk
  - Share findings with other agencies to mutually eliminate vulnerabilities

#### HIPAA – Health Insurance Portability and Accountability Act

- No specific scanning requirements but annual risk analysis with scan required

## Scanning

- **Scan Targets**
  - What do you scan, and why?
    - All systems, or merely critical?
    - Time and effort
  - What tools do you use?
    - **QualysGuard** can be used to build an automatic **asset inventory**
    - Admins can take that asset inventory and set priorities for scans
- **Scan Frequency**
  - Continuous, daily, weekly, yearly?
  - Determined by goals, requirements, and capacity
  - Automated reports can save time and effort
    - **Tenable&#39;s** _ **Nessus** _ **Vulnerability Scanner**
    - Automatically identifies vulnerabilities
- **Scanning Tools**
  - **QualysGuard**
    - Port scans, vulnerability scans, scheduling, asset management, etc.
  - **Nessus**
    - Port scans, vulnerability scans, scheduling, asset management, etc.
    - **H** as default policies to meet certain regulatory requirements
  - **Nexpose**
    - Port scans, vulnerability scans, scheduling, asset management, etc.
  - **OpenVAS**
    - Open-source, low cost, good for home network security
  - **Nikto**
    - Web Application Scanner
    - Other tools are good on the database and network, but Nikto supplements by looking at the code of the app
  - **Microsoft&#39;s Baseline Security Analyzer**
    - Client-side to monitor for updates, registry changes, firewall, hashing, etc.
    - Home use, not effective for central network scan
  - _Be prepared to recognize these products, more than their details!_
- **Scanning Scope**
  - What networks and systems are covered?
  - What tests are performed on each asset
  - Staff and management should know what/when is being scanned
  - **Minimizing the Scope**
    - Network segmentation allows you to scan smaller clusters to achieve regulation compliance
      - If only one machine is processing credit cards, only it needs to meet PCI DSS standards **IF** you segment it properly
    - Increases security, and decreases labor

- **Configuring Scans**
  - Scheduling
  - Producing reports
  - Authenticated Access for Scans
  - Plugins and Scan Agents
  - Scan perspective: internal v external
- **Scanning Sensitivity**
  - Anyone else think scope, targets, and sensitivity overlap hard?
  - Certain targets, such as production environments, require lighter scans or **safe scans** to prevent taking them down during production hours
  - Some scans can disrupt systems or cause loss of data
  - **Plugins** can be grouped by &quot;family&quot; to focus on certain environments
  - **Templates** can be used to group settings and plugins for certain situations/environments/times.
    - Useful if you have a light weekly scan, and a heavier monthly scan, etc.
    - Prevents config errors
  - **Nessus** has default policies to meet certain regulatory requirements
- **Scanning Perspective**
  - Insider threat viewpoint
  - Attacker threat viewpoint
  - Different perspectives may highlight different issues
  - Some regulatory bodies require both internal AND external scans
  - Useful to get the internal worked out before you hire an external group
- **Authenticated/Credentialed Scanning**
  - What Rights does the scanner have while traversing servers, apps, firewalls, etc.
  - Without credentials, scanner can appear as an attacker
  - Scanner should have **read only** rights so that if it becomes compromised, it&#39;s still limited
  - **Agent-Based Scanning**
    - Install agent on each client to provide an &quot;inside-out&quot; perspective of vulnerabilities
    - Data then sent to centralized server for review
    - Can be resource intensive, but provides a very detailed view
- **Maintaining Scanners**
  - Scanners _must_ be updated before use
  - They can become vulnerable themselves, but also need the latest signatures to catch up-to-date threats
  - Vulnerabilities are unavoidable, but can be managed
- Other Considerations:
  - **Organizational Risk Appetite**
    - How much risk are you willing to handle?
    - Determines scan frequency
  - What Regulatory Requirements do you have?
  - How long does a scan take can determine how often you can scan?

## Remediation

- **Standardizing Vulnerabilities**
  - **SCAP - Security Content Automation Protocol**
    - Led by NIST SP 800-117
    - **CCE -** Common _ **Configuration** _ Enumeration
      - Naming convention for system config
    - **CPE** - Common _ **Platform** _ Enumeration
      - Standard names for products and versions
    - **CVE - Common Vulnerabilities and Exposure**
      - Standard names for security-related software flaws
    - **CVSS - Common Vulnerability Scoring System**
      - Standard approach for categorizing severity of software flaws
      - 10 = most critical
      - 1 = least critical
    - **XCCDF** - Extensible Configuration _ **Checklist** _ Description Format
      - Checklist and reporting standards
    - **OVAL -** Open Vulnerability and Assessment Language
      - Low-level testing procedures for XCCDF checklist
- **Workflow for Remediation**
  - **Vulnerability Management Lifecycle:**...Detection -\&gt; Testing -\&gt; Remediation -\&gt; Detection...
  - Continuous Monitoring provides for early detection
  - Automation
    - Many scanner products can automatically create tickets for remediating detected vulnerabilities, and automatically close when vulnerability is fixed
- **Vulnerability Reporting**
  - Analysts need to communicate known issues to SysAdmins
  - Scanners provide detailed reporting that can automatically alert sysadmins periodically
  - Low-priority vulnerabilities can wait, but critical must be communicated immediately
  - **Dashboards** provide a high-level summary that&#39;s easy to understand at a glance
    - Can indicate priorities, trends, etc
    - Host Overview allows you to see which hosts are most vulnerable
      - Useful for allocating remediation resources
    - Overview of Criticality shows the worst vulnerabilities at the top
- **Remediation Priority**
  - CVSS scores and priorities can help you know what vulnerabilities are worst, but you can&#39;t fix everything, and some fixes cost more time, money, and resources
  - How critical is the system and the information it contains?
    - If a system has a lot of PII, financial, or classified data, it needs fixed.
    - If all the data is encrypted, it might be less dangerous if it&#39;s accessed.
  - How difficult is it to fix the vulnerability?
    - If you can fix four vulnerabilities for the same cost as one, well… prioritize
  - How Severe is the vulnerability?
    - CVSS score helps here.
  - How exposed is a server to that vulnerability?
    - If an external facing server has a moderate vulnerability, it might pose a greater risk than a critical vulnerability on an internal server.
  - A lot of these are judgment calls, rather than clear-cut.
- **Implementing and Testing**
  - Vulnerability Analysts do not implement fixes
    - Sysadmins do.
    - Larger fixes need to be run by a Change Control Board
    - Fixes must be tested in a lab environment to ensure they don&#39;t break things worse
  - Analysts view fixes as the highest priority, but not everyone does
    - Fixes often must avoid causing service degradation or breaking promises to customers
    - Scanning, patching, etc. can slow, or take down systems
    - Operations and Security are always in a struggle of balance
  - MOUs and SLAs
    - Security team needs to be involved in their formulation
    - Must address scope of security needs
    - Times for scanning, patches, etc.
  - IT Governance
    - Even in an emergency, it can be necessary to get higher-ups to approve actions which will affect production to push fixes

## Analyzing Vulnerability Scans

- While scanners identify vulnerabilities, analysts must interpret those results
  - Eliminate False Positives
  - Identify root causes
  - Prioritize Remediation
- Parsing Reports
  - Identities
  - Synopsis
  - Description
  - See Also
    - References on the vulnerability
  - Solution
    - List of patches or contingencies for if your system is unsupported
  - Risk Factor
  - CVSS Score
    - 0 is newer, and not addressed on the exam. Recognize 2.0
  - STIG Severity
    - Military - cat 1 is critical, cat 3 is informational
  - References
    - Related vulnerabilities to the plugin
  - Exploitable With
    - Good way to know how prevalent the methods of attack are
  - Plugin Info
    - When the plugin to scan the vulnerability was made
  - Hosts
    - Where the vulnerability exists

### **CVSS Scores** - Common Vulnerability Scoring System

- Industry standard for identifying severity of a vulnerability
- Measured in six categories, based on exploitability and impact
- Each of the below categories is assigned a value - these values are used in a formula to create the ultimate value between 0-10, 10 being the highest vulnerability
  - Exploitability
    - &#39; **AV&#39; - Access Vector Metric**
      - **L** ocal
      - **A** djacent Network
      - **N** etwork (Remote Access)
    - &#39; **AC&#39; - Access Complexity Metric**
      - High - Specialized conditions
      - Medium - &quot;somewhat specialized&quot;
      - Low - no specialized conditions
    - &#39; **Au&#39; - Authentication Metric -** number of times attacker must authenticate on access route
      - Multiple
      - Single
      - None
  - Impact
    - &#39; **C&#39; - Confidentiality Metric**
      - None
      - Partial
      - Complete (loss)
    - &#39; **I&#39; - Integrity Metric**
      - None
      - Partial
      - Complete (loss)
    - &#39; **A&#39; - Availability Metric**
      - None
      - Partial
      - Complete (loss)
  - CVSS metric shows all these values on a single line
    - AV:N = Access Vector, Network
- **CVSS Score Categories**
  - \&lt; 4.0 = low
  - \&gt; 4.0 and \&lt; 6.0 = medium
  - \&gt; 6.0 and \&lt; 10.0 = high
  - 0 = Critical

- **CVSS Temporal Score**
  - Base scores stay the same, but the temporal score changes as vulnerabilities are addressed and mitigated
  - **Exploitability**
    - U - Unproven
    - P - Proof-of-Concept
    - F - Functional
    - H - High
      - When it can be automated, or is super easy
    - ND - Not Defined
  - **RL - Remediation Level Metric**
    - O - Official Fix
    - T - Temporary Fix
    - W - Workaround
    - U - Unavailable
    - ND - Not Defined
  - **RC - Report Confidence**
    - UC - Unconfirmed
    - UR - Uncorroborated
    - C - Confirmed
    - ND - Not Defined

### Validation of Results

- **False Positives**
  - False Positive Error Rate
  - If a report says a patch is missing, check
  - Verify configs
- **Documented Exceptions**
  - Known issues that you don&#39;t plan to deal with or have properly mitigated
  - Implement exceptions in the scan so it doesn&#39;t keep firing the alerts
- **Informational Results**
  - Not everything reported is a vulnerability
  - Some configs just allow attacker to perform some recon
- Compare results with other sources, like log files, config files, SIEM utilities
- Conduct Trend Analysis
  - Understand why you sometimes find more vulnerabilities (patch Tuesday?)
  - Notice when sudden issues appear

## Common Vulnerabilities

- There are thousands
- Five Basic Categories (the next headers)

### Server and Host Vulnerabilities

- **Missing Patches**
  - If nobody installs a patch, it can&#39;t do anything
- **Unsupported Software**
  - Keep track of software EOL - End of Life
  - After that date, nothing gets patched (usually)
- **Buffer Overflows**
  - Tricking systems to run code or release data by forcing data into a section of memory
- **Privilege Escalation**
  - Pushing access from normal user, to root, admin, or superuser
  - An attacker can use a toehold to gain full control
- **Arbitrary Code Execution**
  - Allows attacker to run software on a system
- **Insecure Protocol Use**
  - Using unsecured protocols like FTP or Telnet
- **Debugging Modes**
  - Allows attackers to get a lot of background information for other exploits
  - Debug mode should be left off
- **PoS Malware - Point of Sale Malware**
  - Malware that circumvents encryption by stealing credit card info directly from memory

### Network Vulns

- Missing Firmware Updates
- **SSL and TLS Issues**
  - Must use TLS 1.2 or newer
  - Must use current, secure ciphers
  - Certificates must remain valid and uncompromised
- **Domain Name Server Issues**
- **Internal IP Disclosure**
  - Bad packet headers revealing information that should be hidden by NAT
- **VPN Issues**
  - Protocols, encryption tunnels can be vulnerable

### Virtualization Vulns

- **VM Escape**
  - Break from the virtual machine, and reach the hypervisor (host)
  - Uncommon, but very dangerous
- **Management Interface Access**
  - Access to the configuration utility for virtual machines
- **Virtual Host Patching**
  - Host, and all guests must be patched
- **Virtual Guest Issues**
  - Vulnerability scans can&#39;t stop at the host, need to check the guests as well
- **Virtual Network Issues**
  - Virtual firewalls, routers, and switches must be patched and scanned

### Web Application Vulns

- **Injection Attacks**
  - SQL inject is most common
  - Send commands through web server backend to bypass normal controls
  - Input Validation
- **XSS - Cross Site Scripting**
  - When a website secretly executes a script
  - User is the usual victim, but this can open further vulnerabilities
- **CSRF - Cross Site Request Forgery**
  - Cause a user to perform actions on a website they are already authenticated on
    - A website sees you are logged into your bank, and sends the command to your bank to transfer money out without you knowing
- **Web Application Scans**
  - Go beyond Nessus and Qualysguard - try Nikto within Kali Linux

### IoT - Internet of Things Vulns

- **Smart Devices**
  - TVs, thermostats, or google homes that connect to the internet and can be hard to patch and secure
- **SCADA - Supervisory Control and Data Acquisition Systems**
  - Used in powerplants and such
  - Sensors and agents can remain unsecured
    - These entities should be on an isolated network segment
- **ICS - Industrial Control Systems**
  - Pumps, valves, and pressures controlled by a network computer
  - Firmware must be updated and secured

# Domain III: Cyber Incident Response

- Response to a security incident or event
  - Understand the incident
  - Mitigate negative effects
  - Plan the recovery
  - Investigate Root Cause

![](RackMultipart20200608-4-10inig7_html_989a8360f5ca6258.png)

## Security Incidents

- **Event -** Any observable occurrence in a system
  - Can be good or bad - such as logon event, or incorrect password event
- **Adverse Event** - Any event that has a negative consequence
- **Incidents** - An imminent threat of violation, or a violation, of a security policy, acceptable use policy, or security standard practice
  - Coworker logging in under your account credentials, against policy
  - Coworker downloads and installs malware
- **CSIRT - Computer Security Incident Response Team**

### Incident Response Team - CSIRT

- Cybersecurity professionals with incident response experience
  - Temporarily include experts for specific subjects such as database trouble
  - Smaller orgs assign CSIRT roles as secondary roles
- **Management&#39;s Role**
  - Ensure funding, resources, and expertise available
  - Make critical business decisions
    - Mitigation vs. Production
  - Communicate with legal or news media
  - Communicate with Stakeholders
- Who?
  - Leader is skilled in incident response
  - SMEs (Subject Matter Experts)
  - IT Support Staff
  - Legal Counsel
  - Human Resource Staff
  - PR and Marketing Staff
- CSIRT can be outsourced
  - Must understand the third-party&#39;s guarantees, response time, and expenses
  - Third-party must be trusted
  - Scope must be clearly articulated
    - You could outsource analysis, but remediate in-house
- **Scope of Control**
  - What triggers CSIRT?
  - Who authorizes the activation?
  - What is each CSIRT&#39;s focus?
  - Can CSIRT talk to law enforcement?
  - Can CSIRT talk to media?
  - How does CSIRT escalate the issue?
- **Testing the Team**
  - Train through the plan
  - Simulate and pentest

### Incident Response Phases

- NIST SP 800-61 is a handy guide, but not mandated
- Four phases are cyclical and feed into one another

#### Preparation

- Requires proper policy foundation
- Useless without existing, proper defenses
- Includes training with proper response tools
- **Preparation Tool Kits**
  - Digital Forensic Workstation
  - Forensic Software
  - Packet Capture Devices
  - Spare Servers/Network Gear
  - Backup Devices
  - Blank Removable Media
  - Collection, analysis, and reporting laptops
  - Portable Printers
  - Evidence Collection Materials
- Tools should be tested regularly

#### Detection and Analysis

- Hardest to Standardize
- Tools are helpful, but skilled analyst is necessary
- Analysts shift from detection, to validation, back to detection
- **Alerts**
  - IDS/IPS
    - Host-based/Network-based
      - SNORT
      - Suricata
    - Signature/Anomaly-based
      - Bro
    - Standalone/part of another platform such as NGFWs
  - SIEM
  - Anti-Virus
- **Logs**
  - From OS, services, apps, network devices, and network flows
- **Publicly Available Info**
  - News, media, and open-source info
- **People**
  - Reports from admins and users
- **Best Practices**
  - Understand Baseline
  - Create good logging practices
  - Conduct Event Correlation
    - Keep device times synced
  - Maintain Organization Knowledge Base
  - Capture network traffic ASAP during incident
  - Filter information to reduce confusion
  - Know when to consult experts

#### Containment, Eradication, and Recovery

- Stop the spread, remove it from network, and recover
- **Five Steps**
  - **Pick Containment Strategy**
    - Isolation, or shutdown?
  - **Limit Damage**
  - **Gather Evidence for legal action**
  - **Identify Attacker/Attacking System**
  - **Remove Effects of Incident, Recover normal Actions**

#### Post-Incident Activity

- Recreate a timeline of the incident
- Identify root cause of intrusion/incident
- Consult with sysadmins and management on findings
  - Utilize timeline and root-cause report to address vulnerabilities, improve response time, evaluate response successfulness, and prevent future attacks
  - What did we do well?
  - What can we do better?
- Evidence Retention
  - Understand legal requirements for what data you retain
  - Archive whatever you need to keep, usually 2-3 years minimum

### Incident Response Policies and Procedures

- Foundation of Orgs Incident Response Program
  - Provides authority for response efforts
  - Approved by CEO/CIO
  - Should be relatively timeless and rarely need updating
- Contents
  - Statement of management commitment
  - Purpose
  - Objectives
  - Scope
  - Definitional Terms
  - Roles, responsibilities, and authority
  - Incident prioritization
  - Performance Measure for CSIRT
  - Reporting Requirements
  - Contact Info - by position, not name
- Incident Response Procedures
  - Detailed Info
  - Step-by-step guidelines
- **Playbook**
  - Describes response to high severity incidents
    - Data breach
    - Phishing Attacks
    - Web server compromise
    - Loss of corporate laptop
    - Network Intrusion
- **Communication**
  - How does CSIRT communicate among each other?
  - How will management communicate with employees?
  - Out-of-Band Communication is important if network is compromised
  - When/How will you communicate with law and media?
  - Consider
    - Law Enforcement

    - Information Sharing Partners
    - Vendors
    - Collaterally Affected Orgs
    - Media or Public or Customers

#### Incident Classification

- Methods of Attack
  - Removable Media
  - Attrition
    - Brute-force
  - Web
  - Email
    - Attachments or Spoofing
  - Impersonation
    - Spoofing, SQL Inject
  - Improper Usage
    - Violation of Policy
  - Loss or Theft of Equipment
  - Unknown
  - Other
    - Known origin, but not quite a category
  - **APT - Advanced Persistent Threat**
    - Highly funded/skilled attackers that are willing to work overtime, or wait
    - Could have access that they aren&#39;t actively exploiting

- Severity
  - Functional Impact
    - none, low, medium, or high
  - Economic Impact
    - none, low, medium, or high
  - Recoverability Impact
    - Regular, supplemented, extended, or not recoverable
  - Informational Impact
    - None, privacy breach, proprietary breach, integrity loss
    - OR - Regulated info breach, intellectual property breach, confidential proprietary breach
- Data classifications
  - **PII** – Personally identifiable information (SSN, DOB, etc.)
  - **PHI** – Protected health information (Diagnosis, prescriptions, etc.)
  - **PCI** – Payment card information (Credit card numbers, expiration, etc.)
  - **Intellectual Property** – Company secrets, formulas, etc.
  - **Corporate Confidential** – Accounting data, customers, etc.

## Network Event Monitoring

- Gather, correlate, and analyze data across systems
- **Router-Based Monitoring**
  - Provides data flow and status
  - Relies on capturing data _about_ the traffic
- **Network Flows** _(Think Pcap as a phone call vs. Netflow as call history)_
  - Netflow, sFlow, J-Flow
    - Samples traffic to find out connection types and speeds of data
  - RMON
    - Operates at layers 1-4 of OSI
    - Client/Server model with probes
    - Statistics, history, alarms, and events, reported to **MIB - Management Information Base**
  - SNMP - Simple Network Management
    - Collects info about routers/switches and centralizes them
    - Gathers info about _devices_, not _flow_
    - Only V3 is secure
- **Active Monitoring**
  - Request is sent to a remote system which responds by sending data to a central location
    - Availability
    - Routes
    - Packet Delays
    - Packet Loss
    - Bandwidth
  - Ping/ICMP
  - iPerf
    - Measures max bandwidth of a network
    - Remote testing of a link
    - Useful for determining network baseline
- **Passive Monitoring**
  - Uses a network tap to copy all traffic between two devices
  - Useful between router and firewall
  - Useful for after-the-fact analysis
    - Rates of traffic
    - Protocols used
    - Content

### Network Monitoring Tools

- **Wireshark**
  - Passive monitoring and packet capture
  - Useful for packet analysis
- **SolarWinds**
  - NetFlow Traffic Analyzer
    - solarwinds.com
    - Great for seeing where flow is heaviest
  - Network Performance Monitor
    - What&#39;s up, what&#39;s down, what has errors
- **PRTG - Paessler Router Traffic Grapher**
  - Like SolarWinds, but free
  - Packet sniffing
  - Flows
  - SNMP
  - WMI - Windows Management Instrumentation
- **Nagios**
  - GUI for network and system log monitoring
  - What&#39;s up, what&#39;s down, flow monitoring, etc.
  - Nagios uses &quot;Criticals&quot; that are not like NIST, but set by the user
- **Cacti**
  - SNMP polling of network devices

### Detecting Network Events

- Analysis of logs and other data will allow analyst to determine when an event becomes an incident
- **Beaconing**
  - Significant warning of a malware or botnet infection
  - Pings/heartbeats that send consistently to a command and control center of an attacker
  - Over HTTP or HTTPS
  - Patterns can vary and be difficult to detect
  - Very common
- **Unusual Bandwidth Consumption**
  - Could be service issues, or a sign of larger trouble
  - First step is attempting to identify the cause of the spike
  - Compare unusual data to baseline network data
- **Link and Connection Failures**
  - Usually hardware, firmware, or software issues such as broken cable or unplugged connector
  - Could be a symptom of a Denial of Service attack
- **Unexpected Traffic**
  - Detected by IDS/IPS, traffic monitoring, or manual observation
  - Understand your baseline to identify what&#39;s unusual
  - Not all unexpected traffic is malicious, but should be investigated
    - Unusual country traffic
    - Unusual service traffic like VPN
  - **Baseline or Anomaly Based**
    - Baseline must be indicative of usual traffic - preferably over a long period of time
  - **Heuristic or Behavior Based**
    - Utilizes signatures or defined rules to identify unusual issues
  - **Protocol Analysis**
    - Is a protocol being used that you don&#39;t run usually?

#### Network Probes and Attacks

- Most incident handling is responding to reconnaissance probes like port scans
- **Denial of Service**
  - Ping of death, or other techniques to overwhelm your system
  - Block the source of the attack
- **Distributed Denial of Service**
  - Many sources attempting to overwhelm your system
  - Detectable by coming from known botnets, or unusual system data
  - **Defense**
    - Block the type of traffic
    - Utilize a distribute network, so you can take down an impacted segment
- **Detecting Rogue Devices**
  - Validate by Mac Address for familiar devices
  - Scan network to identify devices
  - Conduct physical site inspection
- **Rogue Wired Devices**
  - Something plugged into your network illegitimately
  - Block unused ports and validate MAC addresses with Network Access Control
- **Rogue Wireless Devices**
  - These devices can be hard to find
  - **Evil Twin** devices used to trick users to connect to them instead of your network
  - Utilize wireless surveys and maps to identify them

#### Server and Host Events

- Monitor CPU, memory, and drive usage
- Some attacks simply cause memory leaks to crash a server
- Windows resource monitor
  - **Resmon**
  - **Perfmon**
    - Allows remote tracking
- For Linux
  - **Ps**
    - CPU and memory utilization
  - **Top**
    - Like PS, but sorted
  - **Df**
    - Disk Usage
  - **W**
    - Account monitoring
- **Malware and Unsupported Software**
  - Use centralized management tools to inventory software and control installs
  - Antivirus and antimalware
  - Blacklist bad software and files
  - Could whitelist only the apps that you want
- **Unauthorized Access, Changes, and Privileges**
  - SIM/SIEM correlate logs for analysis
    - Authentication logs, user creation logs, security event logs, etc.
    - Enables you to ensure nobody is using privileges or access they should have

#### Service and Application Events

- Are the apps up, running, responding, and logging properly?
- **Non-security issues**
  - Authentication issues
  - Permission issues
  - Services not starting on boot
  - Service failures
  - These issues can lead to security issues or be signs of one
- Windows
  - msc or **sc** in the command line
  - Windows event viewer for logs
- Linux
  - Service -status-all
  - /var/log, tail the log files
- Service Application Behavior
  - Get a baseline
  - Log/alert anything outside the baseline
- **Anomalous Activity**
  - Investigate and solve, identify as known-good, or known-bad
- **New Accounts**
  - Ensure they were authorized
- **Unexpected output**
  - Improper output or garbage output
- **Unexpected outbound communication**
  - Is a service reaching outside the network which shouldn&#39;t be?
- **Service Interruption**
  - Simple issue, or DDoS?
- **Memory Overflows**
  - Causes OS errors and crashes
  - Easier to analyze afterwards than to detect

## Digital Forensics

- Determine changes, activities, or actions that have occurred on a system
- Allows incident responders to determine what occurred by collecting info
- **Documentation**
  - Must follow chain of custody and be properly handled
  - Chain of Custody is easier to maintain by having a second tech validate actions
  - Any data needs date, time, and method of collection
  - Proper handling is essential in case the incident is reported to law enforcement
- Forensic personnel should be trained and CERTIFIED for their evidence to be admissible in court

### Forensic Toolkits

- Special software and hardware for disk imaging and analysis
- Free open source versions, or very expensive versions
- **Digital Forensic Workstation**
  - Powerful computer for data capture _and_ analysis
  - 16+ gigs of ram
  - Lots of storage, preferably RAID
    - Must be capable of containing images of MANY computers
  - Powerful CPU
- **Forensic Investigation Software**
  - Software to capture and analyze forensic images
  - Forensic Toolkit (FTK)
  - EnCase
  - SANS Investigative Forensic Toolkit (SIFT)
  - The Sleuth Kit (TSK)
- **Write Blocker**
  - Could be hardware or software
  - Ensures integrity of captured disk by preventing its data from being written to or changed
  - Hashing improves this integrity
  - Hardware write blockers can be expensive, but are more secure
- **Forensic Drive Duplicator**
  - Simply copies a drive perfectly without wasting the energy of a workstation
  - Useful to have multiple if you&#39;ve got a lot of big drives to copy
- **Wiped Drives or removable media**
  - Clean drives ready to receive disk images
- **Cables and Drive Adapters**
  - Prepare for old tech and new tech
- **Digital Camera**
  - Document system layout and config, labels, etc.
  - Good for fixing something if you must make hasty changes during an attack
  - Pictures back up written documentation
- **Label Maker and Labels**
  - Do not just unhook stuff without keeping track of what it is, where it went, etc.
- **Documentation and Checklists**
  - Playbooks, incident response forms, custody forms, checklists, etc.
- **Mobile Forensic Tools**
  - **SIM Card Extractor**
  - **Connection Cables**
    - Lightning, 30-pin, USB-c, USB micro, an array of proprietary cables
  - **Mobile Forensic Software**

### Forensic Software

- Imaging
  - FTK or EnCase or dd
  - FTK is free, and even documents chain of custody, hashes, and creates metadata tags for analysis
  - Always create a hash, and log it, immediately after capturing an image
  - Bit by bit copies preserve slack, or blank, space, preserving file layout and partitions
- Analysis
  - Creates timeline of system changes including hidden files and metadata changes
  - Validates files against known-good
  - Registry Analysis
  - Log file parsing and analysis
- Hashing/Validation
  - Chain of custody file integrity check
  - Should use MD5 or SHA1/SHA256
- Process and Memory Dumps
  - State of OS and currently running processes from memory
  - Difficult to collect without changing the contents
  - Can capture decryption keys
  - Hibernation files and crash dumps contain similar info
  - **Tools**
    - Fmem and LiME (Linux)
    - DumpIt (windows)
    - Volatility Framework (Any)
    - EnCase or FTK
- Password Cracking
  - Tools like John the Ripper or Cain and Abel
  - Some passwords can take forever to be cracked
  - DOC, XLS, PPT, and ZIP files have specialized tools that can crack those passwords

### Forensic Process

1. What are you trying to find out?
2. Where would that information be?
3. Document your plan.
4. Acquire/preserve the relevant evidence
5. Perform initial analysis (log actions)
6. Conduct deeper analysis (log actions)
7. Report your findings

- **Order of Volatility**
  - CPU Cache, Registers, Running Processes, and Memory
  - Network Traffic
  - Hard Disk Drives and USB Drives
  - Backups, Printouts, Optical Media
- What do you do when you find something you did not expect?
  - Evidence of illegal activities, or activities against policy
  - Stop everything
  - Call either management, or law, if relevant.
  - Seek guidance

#### Target Locations

- Windows Registry
  - Information about files and services, locations of deleted files, evidence of applications run
- Autorun keys
  - Programs set to run at startup
- MFT - Master File Table
  - Details of inactive/removed records
- Event Logs
  - Logins, services start/stop, evidence of apps being run
- INDX Files and Change Logs
  - Evidence of deleted files, Mac timestamps
- Volume Shadow Copies
  - Point-in-time information from prior copies
- User directories and files
- Recycle bin contents
- Hibernation files and memory dumps
  - Artifacts of run commands, possible encryption keys
- Temporary directories
  - Artifacts of software installs, user temporary file storage
- Removable Drives
  - System logs may indicate drives were plugging in
  - USB Historian

#### Incident Containment

- Containment can be quick and dirty
  - Can cause loss of business functionality
  - Coordinate with stakeholders to perform risk analysis - but quickly
- **Segmentation**
  - Isolate infected network segments, and try to cut them off from unaffected segments
  - Routers and firewalls are typically the delineation marks
  - Jump Box: Hardened server that must be accessed prior to access to sensitive areas

![](RackMultipart20200608-4-10inig7_html_bce18cdae5190fbe.png)

- **Isolation** or Removal
  - Remove infected segments entirely
  - Recognize you lose their function and perform cost benefit analysis
  - You can isolate segments by allowing them to continue to work, while disconnecting them from the rest of the network
- Objective of Containment
  - Is it worse to take a system offline, or leave it running to spread infection or allow an attacker to move further?
- Identifying Attackers
  - Is this important?
  - It might not matter as much as stopping the attack
  - It might be too expensive and difficult to be worth pursuing - especially if that&#39;s not your business goal
  - Law enforcement might be willing to pursue it further, using the data you collected

#### Eradication and Recovery

- **Remove any artifacts of the incident**
  - Revert all changes and restore backups or rebuild the system
- Restore network to full functionality and correct deficiencies
- Remove malicious code, sanitize compromised media, and fix affected user accounts
- **NOT** Rebuilding the whole network
- **NOT** Buying all new equipment
- **Reconstruction and Reimaging**
  - Reimage or restore to before the attack, because you don&#39;t know what an attacker might have hidden
  - Consider if root cause might affect other systems
- Rescan and patch all systems
- **Sanitization and Disposal**
  - Clear - write all data to 0s
  - Purge - degauss or overwrite with 35x 0s
  - Destroy - Shred, incinerate, chemicals, etc.
  - Take the more extreme measures if your data is very secure, and very vulnerable
- **Validation Effort**
  - Check everything against baselines
  - Ensure only authorized user accounts remain
  - Verify permissions, logging, and scan config

#### Finishing the Response

- Change Management Process
  - Many changes may have been made quickly or hastily
  - Make sure you go back through those changes and document properly according to CM
- Lessons-Learned meeting
  - Document details, root cause, and solution
  - Conduct these meetings immediately after incident
  - Identify needed changes and plan to implement
    - This might require seeking permissions, funding, and resources
- Final Lessons Report
  - Established organizational &quot;memory&quot; for future techs to review
  - Useful for further legal action
  - Should Include:
    - Timeline
    - Root Cause
    - Location and description of evidence collected
    - Actions taken for containment, eradication, and recovery
    - Impact to org in time and money
    - Post-recovery validation results
    - Documentation of Lessons-learned

# Domain IV: Security Architecture and Tool Sets

## Policy Frameworks

### Policy Documents

- High level statements of intent
- Broad statements of security objectives
- **Policy Examples**
  - Information Security Policy
  - Acceptable Use
  - Data Ownership
  - Data Classification
  - Data Retention
  - Account Management
  - Password
- Policy usually approved by the C-Suite or management
- **Standards**
  - Mandatory Actions, steps, or rules
  - Approved below C-Suite
  - Standards also exist across the industry, so can be borrowed
- **Procedures**
  - Step-by-step instructions to perform an action
  - Creates consistent methods and outcomes for security objectives
- **Guidelines**
  - Recommendations, not requirements
  - Flexible so users can adapt to unique situations
  - Easily, quickly changed
- **Exceptions**
  - Framework should have method for granting &quot;exceptions&quot; to rules
  - Usually signed by higher managers, indicated within framework
  - Should understand:
    - What rule is being broken
    - Why it&#39;s being broken
    - Scope and duration
    - Risks associated
    - Risk Mitigations

### Standard Frameworks

- Your company/team doesn&#39;t need to build everything out manually - frameworks exist to simplify this process
- **NIST - National Institute Standard of Technology**
  - Describe Current Posture
  - Describe Desired State
  - Identify/Prioritize areas for improvement
  - Assess progress toward desired state
  - Communicate risk among stakeholders
  - **Tiers**
    - Partial
      - Informal, Reactive
    - Risk Informed
    - Repeatable
      - Understands dependencies and partners
    - Adaptive
      - Formal, well-thought-out, good with partners, etc.
    - TLDR: How well prepared your company is
  - **Risk Assessment**
    - Threats
    - Vulnerabilities
    - Likelihood
    - Impact
- **ISO 27001**
  - Used to be most common standard
  - International
  - Regulated companies are required to use this, but many switching to NIST
  - 14 Categories
- **ITIL - Information Technology Infrastructure Library**
  - Security Management Meets Service Business Needs
- **COBIT - Control Objectives for Information and Related Technologies**

    - Plan and Organize
    - Acquire and Implement
    - Deliver and Support
    - Monitor And Evaluate
  - Less popular than the others
- **TOGAF - The Open Group Architecture Framework**
  - 4 Domains: Business, Application, Data, and Technology - working together in harmony
    - ...but everything changed when the application nation attacked
    - **Technical Architecture** supports the other domains
    - **Business**** Architecture** defines governance and organization
    - **Application Architecture** includes the apps and systems
    - **Data Architecture** is company&#39;s approach to storing and managing assets
- **SABSA - Sherwood Applied Business Security Architecture**
  - Like TOGAF
  - Uncommon

### Policy-Based Controls

- Physical Controls
- Logical Controls
- Administrative Controls
- Combining Control Objectives is obviously better

### Audits, Assessments, Laws, and Regulations

- Guidelines are worthless if you&#39;re not inspecting and enforcing them
- **Audit** - Formal, usually internal, review of security guidelines and procedures
  - Checks specifically to make sure things have been done right
- **Assessment** - Informal review of controls and procedures
  - Mostly asks about stuff, instead of checking specifically
- Confirm **Compliance** with a regulatory body over your data and systems
  - **HIPPA - Healthcare**
    - If you secure any info for patients or healthcare products, this is you
  - **GLBA - Gramm-Leach-Bliley Act**
    - At least the name is memorably
    - Financial controls and security programs
    - Designates a &quot;responsible&quot; individual - usually CFO or CIO
  - **SOX - Sarbanes-Oxley Act**
    - Involves the security around financial systems for publicly traded companies
    - Mostly to make sure companies can be audited properly without &quot;accidentally&quot; destroying their own info
  - **FERPA - Family Education Rights and Privacy Act**
    - Privacy controls for educational records
    - Only students or teacher can access a student&#39;s info
  - **PCI DSS - Payment Card Industry Data Security Standard**
    - Contractual obligation, not a law
    - How you secure and handle credit services and data
    - Requires external audits of compliancy
  - Data Breach Notifications
    - Usually state law
    - Reporting standards to customers so they can protect themselves
  - Really just know the category of each acronym

## Defense In Depth

- Security must be redundant and varied, to prevent any single point of failure and to slow attackers long enough to rebuff them
- **Layered Security Defense**
  - Data \&gt; Application \&gt; Endpoint Security \&gt; Network \&gt; Perimeter
    - Perimeter as outermost layer
  - Difficult to design without affecting business needs
- Four Design Models
  - **Uniform Protection**
    - Same level of protection for all systems
    - Best for smaller networks
    - Expensive for large networks
  - **Protected Enclaves**
    - Higher protection for more secure data
    - Credit ops has more than internal network, which has more than web server
  - **Risk or Threat Based**
    - Employing specific controls based on the threats and risks you&#39;re most worried about
  - **Information-Classification Based**
    - Map data protection to different classes of information
    - Secret, Classified, Top Secret, etc.
    - Higher classifications get additional attention and security controls
  - **Combining Design Models**
    - Combination of above models

### Types of Controls

- Controls prevent, detect, counteract, or limit security risks
- **Technical Controls**
  - Firewalls, IDS/IPS, Authentication Systems, Network Segmentation
- **Administrative/Procedural Controls**
  - Security through policies and procedures
  - Incident Response Plans
  - User Awareness Training
  - Account Creation Policies
  - Acceptable Use Policy
  - Legal Controls
- **Physical Controls**
  - Gates, fences, mantraps, and fire suppression systems
- **Preventative Controls**
  - Proactive measures
  - Stop an incident before it happens
  - Security Guards, antivirus, training
- **Detective Controls**
  - Designed to detect when an incident occurs, capture details about it, and send an alarm
- **Corrective Controls**
  - Reactive - incident response
  - Fix an issue when it occurs
  - Patching, backups, etc.
- **Compensating Control**
  - Minimize threat to acceptable levels
  - Blocking ports on an insecure OS
  - Segmenting vulnerable software that you can&#39;t replace into a distinct network segment

#### Layered Network Defense

- Can be accomplished through
  - Network Segmentation
    - Compartmentalization (synonyms are FUN)
    - Increases availability and efficiency
    - Makes it harder for incidents to spread
    - Implemented through _firewalls,_ routers, switches, and VLANs
  - _Firewalls_
    - **Single** _ **Firewall** _ **or Router**
      - Isolates a segment into a DMZ
      - Router must have good ACL
    - **Multiple Interface** _ **Firewall** _
      - Different ACL and rulesets apply to each interface, creating multiple network segments
      - Requires a fancy expensive _firewall_
    - **Multi-Firewall**
      - Different _firewalls_ at each control point
      - Allows for more stringent controls
      - Can use multiple cheap firewalls, instead of an expensive one
  - Outsourcing Network Segments
    - Remote Services
      - SaaS or PaaS rely on provider&#39;s security
    - Directly Connected Remote Network
      - Acts as an extension of your intranet
      - IaaS with direct point-to-point VPNs
      - Seems like it&#39;s just part of your network, but really uses someone else&#39;s secured system

#### Layered Host Security

- Password and authentication
- Encryption
  - Data at rest
  - Security keys and passwords must be secured
  - Hashing required to maintain integrity
- Host based firewalls or IPS
- Data Loss Prevention software
- White-lists/black-lists
- Patch management
- Antivirus
- System hardening
- Configuration management
- File Integrity Monitoring
- Logging
  - Logs should be centrally stored
  - SIEM can help

#### Data Analytics

- Be ready to correlate data from multiple systems to understand what&#39;s happening
- **Splunk**
  - Syslogs, auth logs, app logs, event logs, and others combined
- **Trend Analysis**
  - Identify future problems based on past data
- **Historical Analysis**

#### Personnel Security

- **Separation of Duties**
  - Each person can only do/access so much
    - One person authorizes a payment, someone else signs it
  - Makes it harder to commit fraud
- **Dual Control**
  - Two people need to perform a single action
  - Check requires two signatures
  - Safe requires two people&#39;s keycards
- **Succession Planning**
  - Don&#39;t allow an employee to be a single point of failure, no matter their position as they come and go
- **Cross Training**
  - Ensure people know more than just their own job
  - If someone quits, make sure you have people to cover
  - If a project gets too big, make sure people can help
- **Background Checks**
  - Make sure people aren&#39;t hidden criminals and in millions of dollars of debt
- **Mandatory Vacation**
  - It&#39;s hard to run fraud if you&#39;re not there
  - Also, it&#39;s a good test to make sure the company can run without you
- **Termination**
  - Make sure people can&#39;t burn the place down on their way out
  - Recover all their devices
  - Disable all their accounts
  - Change any codes that they know
  - Make a checklist so this is the same procedure every time

#### Outsourcing Concerns

- Proper Vetting:
  - What background checks do you perform on the service provider?
  - What background checks does the provider use on their employees?
  - How do they handle internal issues and personnel?
- Access Control
  - What can they touch?
  - How is your data kept separate from another company&#39;s?
- Data Ownership and Control
  - Who owns the data?
  - How is it encrypted?
  - Does the service provider have direct access to that data or the keys?
- Incident Response and Notification Processes
  - What happens during an incident?
  - Will the provider notify you?
  - Will the provider handle it, or just call you in?

#### User Awareness Training

- Train your users
  - AUP
  - Threats faced by organization
    - Like phishing
  - How to report a security issue
  - Physical security concepts
  - BYOD Policy
  - Data handling requirements
    - What can they print?
    - How do they dispose of data, disks, etc.
  - Best practices for passwords, emails, remote work, secure web browsing, etc.

#### Analyzing Secure Architectures

- Attackers are always looking for a flaw
- Pentesters are always looking for single points of failure
- Understand goals and requirements, and check if controls meet those
- **Reviewing Architecture**
  - **Operational View**
    - How a function is performed or what it&#39;s supposed to accomplish
  - **Technical View**
    - Focuses on technologies, configs, and settings
  - **Logical View**
    - Focuses on the connections and paths of the network
- **Common Issues**
  - **Single point of failure**
    - If this one thing breaks, does everything break?
  - **Data Validation and Trust**
    - Don&#39;t assume data, both incoming and resting, remains valid
    - Integrity checks on data at rest with hashing
    - Data validation on any user generated data to prevent SQL injections
  - **Users**
    - Mistakes and abuse cause faults
    - Automate monitoring on users
    - Constrain user access to what they need
      - Users don&#39;t need CLI access
    - Implement checks and balances on all permissions and accounts
    - User awareness training
  - **Authentication and Authorization**
    - Multifactor auth
    - Centralized account and privilege management
      - With checks and balances!
    - Monitor privileged accounts
    - User awareness training
- Analyze through each goal and view
- Identify and report issues
- **Maintaining Secure Architecture**
  - Conduct scheduled reviews
  - Continually improve and stay up on best practices
  - Retire processes that are outdated
  - Reassess how processes work together as they change

## Identity

- **Identity =** User info, rights, credentials, group memberships, and roles
- Name, address, title, contact info, id number, etc.
- **AAA**
  - Authentication
    - Prove you are who you say you are
  - Authorization
    - What are you allowed to access?
  - Accounting
    - A record of what you access and do
    - Logs
- **Account Lifecycle**
  - Create -\&gt; Provision -\&gt; Modify/Maintain -\&gt; Disable -\&gt; Retire/Delete
  - Must Utilize Least Privilege
    - Users with too much access are both threats, and vulnerable
  - Privilege creep
    - validate accounts have the correct rights
    - If someone keeps moving job positions, promotions, etc., they may end up with permissions to a dozen places, which means they can do shady stuff
  - **Identity Lifecycle Management**
    - Centrify, Okta, Ping Identity
      - Help you create, manage, monitor, and report on accounts

### Identity Systems

- **IAM - Centralized Identity Access Management**
  - Create, store, and manage identity info
  - Includes group membership, roles, permissions
  - Used for:
    - Provisioning accounts
    - Authentication
    - Single-sign-on
    - LDAP
    - Account Maintenance
    - Reporting
    - Monitoring
    - Logging
    - Auditing

- **Directory Services**
  - **LDAP - Lightweight Directory Access Protocol**
    - Hierarchical structure
      - dc = domain name
      - u = organizational unit
      - cn = common unit
    - Securing LDAP
      - Enable and require TLS for queries
      - Set password storage to salted hash
      - Disable unauthenticated or anonymous modes
      - Replicate to a redundant server to prevent Denial of Service
      - Strong ACLs to limit access to non-privileged users
    - **LDAP Injection**
      - Like SQL inject
      - Secure web apps and validate queries and input
  - Provides info about systems and users
  - Useful for email and other programs like address books
- **Authentication Protocols**
  - TACACS+
    - TCP to provide AAA services
    - Lacks integrity checking
    - Encryption flaws
    - Bad
  - RADIUS - Remote Authentication Dial-In User Service
    - Common AAA service
    - Password security isn&#39;t great by default
    - Requires IPSec encryption on traffic
  - Kerberos
    - Designed with security in mind
    - Encrypts all data sent
    - Principles (users)
      - Primary - Username
      - Instance - Unique ID
      - Realm - Groups
    - Replaced NTLM for windows domains
    - Review Kerberos ticket system
- **Single-Sign-On SSO**
  - Users authenticate once and gain access to multiple services
  - LDAP
  - **CAS** - Central Authentication Service
  - Reduces password reuse, and less password resets and support calls

  - **Shared Authentication**
    - OpenID
      - Open source standard for decentralized authentication
      - Sign in through google, access everything that relies on them
    - OAuth
      - User shares elements of their info but doesn&#39;t need an account
    - OpenID Connect
      - Uses OAuth info but adds authentication
    - Facebook Connect
      - Basically, OpenID but for Facebook instead of Google

### Identity System Threats

- Logon Exploits
- Credential Handling
- Authorization Process
- Target Account Lifecycle
  - Create credentials
  - Escalate privileges
  - Prevent credential removal
- Phishing
- **Personnel-based Threats**
  - Usually phishing or other social engineering
    - Pretexting: Fabricating a scenario where they need information
    - Tailgating: Bypassing a physical control by following an authorized person
  - Train your users not to share their passwords
  - Insider threats
- **Endpoint Threats**
  - Local exploits on laptop
  - Keyloggers
  - Password stores and tokens
  - Anti-malware and anti-virus and strong authentication will defend against these threats
- **Other Threats**
  - Server-based threats
    - Attacks server to interfere with AAA
  - Application/Service Threats
  - Roles, Rights, and Permission Threats
    - Giving users/accounts additional roles, rights, and permissions

#### Attacking AAA Protocols and Systems

- Directories, AAA and SSO systems are high-profile targets
- **Attacking LDAP**
  - Target unencrypted LDAP traffic
    - Attempting replay attacks
  - Target improper ACLs to harvest info or modify directory
  - Perform LDAP injection against web apps
  - Denial-of-Service
- **Attacking RADIUS**
  - Replay attacks
  - Compromised shares secret key off client machines
  - Brute-force secret keys from stolen passwords
  - Denial of Service
- **Attacking Kerberos**
  - Secure, but popular so high profile target
  - Compromise of Key Distribution Center **KDC** allows attacker to impersonate anyone
  - Stealing Kerberos Tickets allows attacker to impersonate specific user
  - **Ticket Granting Tickets** are especially vulnerable, because these allow an attacker to do pretty much anything on your system
- **Attacking Active Directory**
  - Many existing exploits against clients, servers, and AD domain
  - Many AD domains are outdated and unpatched
  - Malware focused on stealing credentials
  - Attacking older services like NTLM, LANMAN, NetBIOS, unsigned LDAP, and SMB
  - Privilege creep
    - validate accounts have the correct rights
  - Overuse of admin credentials - only use them when you need to perform specific functions
  - Privilege escalation
    - Setup user accounts and admin accounts and name them properly
    - If a user account has admin rights, you have a problem
- Attacking OAuth, OpenID, and OpenID Connect
  - Each service provider implements them uniquely and improper configs can make data vulnerable
  - Original account info - google ID for example - won&#39;t be compromised, but you may be redirected improperly, or attackers may be able to get in unvalidated
  - Early versions of these protocols may be more vulnerable
- **Identity Exploits**
  - Impersonation Attacks
  - Usually credential theft, or OAuth abuse
  - **Session Hijacking**
    - Attacker acquires, or guesses session key
    - Prevented through TLS encryption sessions
  - **Man-in-the-Middle**
    - When attacker taps the data flow and listens in, or takes over
  - **Privilege Escalation**
  - **Rootkits**
    - Uses malware to give attacker access to a server/client continually
  - **SMS Vulnerabilities**
    - Multi-authentication systems that rely on SMS are vulnerable to VoIP attacks
- **Credential Theft**
  - **Phishing**
  - **Compromise other websites**
    - Abusing reused passwords and credentials
    - Dual authentication prevents this risk
  - **Brute-force-attack**
    - Could take millions of years, but it gets easier all the time
    - Captchas and limited login attempts prevent this

#### Securing Authentication and Authorization

- Strong passwords
- Password management
  - SSO
  - Token-based multifactor
  - Password safes (LastPass, Dashlane)
- Encrypt Communication between clients and authenticators
- ACLs to match users with proper right and privileges
- Policies to control right distribution
- Management oversight for approval
- **Securing Auth (Admin)**
  - Privileged Users must be managed and monitored
  - Additional monitoring and logging
  - Separation of Duties
  - Training
  - Prevent admin accounts from being used as daily accounts
- **Multifactor Auth**
  - Knowledge, possession, biometric, location
- **Context Auth**
  - Time of day
  - IP Address
  - Frequency of Access
  - Location
  - Type of Device

#### Identity as a Service (IDaaS)

- Cloud Based AAA
- Make sure you trust your provider
- Will you configure internal/external database?
- Where do you authenticate?
- Where do you store your credentials?
- **Benefits**
  - Can be more secure, capable, and better managed

#### Detecting Identity Attacks

- **SIEM - Security Information and Event Management**
  - Can alert if new privileged accounts are made
  - If privileges change
  - If terminated accounts are restored
  - If unused accounts are lingering
  - Violations of Separation of Duties
  - Can monitor patterns to identify abnormalities
  - **Best part about SIEM: It&#39;s easier to read**
- Humans must analyze these trends and data to see if abnormalities are bad

#### Federated Identity Systems

- Moves the trust boundary to a third party like Google or Facebook
- **IDP - Identity Provider**
  - Third party that houses the identity
- **RP Relying Party or SP Service Provider**
  - You, usually, requesting the identity
  - Members of the federation they provide services to the user when identified
- **Consumer or User**
- **Roughly Four steps**
  - Discovery
  - Validate
  - Register RP Attributes
  - Federation Protocol
- Federated Identity System Technologies
  - **SAML - Security Assertion Markup Language**
    - XML-based
    - Enables SSO for web apps and services
  - **OAuth 2.0**
    - Developed by IETF - Internet Engineering Task Force
    - Designed for HTTP based services
    - Open source
  - **Flickr**
  - **ADFS - Active Directory Federation Services**

## Software Development Life Cycle

- SDLC - Software Development Life Cycle is applicable to other things
- Planning for security earlier makes it easier!
- Phases
  - **Planning**
    - Initial investigations into the effort
    - Feasibility analysis
    - Alternate solutions?
    - Move forward, or buy an off-the-shelf solution
  - **Requirements**
    - Gain stakeholder/customer feedback to determine required functionality
    - What should the program do?
    - What does current program NOT do?
  - **Design**
    - Functionality, architecture, data flows, processes, etc.
    - Basically whiteboarding/flowcharting
  - **Coding**
    - for(){PS|SAPS}  (PowerShell ForkBomb. Beware…)
  - **Testing**
    - Coders already did some testing, now shareholders join in
    - Try to break it
    - See if users are happy with it
    - Ensure security!
  - **Training and Transition**
    - Make sure users can use it
  - **Operations and Maintenance**
    - Longest phase of SDLC
    - Patches, updates, mods, and support
    - Most expensive to update Security at this point
  - **End of Life**
    - How long does software get support?
    - At EoL, support ends, security suffers
    - Users must migrate to new software to maintain security

#### Software Development Models

- **Waterfall Model**
  - Linear model, relatively loose
  - **Requirements**  ****  **Design**  ****  **Implementation**  ****  **Verification**  ****  **Maintenance**
- **Spiral Model**
  - Iterative adaptation of Waterfall
  - Revisits phases repeatedly throughout prototype stages
  - Faster to Minimum Viable Product
- **Agile**
  - Iterative and incremental
  - Function over Documentation
  - Customer collaboration over contract negotiation
  - Responding fast is better than planning
  - **Terms**
    - Backlogs - features to complete
    - Planning Poker - Estimation tool for planning
    - Timeboxes - Agreed upon time to work on specific goal
    - User Stories - High Level User Requirements
    - Velocity Tracking - Add up estimates for current sprint efforts and compare to completion rates
- **RAD - Rapid Application Development**
  - Informal, iterative process, focused on modules and prototypes
  - Highly responsive, no planning phase
  - **Terms**
    - Business Modeling - Understand business process
    - Data Modeling - analyze datasets and their relationships
    - Process Modeling - Define the processes and data flows
    - Application Generation - Convert processes into code
    - Testing and Turnover - Do the inputs and outputs work?
- **Big Bang SDLC Method**
  - One guy in his basement banging it out
- **V Model**
  - Adaption of Waterfall
  - Waterfall down, test back up
  - Costly and time consuming, but quality

#### Coding For Security

- Security isn&#39;t an afterthought - it should be in the requirements
- Security is built during design and coding
- Security is tested in prototypes AND finals
- **Secure Coding Practices**
  - Have an organizational secure code policy
  - Conduct risk assessments to prioritize issues
  - User Input Validation
    - Don&#39;t trust anything you get from the user
  - Consider error messages - how much do you reveal?
  - Database security in application and database
  - Secure data-in-motion
  - Encrypt Stored information
  - Hash passwords
  - Design for availability and scalability
    - Prevent DDoS
  - Conduct Monitoring and Logging
  - If possible, utilize multifactor authentication
  - Code for secure sessions
    - Prevent session hijacking
  - Secure your cookies
  - Encrypt Network Traffic
    - HTTPS or TLS tunnel
  - Secure underlying infrastructure
    - Good code on a bad system can still be vulnerable
- **OWASP - Open Web Application Security Project**
  - Community hosted standards, guides, best practices and tools
  - Proactive controls for testing web app security
  - Top 10 Vulnerability List
  - **ZAP - Zed Attack Proxy**
    - Security Scanner
    - Web proxy
- **Secure Code Management**
  - GitHub
  - Check-in, check-out
  - Revision history

#### Testing Application Code

- Scanning with tools such as automated vuln. scanning tools
- Manual Pentest
- **Code Review**
  - Share knowledge with others and gain more experience across the team
  - Detect problems and enforce good coding
  - Agile and formal models
  - **Pair Programming**
    - 2devs1workstation
    - Costly
  - **Over-The-Shoulder**
    - One dev codes, another dev shows up to see if it makes sense
  - **Pass-Around**
    - Dev codes, then pass it… around
    - Documentation is essential
  - **Tool-Assisted**
    - Formal or informal
    - Marks up code and provides feedback
  - **Fagan**
    - Formal code review by a team of reviewers
    - Specifies input/output for each process
    - More costly and difficult, but effective
- OWASP consider code review the best option

#### Finding Security Flaws

- Static Analysis
  - Code review or scanning
  - Requires access to source code
- Dynamic Analysis
  - Code is executed with specific input and analyzed
  - Automated tools help
  - Test Types:
    - **Fuzzing**
      - Sends invalid data to test ability to handle unexpected data
      - Use large datasets from automated tool
      - Tests for logic issues, memory leaks, error handling, etc.
    - **Fault Injection**
      - Tests error handling functions
      - **Compile-Time Injection**
      - **Protocol Software Injection**
        - Sending FTP instead of HTTP data, etc.
      - **Runtime Injection**
        - Insert data into running memory of the program
    - **Mutation Testing**
      - Make small changes to program to determine if it causes a failure
      - What can bad guys do to the code? (with malware, typically)
    - **Stress Testing**
      - Can app support production load?
      - How does it respond to worst-case scenarios, traffic spikes, etc.?
    - **Security Regression Testing**
      - Ensures that changes made do not create new problems
      - Patch testing, basically
      - Scan, patch, scan

#### Web Application Vulnerability Scanners

- CySA are usually going to be dealing with web app code
- Dedicated web app scanners do better than Nessus, Nexpose, and OpenVAS
- Identify app problems, web server, database, and infrastructure problems
- Examples:
  - Acunetix WVS
  - Archni
  - **\*Burp Suite**
  - IBM App Scan
  - Netsparker
  - QualysGuard Web
  - W3AF
- Better at finding issues with forms, SQL injections, etc.
- Manual Scanning
  - Use an interception proxy to capture communication between browser and server
  - Modify data sent and receives
  - Examples:
    - Tamper Data
    - HttpFox
    - Fiddler
    - \ ***Burp Suite**
  - Allows you to manually try cross-site scripting attacks, injection attacks, etc.
- Learn more about Burp Suite - common, powerful, etc.

## Specific Tools

- Preventative Tools
  - NGFW = Next Generation Firewall

![](RackMultipart20200608-4-10inig7_html_9a92a37f3ea0269.png)

  - Network-Based IDS &amp; IPS

![](RackMultipart20200608-4-10inig7_html_c4298739c5302602.png)

  - Host-Based IPS
    - Only inspects/responds to traffic within the host
    - EMET = Enhanced Mitigation Experience Toolkit
    - Web Proxy

  - WAF = Web Application Firewall

![](RackMultipart20200608-4-10inig7_html_a2e508119f4cbd4f.png)

- Collective Tools
  - SIEM = Security Information and Event Management

![](RackMultipart20200608-4-10inig7_html_e83516f8e33b28ac.png)

  - Network Scanning
    - Nmap
  - Packet Capture

![](RackMultipart20200608-4-10inig7_html_c28c90e36b129da7.png)

  - Analytical Tools

![](RackMultipart20200608-4-10inig7_html_5090e94cf588d5cf.png)

  - Monitoring Tools

![](RackMultipart20200608-4-10inig7_html_94a0b59960fb2c38.png)

  - Interception Proxy

![](RackMultipart20200608-4-10inig7_html_27ad4c42a36ed24e.png)

- Exploitative Tools
  - Exploitation Frameworks

![](RackMultipart20200608-4-10inig7_html_614b4fcd76aa3fb.png)

  - Fuzzers

![](RackMultipart20200608-4-10inig7_html_7847b7b71c522876.png)

- Forensic Tools
  - Forensic Suites

![](RackMultipart20200608-4-10inig7_html_c18193d88f56f914.png)

  - Hashing

![](RackMultipart20200608-4-10inig7_html_36083b92378aedaf.png)

# Performance Based Question Review

- Get familiar with Vulnerability Scan Results
  - Google: Nessus Report Examples
- Analyze Event Logs
- Analyze Server Logs
  - Look for unusual things
  - Lots of invalid logon attempts from the same IP
  - Anything mentioning money, PayPal, payment
  - .exe files on webservers, etc.
  - Exam will be largely obvious - limiting the logs specifically around the nefarious activity
    - Look for repeating IPs, keywords, common ports, server names for clues
    - Look for escalating privileges, admin/system/root accounts
    - Look for users being added to groups, esp. Admin group

![](RackMultipart20200608-4-10inig7_html_1e9a1e495074ed.png) **Protocol IDs**

  - PID 50 - ESP IPsec IPsec
  - PID 51 - AH IPsec Authentication Headers
