![Azure Cloud SOC ](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/8978e62d-823a-4748-94b6-c3dbefd37cf7)

# Introduction

A Security Operations Center (SOC) is a critical part of a company's Information Technology (IT) infrastructure. A SOC is where Cybersecurity professionals such as Analysts and Incident Responders work to protect their organization's network from potential malicious threats such as hackers or insider threats. The job of a SOC Analyst is to monitor their organization's network traffic, triage potential security incidents, and work with cross-functional teams to remediate threats and vulnerabilities. 

# Objective

In this project, I created a mini honeynet within Microsoft Azure. A honeynet is a network that intentionally has vulnerabilities on a server to attract hackers. For this project, the honeynet compromised of three Virtual Machines (VMs). Two VMs were Windows and one was Linux. I intentionally left the Network Security Groups of all VMs vulnerable by allowing any and all inbound traffic. I also disabled the firewall of one Windows VM

To monitor the security events, I enabled logging on all VMs and forwarded the logs to an Azure Log Analytics Workspace. I utilized Microsoft Sentinel, Azure's native Security Information and Event Management (SIEM) system. A SIEM is the core tool used in SOCs to monitor event logs and security events. I configured and deployed Sentinel to monitor the logs to generate alerts, plot the alerts on a world map, and generate incidents. 

I ran the honeynet unsecured for 24 hours. After the 24 hours, I responded to several types of incidents within Sentinel. I used NIST 800-63 as guidance for incident handling. I analyzed the incidents, identified the vulnerabilities, and closed the incidents while recommending remediation points. I utilized NIST 800-53 as guidance and implemented regulatory compliance suggestions and strengthened the security of the honeynet. I also capture the statistics of key security incidents. 

After remediating the vulnerabilities outlined by NIST 800-53, I ran the environment for another 24 hours and captured the statistics again. The statistics captured were:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flow Logs Allowed)

# Utilization 

**Azure**
- Virtual Network (VNet)
- Network Security Groups (NSGs)
- Virtual Machines (Two Windows, One Linux)
- Log Analytics Workspace
- Kusto Query Language (KQL)
- Key Vault 
- Storage
- Microsoft Sentinel (SIEM)
- Microsoft Defender for Cloud

**Microsoft**
- Command Prompt
- Microsoft Remote Desktop 
- Powershell 

**NIST** 
- NIST SP 800-53 Revision 5
- NIST SP 800-61 Revision 2

# Architecture Before Implementation of Security Controls

![Architecture Before](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/becdd761-5ea0-4f83-9fa5-fe5d0783464d)

During the first 24 hours, all resources within the honeynet were exposed to the internet intentionally. The VM's firewalls and NSGs were left wide open. The Key Vault and Storage were configured with public endpoints which were also exposed to the internet. All resources had logging enabled which was ingested and queried by the Log Analytics Workspace and Sentinel aggregates the logs generated to generate alerts and incidents.

# Architecture After Implementation of Security Controls

![Architecture After](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/4e48f45b-b12b-45a7-8535-56369f3ffad3)

After the first 24 hours, security controls were implemented in order to be compliant with NIST 800-53. The following tactics were applied:

- Firewalls: The firewalls of the VMs were enabled and set to block all inbound and outbound traffic. 

- Network Security Groups (NSGs): The NSGs were also enabled and set to block all inbound and outbound traffic. The only traffic that was allowed was the designated IP that was set in the Access Control Lists (ACLs).

- Private Endpoints: To increase the security of the Key Vault and Storage, private endpoints were enabled for these resources. This means that access to these resources was only available from within the private VNet. 

# Attack Maps Before Implementation of Security Controls

The malicious traffic of the Network Security Groups (NSGs):

![NSG Map](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/b28561e8-9070-4558-9fcb-835f1988adf6)

The malicious traffic of the Linux syslog attempt ssh logins:

![Linux Map](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/592eca6b-30d5-496c-95d4-1f94f49a92fb)

The malicious traffic of the Windows attempt Remote Desktop Protocol (RDP) logins:

![Windows Map](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/a4d8d34e-7a73-4c5f-9aa1-c166213b7491)

The malicious traffic of the Microsoft SQL Server (hosted on Windows VM) attempt logins:

![MSSQL Map](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/bba05b9f-073d-42a5-869d-43068fa5af5f)

# Metrics Before Implementation of Security Controls 

Start Time 07/23/2023, 08:44 PM
Stop Time 07/24/2023, 08:44 PM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 22,393
| Syslog                   | 4,673
| SecurityAlert            | 5
| SecurityIncident         | 331
| AzureNetworkAnalytics_CL | 2032


# Investigating Incidents in Sentinel

![Sentinel Windows Brute Force](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/935ef6f8-2b3d-44e5-8dad-76b374019ab5)

![Sentinel Investigate Brute Force](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/a848255e-54fb-48e7-ab46-ccfb9e4e4c7b)

![Sentinel Windows Brute Force KQL Query](https://github.com/BahalaNa0/Azure-Cloud-SOC/assets/120359627/d64fabfc-b8a0-4b00-86ef-8277cb54cc27)

# Attack Maps After Implementation of Security Controls

**The queries of the attack maps did not return any results as there were no instances of malicious traffic during the 24-hour period after security controls were implemented.**

# Metrics After Implementation of Security Controls

Start Time 07/26/2023, 08:22 PM
Stop Time 07/27/2023, 08:22 PM

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 13,649
| Syslog                   | 1
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

# Percentage of Change in Metrics

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | -39.05%
| Syslog                   | 99.98%
| SecurityAlert            | 100%
| SecurityIncident         | 100%
| AzureNetworkAnalytics_CL | 100%


# Conclusion

In this project, I created a honeynet with several Azure resources that were vulnerable to the public internet. The honeynet was very enticing for malicious actors as the security controls were little to nonexistent. Logging was enabled for all resources and was ingested by the Log Analytics Workspace. Sentinel was utilized to trigger alerts and create incidents from the patterns of the event logs. 

It is impressive to see the amount of malicious traffic that was generated prior to applying security controls. After applying the security controls, it was also worth noting the reduction of security events. 

The lesson learned is to always secure the network to reduce the risk of malicious attacks. 
