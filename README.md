# IR Scenario: Virtual Machine Brute Force Detection
```
⚠️ Disclaimer: This repository and github site presents simulated IR scenarios created for educational and portfolio purposes.
Any similarities to real individuals, organizations, or events are purely coincidental. The techniques and methodologies
demonstrated are based on real-world cybersecurity practices but are applied in a simulated environment. This content is
intended to showcase IR skills and analytical thinking for professional development. It does not reflect or promote any actual
security incidents or breaches.
```
## Lab Architecture
![image](https://github.com/user-attachments/assets/72ab5e45-e99c-481f-91fe-34aad3079c7c)


## Overview
```
In this incident response lab, I began by creating an analytics rule in Microsoft Sentinel to detect brute-force activity.
I enabled the rule, mapped it to relevant MITRE ATT&CK framework categories, and configured it to run every four hours
against the last five hours of data. The rule was set to automatically create an incident upon triggering, with entity
mappings defined for Remote IP and DeviceName, and to group all alerts into a single incident per 24-hour period. Once
configured, the rule successfully triggered my first alert and automatically created an incident.

Following the NIST 800-61 Incident Response Lifecycle, I worked the incident to completion. During the Preparation phase,
I ensured roles, procedures, and tools were documented and in place. In the Detection and Analysis phase, I identified and
validated the brute-force attempt, observing that six different IPs targeted two hosts. I assigned the incident to myself in
Sentinel, set the status to Active, and used the "Investigate" feature to explore related entities and gather evidence. I
confirmed that none of the suspicious IPs had successfully logged in by running a custom KQL query.

In the Containment, Eradication, and Recovery phase, I locked down the Network Security Group (NSG) for the target VM to
only allow traffic from my local machine, preventing further RDP attempts from the public internet. I proposed implementing
a corporate policy requiring this for all VMs. Since no successful logins were observed, no remediation was needed beyond
tightening access controls.

Finally, in the Post-Incident phase, I documented all findings within the Sentinel incident, acknowledged the need for more
restrictive NSG policies in the future, and marked the case as a “True Positive.” The incident was reviewed, reported, and
formally closed out.
```

## Creating Alert Rule (Brute Force Attempt)
### KQL Query 
```kql
DeviceLogonEvents
| where TimeGenerated > ago(5h)
| where ActionType == "LogonFailed"
| summarize EventCount = count() by RemoteIP, ActionType, DeviceName
| where EventCount >= 50
| order by EventCount desc
```
![image](https://github.com/user-attachments/assets/1e3bdf4e-81e0-4094-8ad5-044d5f2ba1e6)



## Alert Triggered to Create Incident
![image](https://github.com/user-attachments/assets/9729947b-03f9-4509-a6dc-a2b613440083)


## Work Incident
### Preparation
- Documented roles, responsibilities, and procedures.
- Ensured tools, systems, and training were in place.

### Detection and Analysis
- Identified and validated the incident.
  - Observed the incident and assigned it to myself, and set the status to Active.
  - Investigated the Incident by Actions → Investigate.
- Gathered relevant evidence and assessed impact.
  - 10 different virtual machines were potentially impacted by multiple public IP addresses.
  - Confirmed that none of the public IP addresses that attempted to bruteforce successfully logged in to the virtual machines. 

### KQL Query
```kql
DeviceLogonEvents
| where RemoteIP in ("218.92.0.187", "5.178.87.180", "1.194.210.131", "185.7.214.81", "185.137.233.87", "194.180.48.85", "193.37.69.105", "194.180.49.231")
| where ActionType != "LogonFailed"
| project RemoteIP, ActionType, DeviceName
```
![image](https://github.com/user-attachments/assets/a6f407b7-7ecb-4c09-9a9c-5403c4e8da5c)
![image](https://github.com/user-attachments/assets/c88500a8-9cca-43ea-b861-6cd702c1e03c)
![image](https://github.com/user-attachments/assets/601c1114-78ad-466e-8a20-36b7eddd66c1)

### Containment, Eradication, and Recovery
- Isolated 10 affected virtual machines on Microsoft Defender for Endpoint.
- Conducted antivirus scans for all 10 virtual machines.

![image](https://github.com/user-attachments/assets/ac80bf16-5690-42ee-9cf1-3cbf4a83af22)

- Updated the Network Security Group (NSG) to prevent any traffic except my local PC from reaching the VMs.
- NSG was locked down to prevent RDP attempts from the public internet.
- Corporate policy was proposed to require this for all VMs going forward.
- Would have removed the threat and restored VMs to normal, however brute force attempts were not successful.

### Post Incident Activities
- Documented findings and lessons learned.
- Recorded notes within the incident.
- Updated policies and tools to prevent recurrence.
- In real world scenarios, I would make it a company policy for hardening the VMs to not allow completely wide open NSGs utilizing Azure Policy.

![image](https://github.com/user-attachments/assets/b71b56aa-323f-485e-8a94-a5f60719f448)


### Closure
- Closed out the incident within Sentinel as a “True Positive”.
- However, the brute force attempt was not successful.

![image](https://github.com/user-attachments/assets/316f3a9d-de9e-451f-a56d-671971e535c0)

