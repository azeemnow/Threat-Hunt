<h1> Tactic: Discovery
Technique: Security Software Discovery (T1063)  </h1>
<h2> From MITRE ATT&CK </h2>

Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

<h2> Test </h2>

Name                      | Description                                                             | Reference
------------------------- | ------------------------------------------------------------------------| ------------
PowerShell WMI Execution  | Simulates adversary leveraging PS WMI Script to list Security Software  | N/A 

<h3> Test Development </h3>

<h4> Create a custom Powershell WMI script that lists names of installed security software on the system </h3>


```
(WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayname /format:csv)
```
<h3> Test Execution </h3>

Execute the above script in Windows PowerShell: 

![PowerShell_WMI; T1063](T1063_images/security-software-discovery-1.png)

The output from above will show list of installed security software in a CSV format.

<h2> Detection </h2>

<h4> 1. Enable WMI Tracing </h3>

```wevtutil sl Microsoft-Windows-WMI-Activity/Trace /e:true```


https://docs.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity
