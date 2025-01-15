# Suspicious File Activity Triage Query KQL

## Purpose
When you encounter a suspicious file in MS Windows Defender during threat hunting, transitioning to a deeper investigation is crucial. The following Windows Defender Advanced Hunting query is my go-to tool for quickly obtaining a detailed analysis of a given file, helping you determine its legitimacy and potential risk.

## Query
```kusto
DeviceProcessEvents
| where Timestamp > ago(720h) //30days
| where 
    FileName =~ "CHANGE-ME.EXE" and  // Replace with your suspicious filename
    FolderPath contains "C:\\Windows\\Temp\\"  // Replace with suspicious path
| project
    ProcessTime = Timestamp,
    DeviceName,
    ProcessId,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(720h)
    | where InitiatingProcessFileName =~ "CHANGE-ME.EXE"  // Replace with your suspicious filename
    | project 
        NetworkTime = Timestamp,
        DeviceName,
        RemoteIP,
        RemotePort,
        RemoteUrl,
        Protocol,
        LocalIP,
        InitiatingProcessFileName
) on DeviceName
| project
    TimeStamp = coalesce(NetworkTime, ProcessTime),
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    Protocol,
    LocalIP
| sort by TimeStamp asc
```
## Usage

1.  Replace `"CHANGE-ME.EXE"` with your suspicious file name
2.  Replace the `FolderPath` with your suspicious path
3.  Run query and analyze results chronologically
4.  Focus on unexpected network connections
5.  Document findings for incident response
## Features

-   Correlates process execution with network connections
-   30-day lookback period
-   Maintains chronological order of events
-   Shows execution context (initiating process, command lines)
-   Reveals network indicators (IPs, URLs, ports)


## Investigation Guidelines
**Process Analysis**

 - [ ] Review `InitiatingProcessFileName` to understand 
 - [ ] How the file was launched
 - [ ] Check `AccountName` for unexpected privileged accounts
 - [ ] Note frequency and timing of executions

**Network Indicators**

 - [ ] Check `RemoteIP` against threat intelligence
 - [ ] Analyze `RemoteUrl` for suspicious domains
 - [ ] Review `RemotePort` for unusual services
 - [ ] Examine `Protocol` for unexpected network behavior

**Execution Context**

 - [ ] Validate `FolderPath` matches expected location 
 - [ ] Cross-reference `DeviceName` with expected scope 
 - [ ] Check `TimeStamp` patterns for  unusual timing

## Signs of Malicious Activity

-   **Process Indicators**:
    -   Execution from unexpected temporary directories
    -   Unusual initiating processes
    -   Suspicious command line arguments
    -   Execution under unexpected accounts
    -   Multiple executions across devices
-   **Network Indicators**:
    -   Connections to known malicious IPs
    -   Unusual ports or protocols
    -   Suspicious domain names
    -   High volume of connections
    -   Beaconing patterns

## Customization
-   Adjust time range (ago(720h/30d))
-   Modify file name and path filters
-   Add specific network indicators
-   Include additional event types
## False Positive Reduction

-   Validate against known software behavior
-   Check software deployment schedules
-   Verify legitimate network connections
-   Cross-reference with IT operations
## Performance Considerations
-   Query uses lightweight joins
-   Focused on specific file activity
-   Efficient filtering before joins
-   Limited result set
## Customization
Adjust thresholds based on your environment:
-   Modify Count thresholds (currently 500/300)
-   Adjust time window (currently 720h/30d)
-   Update regex patterns for temp folders
-   Modify exclusion filters for legitimate software
### Disclosure
This project includes contributions from AI (e.g., ChatGPT)

