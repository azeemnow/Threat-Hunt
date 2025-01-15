# Detect Suspicious Executable and DLL Files in Temporary Directories on Windows Systems
## Purpose
This Windows Defender KQL (Kusto Query Language) query helps identify potentially malicious executable and DLL files in temporary directories on Windows systems. It analyzes execution patterns, frequency, and context over a 30-day period, enabling enhanced security monitoring and threat detection. By targeting unusual file behavior, this query aids in uncovering hidden threats and protecting against malware.
## Query
```kusto
    DeviceImageLoadEvents 
    | where Timestamp > ago(720h)
    | where FolderPath has_any("C:\\Windows\\Temp", "AppData") 
    | summarize 
        Count = count(),
        LastSeen = max(Timestamp),
        FirstSeen = min(Timestamp),
        UniqueInitiatingProcesses = dcount(InitiatingProcessFileName),
        InitiatingProcesses = make_set(InitiatingProcessFileName, 5),
        UniqueDevices = dcount(DeviceName)
        by FolderPath, FileName
    | where 
        not(FolderPath contains "MSI") and
        not(InitiatingProcesses has "msiexec.exe") and
        (FolderPath contains "\\Temp\\" and (FileName endswith ".exe" or FileName endswith ".dll"))
    | extend RiskIndicators = case(
            Count > 500 and UniqueInitiatingProcesses <= 2, "Critical: High Frequency Execution",
            Count > 300 and UniqueInitiatingProcesses == 1 and UniqueDevices == 1, "Warning: Single Process High Count",
            FolderPath matches regex @".*\\Temp\\~[a-zA-Z0-9]+\\.*\.exe", "Suspicious: Temp Pattern",
            "Low"
        )
    | where RiskIndicators != "Low"
    | project 
        FileName,
        FolderPath,
        Count,
        UniqueInitiatingProcesses,
        InitiatingProcesses,
        UniqueDevices,
        FirstSeen,
        LastSeen,
        RiskIndicators
    | order by 
        case(
            RiskIndicators startswith "Critical", 1,
            RiskIndicators startswith "Warning", 2,
            RiskIndicators startswith "Suspicious", 3,
            4
        ),
        Count desc
    | take 15
```
## Features

 -  Focuses on temp directories where malware often operates
-   Tracks execution frequency and patterns
-   Identifies files with suspicious behavior patterns
-   Excludes common legitimate installer activity
-   Provides context for investigation
## Risk Categories

- Critical: High frequency executions (>500) with limited process variety
- Warning: High count (>300) single-process executions on single devices
- Suspicious: Executables in randomly named temp folders
## Investigation Guidelines
For each flagged item:

 - [ ] Check InitiatingProcesses to understand what launched the file
 - [ ] Compare FirstSeen and LastSeen timestamps for execution patterns
 - [ ] Investigate high-count executions from limited processes
 - [ ] Review files in randomly named temp directories
 - [ ] Cross-reference UniqueDevices count with expected behavior

For a more detailed investigation, check out my triage KQL: (https://github.com/azeemnow/Threat-Hunt/blob/master/Hunt-Queries/Defender_KQL/suspicious-file-activity-triage-kql.md) 

## Limitations

- Limited to 15 results for focused analysis
- 30-day lookback period
- May need threshold adjustments based on environment
- Excludes MSI installer activity which could miss some threats

## Usage
- Run query in Windows Defender Advanced Hunting
- Focus on items marked "Critical" first
- Investigate "Warning" items on single devices
- Review "Suspicious" patterns in temp directories
## False Positive Reduction
- Excludes known MSI installer processes
- Filters out common installation paths
- Considers device spread in risk scoring
- Focuses on sustained suspicious patterns
## Performance Considerations
- Query optimized for large environments
- Uses efficient summarize operations
## Customization
Adjust thresholds based on your environment:
-   Modify Count thresholds (currently 500/300)
-   Adjust time window (currently 720h/30d)
-   Update regex patterns for temp folders
-   Modify exclusion filters for legitimate software
### Disclosure
This project includes contributions from AI (e.g., ChatGPT, Claude, etc.)
