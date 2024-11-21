# Splunk Keyword Grouping Search for Threat Hunting

## Overview

This Splunk search provides a powerful method for identifying and categorizing security-related events by grouping them into meaningful categories, such as "General Errors," "Linux Errors," "Windows Errors," "Network Issues," and "Privilege Escalation." It captures a wide range of critical keywords from logs, helping security teams perform more efficient threat hunting by providing detailed insights into event types and trends.

## Benefits of the Search from a Threat Hunting Perspective

Threat hunting involves proactively searching for signs of malicious activity and potential vulnerabilities within an organization’s network or system logs. This search offers several key benefits for threat hunting:

### 1. **Improved Detection of Malicious Activity**
By categorizing log events into specific groups based on keywords, you can more easily detect suspicious activities. For example:
   - **Privilege Escalation** events like the use of tools (`sudo`, `nc`, `curl`) are immediately flagged, helping you spot potential attackers attempting to gain unauthorized access.
   - **Network Issues** such as `port scans` and `SSL/TLS handshake failures` are indicative of possible reconnaissance or exploit attempts.

### 2. **Granular and Actionable Insights**
This search doesn’t just flag an event group but also provides the exact **keyword** that matched, giving you more context on the nature of the issue. This granular data helps you prioritize incidents and reduce false positives, improving response times.

### 3. **Faster Incident Response**
By organizing log data into easily digestible groups like "General Errors" or "Windows Errors," this search allows your security team to quickly identify the root cause of issues. Whether it's a `segfault` on a Linux server or an `EventCode=4625` on a Windows machine, you get actionable information to respond faster.

### 4. **Comprehensive Coverage**
The expanded keyword list ensures that a wider range of log events are captured. This search doesn't only cover common errors but also includes specialized keywords like `kernel panic`, `nmap`, and `EventCode=5156`, increasing its ability to spot security events across multiple platforms.

### 5. **Optimized for Cross-Platform Detection**
By including both **Linux** and **Windows-specific keywords**, this search is effective in mixed-environment networks, where both operating systems are in use. It can identify issues specific to each environment, enabling you to detect platform-specific vulnerabilities.

## Explanation of the Search

This search queries two key indexes: `windows` and `linux`, pulling events from the past 7 days. It utilizes a `case` statement to categorize events based on the presence of specific keywords, giving each event a **keyword group** and a **matched keyword**. 

Here’s the breakdown of how the search works:

1. **Search Scope**:
   The search looks for logs from two indexes: 
   - `windows`: Contains Windows-specific logs (such as security events and system errors).
   - `linux`: Contains Linux-specific logs (such as system logs and authentication attempts).
   
   The query is scoped to events that occurred in the past 7 days (`earliest=-7d latest=now`).

2. **Keyword Grouping**:
   The `eval` function is used to group events into categories based on specific keywords found in the raw log data. These categories are defined as:
   - **General Errors**: A broad set of keywords representing errors, failures, and critical issues like `error`, `failure`, `critical`, `timeout`, and more.
   - **Linux Errors**: Linux-specific errors such as `segfault`, `kernel panic`, and `permission denied`.
   - **Windows Errors**: Specific EventCodes (`EventCode=4625`, `EventCode=4719`) that indicate login failures, security issues, or configuration errors.
   - **Network Issues**: Keywords related to network security, such as `port scan`, `SSL/TLS handshake failure`, and `unauthorized access`.
   - **Privilege Escalation**: Keywords associated with privilege escalation attempts, such as `nmap`, `sudo`, and `root`.

3. **Matched Keywords**:
   The `eval` function also extracts the specific keyword that caused the match and stores it in a new field, `matched_keyword`. This helps identify the exact trigger for each event.

4. **Aggregation**:
   The `stats` command groups the results by the `index`, `keyword_group`, and `matched_keyword`, providing counts of how many times each specific keyword was found in the logs. The results are sorted in descending order by count to highlight the most frequent events.

### Splunk Query

```spl
(index="windows" OR index="linux") earliest=-7d latest=now
| eval keyword_group = case(
    lower(_raw) IN ("error", "failure", "critical", "timeout", "unable", "exception", "denied", "rejected", "not found", "could not", "unauthorized", "invalid", "warning", "fatal", "invalid argument", "error code", "bad request"), "General Error",
    lower(_raw) IN ("segfault", "kernel panic", "OOM", "permission denied", "connection refused", "authentication failure", "sudo:", "SSH:", "service not found", "unknown user", "user not found", "segmentation fault", "authentication error", "invalid command", "command not found", "no such file or directory"), "Linux Error",
    lower(_raw) IN ("EventCode=4625", "EventCode=4624", "EventCode=4719", "EventCode=4771", "EventCode=1102", "EventCode=4728", "EventCode=4740", "EventCode=4688", "EventCode=4697", "EventCode=5156", "EventCode=5158"), "Windows Error",
    lower(_raw) IN ("port scan", "unauthorized access", "SSL/TLS handshake failure", "certificate expired", "open port", "retransmission", "icmp unreachable", "TCP connection reset", "unresponsive service", "connection timed out", "SSL error", "certificate warning", "insecure connection"), "Network Issues",
    lower(_raw) IN ("nc", "curl", "wget", "ftp", "telnet", "sudo", "su", "root", "nmap", "netcat", "dig", "ssh", "rsync", "scp", "wget", "bash", "bash shell", "privilege escalation", "escalate privileges", "attack vector"), "Privilege Escalation"
)
| eval matched_keyword = case(
    lower(_raw) IN ("error", "failure", "critical", "timeout", "unable", "exception", "denied", "rejected", "not found", "could not", "unauthorized", "invalid", "warning", "fatal", "invalid argument", "error code", "bad request"), "General Error",
    lower(_raw) IN ("segfault", "kernel panic", "OOM", "permission denied", "connection refused", "authentication failure", "sudo:", "SSH:", "service not found", "unknown user", "user not found", "segmentation fault", "authentication error", "invalid command", "command not found", "no such file or directory"), "Linux Error",
    lower(_raw) IN ("EventCode=4625", "EventCode=4624", "EventCode=4719", "EventCode=4771", "EventCode=1102", "EventCode=4728", "EventCode=4740", "EventCode=4688", "EventCode=4697", "EventCode=5156", "EventCode=5158"), "Windows Error",
    lower(_raw) IN ("port scan", "unauthorized access", "SSL/TLS handshake failure", "certificate expired", "open port", "retransmission", "icmp unreachable", "TCP connection reset", "unresponsive service", "connection timed out", "SSL error", "certificate warning", "insecure connection"), "Network Issues",
    lower(_raw) IN ("nc", "curl", "wget", "ftp", "telnet", "sudo", "su", "root", "nmap", "netcat", "dig", "ssh", "rsync", "scp", "wget", "bash", "bash shell", "privilege escalation", "escalate privileges", "attack vector"), "Privilege Escalation"
)
| stats count by index, keyword_group, matched_keyword
| sort - count
