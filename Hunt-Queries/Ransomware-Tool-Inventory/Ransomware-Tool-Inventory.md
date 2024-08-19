# Splunk Query for Ransomware Tool Inventory

## Description

This Splunk query is designed to perform an **inventory analysis** of tools that are known to be used in ransomware operations within an enterprise environment. It searches through all indexed data to identify occurrences of specific tools associated with malicious activities or security vulnerabilities.

## How It Works

1. **Search All Indexes**: The query begins by searching across all indexed data (`index=*`).

2. **Evaluate Tool Presence**: It uses the `eval` command with the `case` function to categorize events based on the presence of tool names in the raw log data (`_raw`). Each tool name is associated with a specific label (e.g., `mimikatz`, `nmap`, `cobalt strike`).

3. **Aggregate and Count**: The `stats` command then aggregates this information by counting occurrences and listing the indexes where these tools were found. It groups results by the tool name (`keyword`) and counts the number of occurrences.

4. **Filter Results**: Finally, the `where` clause filters the results to show only those tools that appear fewer than 100 times across the logs. This helps in identifying tools with potentially lower visibility or less frequent usage in the environment.

## Use Case

This query is particularly useful for an initial enterprise inventory to:

- Identify which known tools related to ransomware operations are present in the environment.
- Assess exposure by determining which of these tools are actively being logged and potentially used.
- Prioritize investigation or remediation efforts based on the visibility and frequency of these tools.

## Inspiration

This query is inspired by and adapted from the excellent project [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) by BushidoUK. This project provides a comprehensive list of tools commonly associated with ransomware operations, which served as the basis for identifying and categorizing these tools in the Splunk query.
