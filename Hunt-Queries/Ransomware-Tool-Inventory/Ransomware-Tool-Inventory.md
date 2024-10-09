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

## Hunting Next Steps

After running this query and identifying the tools in use, follow these next steps to enhance your security posture:

1. **Triaging Low-Hanging Fruits**: Focus first on tools that appear infrequently. Investigate why these tools are present, their use cases, and if they pose any risk.

2. **Perform Least Frequency Analysis**: Analyze tools with the lowest frequency of appearance. These may indicate less common or less well-known tools that could be exploited by attackers. Determine their role and necessity.

3. **Assess Authorization and Risk**: For each tool identified, verify if it is authorized and intended for use within the organization. If a tool is found to be unauthorized or poses a security risk, consider alternative, less risky options that could fulfill the same function.

4. **Tool Discovery and Update**: Continuously update the list of tools in the query as new tools are discovered and become relevant. Regularly review and refine the query to include emerging tools used by ransomware groups.

5. **Schedule Regular Searches**: Schedule this search to run on a weekly basis. Regular monitoring will help in discovering new tools and ensuring ongoing awareness of their presence and usage.

## Inspiration

This query is inspired by and adapted from the excellent project [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) by BushidoUK. This project provides a comprehensive list of tools commonly associated with ransomware operations, which served as the basis for identifying and categorizing these tools in the Splunk query.

## Splunk Query

```spl

index=*
| eval keyword=case(
    match(_raw, "gitguardian"), "gitguardian",
    match(_raw, "jecretz"), "jecretz",
    match(_raw, "keethief"), "keethief",
    match(_raw, "lazagne"), "lazagne",
    match(_raw, "lostmypassword"), "lostmypassword",
    match(_raw, "mimikatz"), "mimikatz",
    match(_raw, "nirsoft bulletspassview"), "nirsoft bulletspassview",
    match(_raw, "bulletspassview"), "bulletspassview",
    match(_raw, "chromepass"), "chromepass",
    match(_raw, "dialupass"), "dialupass",
    match(_raw, "extpassword"), "extpassword",
    match(_raw, "iepassview"), "iepassview",
    match(_raw, "iepv"), "iepv",
    match(_raw, "mailpassview"), "mailpassview",
    match(_raw, "netpass"), "netpass",
    match(_raw, "operapassview"), "operapassview",
    match(_raw, "routerpassview"), "routerpassview",
    match(_raw, "remotedesktoppassview"), "remotedesktoppassview",
    match(_raw, "rdpv"), "rdpv",
    match(_raw, "sniffpass"), "sniffpass",
    match(_raw, "vncpassview"), "vncpassview",
    match(_raw, "webbrowserpassview"), "webbrowserpassview",
    match(_raw, "wirelesskeyview"), "wirelesskeyview",
    match(_raw, "passwordfox"), "passwordfox",
    match(_raw, "procdump"), "procdump",
    match(_raw, "rdp recognizer"), "rdp recognizer",
    match(_raw, "router scan"), "router scan",
    match(_raw, "secretserversecretstealer"), "secretserversecretstealer",
    match(_raw, "sharpchrome"), "sharpchrome",
    match(_raw, "sharpdump"), "sharpdump",
    match(_raw, "trufflehog"), "trufflehog",
    match(_raw, "avast anti-rootkit"), "avast anti-rootkit",
    match(_raw, "backstab"), "backstab",
    match(_raw, "defender control"), "defender control",
    match(_raw, "eraser"), "eraser",
    match(_raw, "gmer"), "gmer",
    match(_raw, "iobit"), "iobit",
    match(_raw, "killav"), "killav",
    match(_raw, "pchunter"), "pchunter",
    match(_raw, "powertool"), "powertool",
    match(_raw, "processhacker"), "processhacker",
    match(_raw, "tdsskiller"), "tdsskiller",
    match(_raw, "universal virus sniffer"), "universal virus sniffer",
    match(_raw, "virtualbox"), "virtualbox",
    match(_raw, "ydark"), "ydark",
    match(_raw, "zemana anti-rootkit"), "zemana anti-rootkit",
    match(_raw, "adexplorer"), "adexplorer",
    match(_raw, "adrecon"), "adrecon",
    match(_raw, "adfind"), "adfind",
    match(_raw, "advanced ip scanner"), "advanced ip scanner",
    match(_raw, "advanced port scanner"), "advanced port scanner",
    match(_raw, "angry ip scanner"), "angry ip scanner",
    match(_raw, "aws systems manager inventory"), "aws systems manager inventory",
    match(_raw, "bloodhound"), "bloodhound",
    match(_raw, "lansweeper"), "lansweeper",
    match(_raw, "nbtscan"), "nbtscan",
    match(_raw, "nmap"), "nmap",
    match(_raw, "nping"), "nping",
    match(_raw, "pingcastle"), "pingcastle",
    match(_raw, "powerview"), "powerview",
    match(_raw, "seatbelt"), "seatbelt",
    match(_raw, "servicecontrol"), "servicecontrol",
    match(_raw, "sc.exe"), "sc.exe",
    match(_raw, "sharpshares"), "sharpshares",
    match(_raw, "sharefinder"), "sharefinder",
    match(_raw, "sharpview"), "sharpview",
    match(_raw, "softperfect netscan"), "softperfect netscan",
    match(_raw, "dropbox"), "dropbox",
    match(_raw, "filezilla"), "filezilla",
    match(_raw, "freefilesync"), "freefilesync",
    match(_raw, "mega"), "mega",
    match(_raw, "privatlab"), "privatlab",
    match(_raw, "protonmail"), "protonmail",
    match(_raw, "restic"), "restic",
    match(_raw, "rclone"), "rclone",
    match(_raw, "sendspace"), "sendspace",
    match(_raw, "ufile"), "ufile",
    match(_raw, "winscp"), "winscp",
    match(_raw, "psexec"), "psexec",
    match(_raw, "bitsadmin"), "bitsadmin",
    match(_raw, "windows event utility"), "windows event utility",
    match(_raw, "ntds utility"), "ntds utility",
    match(_raw, "bcedit"), "bcedit",
    match(_raw, "wmic"), "wmic",
    match(_raw, "softperfect netscan"), "softperfect netscan",
    match(_raw, "adfind"), "adfind",
    match(_raw, "gmer"), "gmer",
    match(_raw, "cobalt strike"), "cobalt strike",
    match(_raw, "mimikatz"), "mimikatz",
    match(_raw, "anydesk"), "anydesk",
    match(_raw, "splashtop"), "splashtop",
    match(_raw, "psexec"), "psexec",
    match(_raw, "rclone"), "rclone",
    match(_raw, "chisel"), "chisel",
    match(_raw, "cloudflared"), "cloudflared",
    match(_raw, "openssh"), "openssh",
    match(_raw, "ligolo"), "ligolo",
    match(_raw, "ngrok"), "ngrok",
    match(_raw, "plink"), "plink",
    match(_raw, "proxifier"), "proxifier",
    match(_raw, "socat"), "socat",
    match(_raw, "sshimpanzee"), "sshimpanzee",
    match(_raw, "tailscale"), "tailscale",
    match(_raw, "termite"), "termite",
    match(_raw, "wstunnel"), "wstunnel",
    match(_raw, "anydesk"), "anydesk",
    match(_raw, "atera"), "atera",
    match(_raw, "chrome remote desktop"), "chrome remote desktop",
    match(_raw, "dwagents"), "dwagents",
    match(_raw, "fixmeit"), "fixmeit",
    match(_raw, "fleetdeck"), "fleetdeck",
    match(_raw, "level.io"), "level.io",
    match(_raw, "logmein"), "logmein",
    match(_raw, "mobaxterm"), "mobaxterm",
    match(_raw, "n-able"), "n-able",
    match(_raw, "netsupport"), "netsupport",
    match(_raw, "parsec"), "parsec",
    match(_raw, "pulseway"), "pulseway",
    match(_raw, "remotepc"), "remotepc",
    match(_raw, "remoteutilities"), "remoteutilities",
    match(_raw, "rsat"), "rsat",
    match(_raw, "rustdesk"), "rustdesk",
    match(_raw, "screenconnect"), "screenconnect",
    match(_raw, "simplehelp"), "simplehelp",
    match(_raw, "splashtop"), "splashtop",
    match(_raw, "superops"), "superops",
    match(_raw, "tacticalrmm"), "tacticalrmm",
    match(_raw, "teamviewer"), "teamviewer",
    match(_raw, "tightvnc"), "tightvnc",
    match(_raw, "twingate"), "twingate",
    match(_raw, "zohoassist"), "zohoassist"
)
| stats count values(index) by keyword
| where count < 100
