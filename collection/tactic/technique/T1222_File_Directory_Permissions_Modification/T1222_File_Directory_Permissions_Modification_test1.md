<h1> Tactic: Defense Evasion |
Technique: File and Directory Permissions Modification: Windows File and Directory Permissions Modification (T1222.001)  </h1>
<h2> From MITRE ATT&CK </h2>

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls`, `takeown`, and `attrib`, which can grant adversaries higher permissions on specific files and folders.

<h3> Note</h3>

At the time of this commit, MITRE ATT&CK does not include the old `cacls` Windows built-in command.
`Cacls`, which is short for *change access control list*, is the predecessor to `icacls`. However, it is still available on many standard Windows 10 builds. 

