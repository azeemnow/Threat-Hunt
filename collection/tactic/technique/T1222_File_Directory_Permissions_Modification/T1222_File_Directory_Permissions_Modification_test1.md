<h1> Tactic: Defense Evasion |
Technique: File and Directory Permissions Modification: Windows File and Directory Permissions Modification (T1222.001)  </h1>
<h2> From MITRE ATT&CK </h2>

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls`, `takeown`, and `attrib`, which can grant adversaries higher permissions on specific files and folders.

<h3> Note</h3>

At the time of this commit, MITRE ATT&CK does not include the old `cacls` Windows built-in command.
`Cacls`, which is short for *change access control list*, is the predecessor to `icacls`. However, it is still available on many standard Windows 10 builds. 

<h2> Test </h2>

Name                      | Description                                                     | Reference
------------------------- | ----------------------------------------------------------------| ------------
File Perm. Modification   | Simulates adversary leveraging Cacls to modify file permission  | [SANS ISC](https://isc.sans.edu/diary/Malicious+Script+Leaking+Data+via+FTP/24484), [VT](https://www.virustotal.com/gui/file/1dcd1c508f00c124026052a66cfa1f215d0d06844c3d10977e607da23ee4618b/behavior/VirusTotal%20Cuckoofork) 

<h3> Test Development </h3>

<h4> Use Cacls to modify a newly created empty .text file's permission to "everyone" </h4>

 1. Create a black text file and give it:
```
  C:\Users\hello\Desktop\T1222>echo.>T1222_Test.txt
```
 2. Check the current permissions of the above created file:
```
  C:\Users\hello\Desktop\T1222>cacls T1222_Test.txt
```
The output from above will show file's permissions for the `SYSTEM` , `Administrators` and `User` account as **`F`** - (Full Permissions).
![File Permissions](https://github.com/azeemnow/Threat-Hunt/blob/master/collection/tactic/technique/T1222_File_Directory_Permissions_Modification/T1222_image/T1222_File_Directory_Permissions_Modification-2.png)

<h3> Test Execution </h3>

Modify `Administrators` permission's from **`F`** (full Permissions) to  **`N`** (none)
```
C:\Users\hello\Desktop\T1222>cacls T1222_Test.txt /e /p Administrators:N

```

