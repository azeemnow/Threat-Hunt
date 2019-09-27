<h1> Tactic: Defense Evasion, Execution
Technique: Compiled HTML File (T1223)  </h1>
<h2> From MITRE ATT&CK </h2>

Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).

Adversaries may abuse this technology to conceal malicious code. A custom CHM file containing embedded payloads could be delivered to a victim then triggered by User Execution. CHM execution may also bypass application whitelisting on older and/or unpatched systems that do not account for execution of binaries through hh.exe.

<h2> Test </h2>

Name          | Description                                                                  | Reference
------------- | -----------------------------------------------------------------------------| ------------
Network Comm. | Simulates adversary leveraging custom CHM for outbound network communication |  

<h3> Test Development </h3>

<h4> Create Custom CHM File </h3>
