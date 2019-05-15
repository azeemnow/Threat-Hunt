<h1> MITRE ATT&CK </h1>
<h2>Tactic: Defense Evasion, Execution
Technique: Mshta (T1170) </h2>

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension .hta. HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser.                   Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code.

<h2> Test </h2>

Name  | Description                                       | Reference
----- | --------------------------------------------------| ------------
Koadic| Koadic can use MSHTA to serve additional payloads | [Link to Koadic](https://github.com/zerosum0x0/koadic) 

