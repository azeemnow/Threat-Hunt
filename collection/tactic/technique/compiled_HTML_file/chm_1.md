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

<h4> Create a custom CHM File </h3>

* Install HelpNDoc (https://www.helpndoc.com/)
* Create a new project
* Choose one of the empty files from the table of contents on the left
* Select Insert from the top Ribbon and choose Insert > Insert another HTML code
* Insert the following code
```
<html>
    <head>
    <script type="text/javascript">
    function load()
    {
    window.location.href = "http://www.[enter domain]";

    }
    </script>
    </head>

    <body onload="load()">
    <h1>Hello World!</h1>
    </body>
    </html>
    ```
