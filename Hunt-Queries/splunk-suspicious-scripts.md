### Splunk Search for Script Execution

### Description
This Splunk search is designed to identify and analyze various script files executed on your system. It searches for specific file extensions associated with scripts and programs, and then aggregates and displays the results by the parent process that created them.

### Value
Script Identification: Helps in identifying the execution of various types of scripts (e.g., PowerShell, JavaScript, Python) and their command-line arguments.
Execution Timeline: Displays when these scripts were executed by grouping results by month and year, which is useful for tracking and analyzing script activity over time.
Parent Process Analysis: Groups results by the process responsible for executing the scripts, allowing you to understand which applications or services are running these scripts.


### Extension Types Explained

- **`*.ps1`**: PowerShell script files. Used for executing commands or automating tasks within the Windows environment.

- **`*.psm1`**: PowerShell module files. Contain reusable PowerShell code that can be imported into other scripts or sessions.

- **`*.psd1`**: PowerShell data files. Used for defining data and configuration settings that can be imported into PowerShell scripts.

- **`*.bat`**: Batch script files. Executed by the Windows Command Processor to run a series of commands automatically.

- **`*.cmd`**: Command script files. Similar to `.bat` files but with some additional features and syntax support.

- **`*.vbs`**: VBScript files. Used for scripting tasks within Windows and Internet Explorer.

- **`*.js`**: JavaScript files. Commonly used for scripting web pages, but can also be run on the Windows OS.

- **`*.wsf`**: Windows Script Files. Used for running multiple scripts in a single file, supporting VBScript, JScript, and other scripting languages.

- **`*.sh`**: Shell script files. Typically used in Unix/Linux environments for executing commands and automating tasks.

- **`*.hta`**: HTML Application files. Can execute scripts and run HTML applications with embedded scripts.

- **`*.pl`**: Perl script files. Used for a variety of tasks, including web development and system administration.

- **`*.py`**: Python script files. Used for a wide range of programming tasks and automation.

- **`*.ps1xml`**: PowerShell XML files. Used for defining PowerShell objects and their formatting.


#### Search Query
```spl (@azeemnow)

index=windows
("*ps1*" OR "*psm1*" OR "*.psd1*" OR "*.bat*" OR "*.cmd*" OR "*.vbs*" OR "*.js*" OR "*.wsf*" OR "*.sh*" OR "*.hta*" OR "*.pl*" OR "*.py*" OR "*.ps1xml*")
| eval dtime=strftime(_time, "%Y%m")
| stats count values(Process_Command_Line) values(dtime) by Creator_Process_Name
