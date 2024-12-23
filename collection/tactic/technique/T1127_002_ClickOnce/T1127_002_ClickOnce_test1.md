# Tactic: Execution | Technique: Trusted Developer Utilities Proxy Execution (ClickOnce - T1127.002)

## From MITRE ATT&CK

**Trusted Developer Utilities Proxy Execution** is an abuse of legitimate developer tools to execute arbitrary code. This can involve tools like ClickOnce, which simplifies deployment of applications via URLs. Adversaries can exploit ClickOnce to execute unauthorized applications or files by hosting malicious ClickOnce manifests online. This technique often bypasses security measures by leveraging trusted utilities.

## Test

| Name                                         | Description                                                              | Reference |
|----------------------------------------------|--------------------------------------------------------------------------|-----------|
| ClickOnce File Download via Custom .NET App | Simulates adversaries leveraging a .NET application to proxy file execution using ClickOnce | N/A       |

### Test Development

#### Use ClickOnce to download a file from a specified URL and save it locally

```csharp
using System.Net.Http;
using System.IO;

namespace clickonce4
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            string url = "https://drive.google.com/file/d/1JdZiLXGxISmSIeSG4kBLOfIfLZb5CTuE/view?usp=drive_link";

            // Get the user's home directory path
            string userHomePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            // Define a generic filename with timestamp
            string fileName = $"downloaded_file_{DateTime.Now:yyyyMMddHHmm}.zip";  // Includes date and time

            string destinationFile = Path.Combine(userHomePath, fileName);

            using (HttpClient client = new HttpClient())
            {
                using (HttpResponseMessage response = await client.GetAsync(url))
                {
                    response.EnsureSuccessStatusCode();
                    using (Stream stream = await response.Content.ReadAsStreamAsync())
                    {
                        using (FileStream fileStream = File.Create(destinationFile))
                        {
                            await stream.CopyToAsync(fileStream);
                        }
                    }
                }
            }

            MessageBox.Show("File downloaded successfully!");
        }
    }
}
```

### Test Execution

1. Save the above C# code to a file (e.g., `ClickOnceApp.cs`).
2. Compile the code using Visual Studio or the `csc` command-line compiler to produce an executable (e.g., `ClickOnceApp.exe`).
3. Execute the application.
4. Check the user's home directory for a file named `downloaded_file_<timestamp>.zip`.

### Detection

#### Monitor for unusual ClickOnce activity
Monitor for processes like `rundll32.exe` using `dfshim.dll` or for network connections to unusual URLs that host ClickOnce manifests. Pay special attention to downloads resulting in executable files, particularly if they are being saved in suspicious locations.

#### Example PowerShell Command
Log processes leveraging `rundll32.exe` and `dfshim.dll`:

```powershell
Get-WinEvent -LogName Security | Where-Object { $_.Message -match "rundll32.exe dfshim.dll" }


```
### Input Arguments

- **`file_download_url`**: URL to the file to be downloaded by the ClickOnce application.
  - Example: `https://drive.google.com/file/d/1JdZiLXGxISmSIeSG4kBLOfIfLZb5CTuE/view?usp=drive_link`
  
- **`file_name_pattern`**: Pattern for the saved file name (timestamped).
  - Example: `downloaded_file_<yyyyMMddHHmm>.zip`

### Executor

#### Manual Execution Steps:
1. Save the C# code to a file (e.g., `ClickOnceApp.cs`).
2. Compile the code using Visual Studio or `csc` (command-line compiler).
3. Run the compiled executable (`ClickOnceApp.exe`).
4. Check for the downloaded file in the user's home directory.

### Dependencies

- **.NET Runtime**: Ensure that the .NET runtime is available on the target system to run the application.
- **Network Connectivity**: Ensure that the system can access the specified URL for downloading the file.

### Cleanup Command

To clean up after the test, delete the downloaded file from the user's home directory:

```powershell
Remove-Item -Path "$HOME\downloaded_file_*.zip" -Force
