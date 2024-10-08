# Common Remote Access Tools Hunt

This KQL query filters events from the `DeviceProcessEvents` table to identify the usage of commonly used remote access tools. It retrieves relevant details about each event, including timestamps, device names, and command line usage.

# Threat Hunt Benefits

- **Monitoring Remote Access**: Helps security teams monitor and track the usage of remote access applications, which can be exploited by attackers for unauthorized access.
- **Identifying Anomalies**: Facilitates the detection of unusual or unauthorized use of remote access tools, aiding in the identification of potential security incidents.
- **Accountability**: Provides information about which accounts are initiating remote access processes, supporting accountability and investigation efforts.
- **Proactive Defense**: Enables proactive security measures by identifying trends in remote access usage that may indicate malicious activity.

# KQL

```kql
DeviceProcessEvents
| where FileName in~ ("anydesk.exe",    // AnyDesk
                      "AteraAgent.exe", // Atera
                      "teamviewer.exe", "TeamViewer_Setup.exe", // TeamViewer
                      "remote_assistance_host.exe", "remoting_desktop.exe", "remoting_host.exe", // Chrome Remote Desktop
                      "SRService.exe", "SRManager.exe", "SRServer.exe", "SRAgent.exe", "ClientService.exe", // Splashtop
                      "ScreenConnect.WindowsClient.exe", "ScreenConnect.WindowsBackstageShell.exe", "ScreenConnect.ClientService.exe", "ScreenConnect.Service.exe", // ScreenConnect
                      "ngrok.exe",    // NGrok
                      "fleetdeck-agent.exe", "fleetdeck.exe", // Fleetdeck
                      "level.exe",    // Level IO
                      "TakeControlTechConsole-Stable.exe", // N-Able
                      "remcmdstub.exe",    // NetSupport
                      "NinjaRMMAgentPatcher.exe", "ninjarmm-cli.exe", "NinjaRMMAgent.exe", // NinjaRMM
                      "nxexec.exe", "nxplayer.exe", "nxservice.exe", "nxservice64.exe", // NoMachine
                      "PCMonitorSrv.exe", "PCMonitorManager.exe", // Pulseway
                      "rustdesk.exe",    // RustDesk
                      "meshagent.exe", "tacticalrmm.exe", // TacticalRMM
                      "tailscale.exe", "tailscaled.exe", // Tailscale
                      "ZA_Connect.exe", "ZMAgent.exe", "ZohoTray.exe"    // Zoho
                     )
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
