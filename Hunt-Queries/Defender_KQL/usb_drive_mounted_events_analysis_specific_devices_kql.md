
# USB Drive Mounted Events Analysis Specific Devices
## Summary of the KQL Query

This query retrieves and analyzes events related to USB drives mounted on devices, specifically focusing on USB devices from certain manufacturers or with specific serial numbers. It includes the following steps:

- Filtering for USB drive mount events.
- Extracting relevant information from additional fields, including serial number, product name, and manufacturer.
- Filtering the results to include only devices from manufacturers that contain "pikvm," "kvm," or "tinypilot," or where the serial number contains "CAFEBABE."
- Ordering the results by the timestamp of the mount event in descending order.


### Detection Use Case

This query serves as a detection use case by specifically targeting USB devices that are known to be associated with security concerns. By focusing on particular manufacturers and serial numbers, security teams can proactively monitor for unauthorized or potentially malicious USB devices. This capability is crucial for detecting and mitigating risks related to data exfiltration or other security incidents involving USB drives.

## Benefits

The benefit of this query lies in Security Operations and Threat Hunting. By targeting specific manufacturers and serial numbers associated with potential rogue devices, security teams can focus their investigations on USB drives that may pose a risk. This targeted approach aids in the detection of unauthorized devices that could lead to data breaches or other security incidents.


## Reference

For more information on specific USB devices and their implications, check out the blog post [Hold Me Closer, Tinypilot](https://blog.grumpygoose.io/hold-me-closer-tinypilot-62360203290f).


## KQL Query

```kql
DeviceEvents
| where ActionType=="UsbDriveMounted"
| extend ParsedFields=parse_json(AdditionalFields)
| project
    MountTime=Timestamp, 
    DeviceName,
    SerialNumber=ParsedFields.SerialNumber, 
    InitiatingProcessAccountName, 
    LoggedOnUsers=ParsedFields.LoggedOnUsers,
    DriveLetter=ParsedFields.DriveLetter, 
    ProductName=ParsedFields.ProductName, 
    Manufacturer=ParsedFields.Manufacturer,
    Volume=ParsedFields.Volume, 
    ReportId,
    AdditionalFields
| where
    (
        Manufacturer contains "pikvm"
        or Manufacturer contains "kvm"
        or Manufacturer contains "tinypilot"
        or SerialNumber contains "CAFEBABE"
    )
| order by MountTime desc
