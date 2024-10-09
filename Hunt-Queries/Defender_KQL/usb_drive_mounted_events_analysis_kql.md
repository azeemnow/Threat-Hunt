# USB Drive Mounted Events Analysis 
## Summary of the KQL Query

This query retrieves and analyzes events related to USB drives mounted on devices. It focuses on:

- Filtering for USB drive mount events.
- Extracting relevant information from additional fields, including serial number, product name, and manufacturer.
- Grouping results by manufacturer, product name, and serial number, counting occurrences.
- Filtering to show only combinations mounted fewer than 10 times.
- Ordering the results by count.


## Benefits

The benefit of this query is in Security Operations and Threat Hunting, as it helps identify rogue USB devices that may be connected to the system. By analyzing the frequency of USB device connections and filtering for those with low counts, security teams can pinpoint potentially unauthorized or suspicious devices, aiding in the prevention of data exfiltration and other security incidents.

# KQL

This KQL query analyzes USB drive mounting events on devices monitored by Microsoft Defender.

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
| extend vendor = tostring(Manufacturer)
| extend product = tostring(ProductName) 
| extend serial = tostring(SerialNumber)
| summarize count() by vendor, product, serial
| where count_ < 10 
| order by count_

