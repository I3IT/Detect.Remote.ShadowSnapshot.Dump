# Detect.Remote.ShadowSnapshot.Dump

This project detects remote local credentials dumps using the "Shadow Snapshot method". This was implemented in Impacket in the following PR: [[SECRETSDUMP] New Dump Method - Shadow Snapshot Method via WMI](https://github.com/fortra/impacket/pull/1719).

This project leverages Event Tracing for Windows (ETW) to monitor this behaviour.

Shadow Copy Creation and Removal Detection:

This PoC uses the Microsoft-Windows-WMI-Activity ETW provider to trace WMI method invocations. It specifically monitors:
1. Shadow Copy creation via the Win32_ShadowCopy::Create method.
2. Shadow Copy removal.

And this PoC monitor the Microsoft-Windows-SMBClient ETW provider for events indicating file reads over the SMB protocol.
1. Detect reads to _SYSTEM32\CONFIG\SAM_,  _SYSTEM32\CONFIG\SECURITY_ and/or  _SYSTEM32\CONFIG\SYSTEM_.

If this behaviour is detected, i.e, a Shadow Snapshot is created, then SAM, SYSTEM and/or SECURITY accessed via SMB and then the SS removed these are indicators about the use of that technique.

This project relies purely in ETW.

![Sample Exec](snapshots%2F2025-01-17%2014-24-08.gif)

# Example

![Impacket Secretsdump](snapshots%2F2024-12-27%2013_54_40-kali-linux-2024.4-vmware-amd64%20-%20VMware%20Workstation.png)

![Detection](snapshots%2F2024-12-27%2004_56_28-.png)

# Important Compilation note

Remember to add tdh.lib as a dependency, as this lib is not included by default.

![Visual Studio Lib Dependency](snapshots%2F2024-12-27%2004_53_16-Detect.Remote.ShadowSnapshot.Dump%20-%20Microsoft%20Visual%20Studio.png)
