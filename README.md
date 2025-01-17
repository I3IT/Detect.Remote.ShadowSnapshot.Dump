﻿# Detect.Remote.ShadowSnapshot.Dump

This projects detects remote local credentials dumps using the "Shadow Snapshot method". This was implemented in Impacket in the following PR: [[SECRETSDUMP] New Dump Method - Shadow Snapshot Method via WMI](https://github.com/fortra/impacket/pull/1719).

# Important Compilation note

Remember to add tdh.lib as a dependency, as this lib is not included by default.

![Visual Studio Lib Dependency](snapshots%2F2024-12-27%2004_53_16-Detect.Remote.ShadowSnapshot.Dump%20-%20Microsoft%20Visual%20Studio.png)

# Example

![Impacket Secretsdump](snapshots%2F2024-12-27%2013_54_40-kali-linux-2024.4-vmware-amd64%20-%20VMware%20Workstation.png)

![Detection](snapshots%2F2024-12-27%2004_56_28-.png)
