Title: EsafeNet ProcessCtr.sys arbitrary process termination

Vendor: EsafeNet
Product: ProcessCtrl
Component: ProcessCtr.sys
SHA-256: d64eeb940daffdc8327fb18b160c20e539088cf8407813655f59efa9fdf0022e
MD5: 5ee52684ee22f3ad730b6af7e327d82b
SHA-1: 72ffc3e2afc384657bc1559eb69b4651e24d57d6
Size: 44440 bytes
PE timestamp: 2024-09-05 13:48:53 UTC
FileVersion: 1.0.1.2
ProductVersion: 1.0.1.2
OriginalFilename: ProcessCtrl
Version-resource product name: ProcessCtrl
Version-resource company name: EsafeNet
Signer: CN=北京亿赛通科技发展有限责任公司, O=北京亿赛通科技发展有限责任公司, STREET=海淀区西二旗大街39号4层401, L=北京, S=北京, C=CN, OID.1.3.6.1.4.1.311.60.2.1.2=Beijing, OID.1.3.6.1.4.1.311.60.2.1.3=CN, SERIALNUMBER=91110108746729965F, OID.2.5.4.15=Private Organization
Certificate thumbprint: 8B3761DA3D20565E4DA4CF181181CB382213F79E
Certificate not before: 2024-04-30 03:37:38 UTC
Certificate not after: 2027-05-01 03:37:38 UTC
Authenticode status: Valid
Device: \\.\ProcessCtr
PDB: D:\client_code\Driver\强制注入\Process\bin\ProcessCtrl64.pdb

CVE:

Description:
ProcessCtr.sys in EsafeNet ProcessCtrl FileVersion 1.0.1.2 (SHA-256 d64eeb940daffdc8327fb18b160c20e539088cf8407813655f59efa9fdf0022e) passes a caller-supplied process ID to ZwOpenProcess with PROCESS_TERMINATE and then to ZwTerminateProcess on IOCTL 0x89DB202C (METHOD_BUFFERED), does not check that the caller may terminate that process, and still completes the request with success when that open fails, which allows a local user to terminate a process the caller cannot open for termination via \\.\ProcessCtr. The Authenticode status is Valid, signed by CN=北京亿赛通科技发展有限责任公司, O=北京亿赛通科技发展有限责任公司, STREET=海淀区西二旗大街39号4层401, L=北京, S=北京, C=CN. The version-resource CompanyName is EsafeNet and the ProductName is ProcessCtrl. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator created one process, PID 5680, whose security descriptor granted access only to SYSTEM and Administrators, and did not send the IOCTL. Local account aida-low, a member of Users and not a member of Administrators, could not open that process for termination. That account opened \\.\ProcessCtr, sent IOCTL 0x89DB202C with that process ID, and the process exited with code 0. The administrator saw that process exit with code 0. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x89DB202C, terminate a process only when the calling thread is allowed to open it with PROCESS_TERMINATE, and limit access to \\.\ProcessCtr to Administrators and SYSTEM.
