# Memory-Forensics-Analysis

## Objective

The objective of this project was to conduct a detailed analysis of the provided memory file (KobayashiMaru.vmem) using memory forensics techniques. The primary goal was to identify and investigate potential indicators of malicious activity within the memory dump.

### Skills Learned

- Memory Forensics Analysis: Proficiency in analyzing memory dumps for running processes, command-line executions, and malware artifacts.
- Malicious Activity Identification: Recognition of compromise indicators, abnormal processes, and suspicious command-line activity.
- Command-Line Execution Analysis: Interpretation of command-line actions to detect malicious behavior.
- DLL Analysis: Identification of abnormal or malicious DLLs associated with running processes.
- Malware Detection and Analysis: Detection and analysis of malware artifacts, including hidden processes and code analysis using tools like VirusTotal.

### Tools Used

- SIFT Machines, utilized for memory forensics analysis, equipped with various pre-installed tools and utilities.
- Volatility, open-source memory forensics framework used for extracting information from memory dumps.
- SANS Memory Forensics Cheat Sheet, reference material providing guidance and tips for memory forensics analysis.
- VirusTotal, a online service used for scanning files and URLs to detect malware and malicious activity.

## Steps
"imageinfo"
![Screenshot (628)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/59c689c6-221e-4cf1-96de-c025ca773d07)
- I began by identifying the system profile using imageinfo flag. This gave me the ability to identify the operating system, profile, and other basic information about the memory dump. The output suggests that the profile is a Windows XP SP2 or SP3 system, which is quite outdated and may be more vulnerable to exploits due to lack of security updates.

"connscan"
![Screenshot (631)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/60e23ca4-6614-49df-8055-6ea8a537d6b1)
- The connscan plugin scans for network connections in the memory dump. It appears to show an established connection to a remote IP address (192.168.5.98) on port 3460 with no Local IP address associated. This plugin also gives a 
process ID number (PID) which gave me the ability to further investigate.

"pslist"
![Screenshot (632)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/4e7db0e3-4c0b-4050-b0d8-d512f3836acc)
![Screenshot (633)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/2e42a9f4-fc81-474a-916c-34168fbd0a8d)
- I used the pslist plugin to list the processes running in the memory at the time the dump was taken. I identified a process named poisonivy.exe with the PID 480, which is notable because Poison Ivy is a well-known Remote Access Trojan (RAT). The association of this process with an external IP address is highly indicative of a compromise, as Poison Ivy is often used for unauthorized remote control, surveillance, and data exfiltration.

"pstree"
![Screenshot (643)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/10a5ee2d-4d95-47d8-a5f3-45145c14e3b6)
- The pstree plugin is instrumental for revealing the parent-child relationships between processes. This can be particularly useful for uncovering processes that may have been spawned by malicious software. As seen in the screenshots above, there are several processes with the parent process identifier (PPID) of 404.
- 
- Parent Process 404: Multiple processes spawned from the same parent may suggest that the parent process is a loader or injector, which is a common technique used by malware to execute and hide its presence on a system.

"psxview"
![Screenshot (642)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/4598bef2-6fb1-4276-82dc-32916eea14ad)
- The use of psxview plugin is used for identifying potentially hidden or stealthy processes. It does this by comparing the output of several process listings from the operating system to identify discrepancies. If a process is visible in some process listings but not in others, this could indicate that the process is trying to hide itself from certain utilities, which is a common behavior of malware.

- Noticeably, there are several instances of iroffer.exe with discrepancies across the different process listings, as indicated by "False" in the output. This could potentially suggest that the process is being hidden or is not being correctly reported by certain system functions, which can be a sign of rootkit or stealth techniques used by malware.

"cmdline"
![Screenshot (645)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/3a17ed2d-965e-4350-b4ec-316e980d2212)
![Screenshot (646)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/724a3be0-1ee5-47cd-869c-e25657b6664c)
![Screenshot (647)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/de9ad11a-a270-472f-a78f-2f783a5dca1e)
- The cmdline plugin shows the command line arguments passed to each process at the time they were started. Which can reveal the intent and actions of executables. Finding processes with unexpected or malicious command lines points towards malicious activity or persistence mechanisms. A few points stand out:

- PID 480 and 404: These PIDs are associated with the cmdline command. This means that the command line was used to start these processes, which reveals malicious intent or anomalous behavior.

- Hidden Process (PID 728): Discovered a hidden process whichs is a strong indicator of stealthy behavior typical of rootkits or advanced malware.

- Suspected Rootkit (PID 1472): The presence of a rootkit can be confirmed by irregularities such as unknown or unexpected command lines, processes hiding their presence, or by detecting known rootkit names or behaviors.

"malfind"
![Screenshot (634)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/aac33b7e-c6cd-4372-be23-e2f54f786a99)
![Screenshot (635)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/b502c3e7-e74e-4d6b-8e84-b3645a8920e1)
![Screenshot (636)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/b3e1d13d-295c-4fa5-8263-b373f78f96c7)
![Screenshot (637)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/1d59b0a3-bf02-4d5e-9ad9-9d38dc699b78)
![Screenshot (638)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/9901c706-e7ab-47b2-a281-e7941cdf7d2c)
![Screenshot (639)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/bafb5f8b-9801-48b9-8daa-2f9623e300d7)
- The malfind plugin is designed to detect potentially malicious code based on memory page protections and other heuristics. It is particularly useful for finding injected code, packed malware, and hidden processes that may not show up in a standard process list.

- From the output of malfind, note that the process smss.exe, csrss.exe, winlogon.exe, services.exe, vmacthlp.exe, and poisonivy.exe have memory sections with suspicious characteristics. Specifically, these sections have PAGE_EXECUTE_READWRITE permissions, which is unusual for legitimate processes as it means the pages are writable and executable. This is a common characteristic of a process that has been injected with malicious code because malware authors need to be able to write and then execute their code within another process' space to carry out their activities stealthily.

- Additionally, strings like "[Hacker.Defender]", is a known signature of a particular rootkit. Hacker Defender is a well-documented rootkit that can hide processes, files, and registry keys and can redirect network traffic, amongst other things.

"dlllist"
![Screenshot (681)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/4bd44f91-58d0-4ab7-9bc7-839a15ab3df9)
![Screenshot (671)](https://github.com/fypm2000/Memory-Forensics-Analysis/assets/117059426/d97c918a-83f0-43ff-88bd-61dcf40c1da9)
- The dlllist plugin in Volatility provides information about the dynamic link libraries (DLLs) that are loaded into each process's memory space.

- In this case, without specific anomalies in the paths or non-standard DLLs being loaded, the dlllist output mostly just reaffirms that poisonivy.exe is present and active on the system with jusched.exe.
